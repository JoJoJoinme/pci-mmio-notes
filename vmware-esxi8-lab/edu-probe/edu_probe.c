// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/pci.h>

#define EDU_VENDOR_ID             0x1234
#define EDU_DEVICE_ID             0x11e8

#define EDU_REG_ID                0x00
#define EDU_REG_LIVENESS          0x04
#define EDU_REG_IRQ_STATUS        0x24
#define EDU_REG_IRQ_RAISE         0x60
#define EDU_REG_IRQ_ACK           0x64
#define EDU_REG_DMA_SRC           0x80
#define EDU_REG_DMA_DST           0x88
#define EDU_REG_DMA_COUNT         0x90
#define EDU_REG_DMA_CMD           0x98

#define EDU_DMA_RUN               BIT(0)
#define EDU_DMA_FROM_DEVICE       BIT(1)
#define EDU_DMA_IRQ               BIT(2)
#define EDU_DMA_IRQ_STATUS        BIT(8)
#define EDU_INTERNAL_BUFFER       0x40000
#define EDU_DMA_BYTES             256
#define EDU_SENTINEL              0x45445531U
#define IVSHMEM_VENDOR_ID         0x1af4
#define IVSHMEM_DEVICE_ID         0x1110
#define IVSHMEM_MEMORY_BAR        2

struct edu_probe_data {
	struct pci_dev *pdev;
	void __iomem *bar0;
	struct completion irq_completion;
	atomic_t irq_count;
	u32 last_irq_status;
	bool irq_requested;
	void *dma_cpu;
	dma_addr_t dma_addr;
};

static irqreturn_t edu_probe_irq(int irq, void *opaque)
{
	struct edu_probe_data *data = opaque;
	u32 status = ioread32(data->bar0 + EDU_REG_IRQ_STATUS);

	if (!status)
		return IRQ_NONE;

	iowrite32(status, data->bar0 + EDU_REG_IRQ_ACK);
	WRITE_ONCE(data->last_irq_status, status);
	atomic_inc(&data->irq_count);
	complete(&data->irq_completion);
	return IRQ_HANDLED;
}

static void edu_probe_arm_irq(struct edu_probe_data *data, u32 clear)
{
	iowrite32(clear, data->bar0 + EDU_REG_IRQ_ACK);
	WRITE_ONCE(data->last_irq_status, 0);
	reinit_completion(&data->irq_completion);
}

static int edu_probe_wait_irq(struct edu_probe_data *data, u32 expected)
{
	unsigned long timeout;
	u32 status;

	timeout = wait_for_completion_timeout(&data->irq_completion,
					       msecs_to_jiffies(2000));
	if (!timeout)
		return -ETIMEDOUT;

	status = READ_ONCE(data->last_irq_status);
	if (!(status & expected))
		return -EIO;

	return 0;
}

static int edu_probe_interrupt(struct edu_probe_data *data)
{
	int ret;

	edu_probe_arm_irq(data, U32_MAX);
	iowrite32(BIT(0), data->bar0 + EDU_REG_IRQ_RAISE);
	ret = edu_probe_wait_irq(data, BIT(0));
	if (ret)
		return ret;

	dev_info(&data->pdev->dev,
		 "EDU-MSI-PASS irq=%d interrupts=%d status=0x%08x\n",
		 pci_irq_vector(data->pdev, 0), atomic_read(&data->irq_count),
		 READ_ONCE(data->last_irq_status));
	return 0;
}

static void edu_probe_program_dma(struct edu_probe_data *data, u64 source,
				  u64 destination, u64 count, u32 command)
{
	writeq(source, data->bar0 + EDU_REG_DMA_SRC);
	writeq(destination, data->bar0 + EDU_REG_DMA_DST);
	writeq(count, data->bar0 + EDU_REG_DMA_COUNT);
	wmb();
	iowrite32(command, data->bar0 + EDU_REG_DMA_CMD);
}

static int edu_probe_dma(struct edu_probe_data *data)
{
	u8 *buffer = data->dma_cpu;
	int i;
	int ret;

	for (i = 0; i < EDU_DMA_BYTES; i++)
		buffer[i] = (u8)(i ^ 0xa5);

	edu_probe_arm_irq(data, EDU_DMA_IRQ_STATUS);
	edu_probe_program_dma(data, data->dma_addr, EDU_INTERNAL_BUFFER,
			      EDU_DMA_BYTES, EDU_DMA_RUN | EDU_DMA_IRQ);
	ret = edu_probe_wait_irq(data, EDU_DMA_IRQ_STATUS);
	if (ret)
		return ret;

	memset(buffer, 0, EDU_DMA_BYTES);
	edu_probe_arm_irq(data, EDU_DMA_IRQ_STATUS);
	edu_probe_program_dma(data, EDU_INTERNAL_BUFFER, data->dma_addr,
			      EDU_DMA_BYTES,
			      EDU_DMA_RUN | EDU_DMA_FROM_DEVICE | EDU_DMA_IRQ);
	ret = edu_probe_wait_irq(data, EDU_DMA_IRQ_STATUS);
	if (ret)
		return ret;

	rmb();
	for (i = 0; i < EDU_DMA_BYTES; i++) {
		if (buffer[i] != (u8)(i ^ 0xa5))
			return -EILSEQ;
	}

	dev_info(&data->pdev->dev,
		 "EDU-DMA-PASS bytes=%u dma=%pad interrupts=%d\n",
		 EDU_DMA_BYTES, &data->dma_addr, atomic_read(&data->irq_count));
	return 0;
}

static void edu_probe_p2p(struct edu_probe_data *source)
{
	struct pci_dev *peer;
	void __iomem *peer_bar;
	resource_size_t peer_bus;
	u8 *buffer = source->dma_cpu;
	int mismatch = -1;
	int i;
	int ret;

	peer = pci_get_device(IVSHMEM_VENDOR_ID, IVSHMEM_DEVICE_ID, NULL);
	if (!peer) {
		dev_info(&source->pdev->dev,
			 "EDU-P2P-UNAVAILABLE reason=ivshmem-not-found\n");
		return;
	}

	ret = pci_enable_device_mem(peer);
	if (ret)
		goto fail_enable;
	ret = pci_request_region(peer, IVSHMEM_MEMORY_BAR,
				 KBUILD_MODNAME "-p2p-peer");
	if (ret)
		goto fail_region;
	peer_bar = pci_iomap(peer, IVSHMEM_MEMORY_BAR, EDU_DMA_BYTES);
	if (!peer_bar) {
		ret = -ENOMEM;
		goto fail_iomap;
	}

	peer_bus = pci_bus_address(peer, IVSHMEM_MEMORY_BAR);
	memset_io(peer_bar, 0, EDU_DMA_BYTES);
	for (i = 0; i < EDU_DMA_BYTES; i++)
		buffer[i] = (u8)(i ^ 0x6d);

	edu_probe_arm_irq(source, EDU_DMA_IRQ_STATUS);
	edu_probe_program_dma(source, source->dma_addr, EDU_INTERNAL_BUFFER,
			      EDU_DMA_BYTES, EDU_DMA_RUN | EDU_DMA_IRQ);
	ret = edu_probe_wait_irq(source, EDU_DMA_IRQ_STATUS);
	if (ret)
		goto fail_transfer;

	edu_probe_arm_irq(source, EDU_DMA_IRQ_STATUS);
	edu_probe_program_dma(source, EDU_INTERNAL_BUFFER, peer_bus,
			      EDU_DMA_BYTES,
			      EDU_DMA_RUN | EDU_DMA_FROM_DEVICE | EDU_DMA_IRQ);
	ret = edu_probe_wait_irq(source, EDU_DMA_IRQ_STATUS);
	if (ret)
		goto fail_transfer;

	mb();
	for (i = 0; i < EDU_DMA_BYTES; i++) {
		if (ioread8(peer_bar + i) != (u8)(i ^ 0x6d)) {
			mismatch = i;
			break;
		}
	}
	if (mismatch < 0) {
		dev_info(&source->pdev->dev,
			 "EDU-P2P-PASS source=%s peer=%s peer_bus=0x%llx bytes=%u\n",
			 pci_name(source->pdev), pci_name(peer),
			 (unsigned long long)peer_bus, EDU_DMA_BYTES);
	} else {
		dev_info(&source->pdev->dev,
			 "EDU-P2P-FAIL source=%s peer=%s peer_bus=0x%llx mismatch=%d got=0x%02x expected=0x%02x\n",
			 pci_name(source->pdev), pci_name(peer),
			 (unsigned long long)peer_bus, mismatch,
			 ioread8(peer_bar + mismatch), (u8)(mismatch ^ 0x6d));
	}

	pci_iounmap(peer, peer_bar);
	pci_release_region(peer, IVSHMEM_MEMORY_BAR);
	pci_disable_device(peer);
	pci_dev_put(peer);
	return;

fail_transfer:
	pci_iounmap(peer, peer_bar);
fail_iomap:
	pci_release_region(peer, IVSHMEM_MEMORY_BAR);
fail_region:
	pci_disable_device(peer);
fail_enable:
	dev_info(&source->pdev->dev,
		 "EDU-P2P-FAIL source=%s peer=%s stage=setup-or-transfer error=%d\n",
		 pci_name(source->pdev), pci_name(peer), ret);
	pci_dev_put(peer);
}

static int edu_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct edu_probe_data *data;
	const char *reset_state;
	u32 identification;
	u32 initial;
	u32 readback;
	int ret;

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->pdev = pdev;
	init_completion(&data->irq_completion);
	atomic_set(&data->irq_count, 0);
	pci_set_drvdata(pdev, data);

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	ret = pcim_iomap_regions(pdev, BIT(0), KBUILD_MODNAME);
	if (ret)
		return ret;

	data->bar0 = pcim_iomap_table(pdev)[0];
	if (!data->bar0)
		return -ENOMEM;

	identification = ioread32(data->bar0 + EDU_REG_ID);
	if ((identification & 0xff) != 0xed)
		return -ENODEV;

	initial = ioread32(data->bar0 + EDU_REG_LIVENESS);
	if (initial == 0)
		reset_state = "reset";
	else if (initial == ~EDU_SENTINEL)
		reset_state = "persisted";
	else
		reset_state = "unknown";
	dev_info(&pdev->dev,
		 "EDU-RESET-SENTINEL initial=0x%08x state=%s\n",
		 initial, reset_state);

	iowrite32(EDU_SENTINEL, data->bar0 + EDU_REG_LIVENESS);
	readback = ioread32(data->bar0 + EDU_REG_LIVENESS);
	if (readback != ~EDU_SENTINEL)
		return -EIO;
	dev_info(&pdev->dev,
		 "EDU-LIVENESS-PASS id=0x%08x readback=0x%08x\n",
		 identification, readback);

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(28));
	if (ret)
		return ret;
	pci_set_master(pdev);

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (ret < 0)
		return ret;
	if (ret != 1 || !pdev->msi_enabled) {
		ret = -ENXIO;
		goto err_vectors;
	}

	ret = request_irq(pci_irq_vector(pdev, 0), edu_probe_irq, 0,
			  KBUILD_MODNAME, data);
	if (ret)
		goto err_vectors;
	data->irq_requested = true;

	data->dma_cpu = dmam_alloc_coherent(&pdev->dev, EDU_DMA_BYTES,
					    &data->dma_addr, GFP_KERNEL);
	if (!data->dma_cpu) {
		ret = -ENOMEM;
		goto err_irq;
	}

	ret = edu_probe_interrupt(data);
	if (ret)
		goto err_irq;

	ret = edu_probe_dma(data);
	if (ret)
		goto err_irq;

	edu_probe_p2p(data);

	dev_info(&pdev->dev,
		 "EDU-PROBE-PASS id=0x%08x irq_mode=msi dma=roundtrip reset=%s\n",
		 identification, reset_state);
	return 0;

err_irq:
	free_irq(pci_irq_vector(pdev, 0), data);
	data->irq_requested = false;
err_vectors:
	pci_free_irq_vectors(pdev);
	return ret;
}

static void edu_probe_remove(struct pci_dev *pdev)
{
	struct edu_probe_data *data = pci_get_drvdata(pdev);

	if (data->irq_requested)
		free_irq(pci_irq_vector(pdev, 0), data);
	pci_free_irq_vectors(pdev);
}

static const struct pci_device_id edu_probe_ids[] = {
	{ PCI_DEVICE(EDU_VENDOR_ID, EDU_DEVICE_ID) },
	{ }
};
MODULE_DEVICE_TABLE(pci, edu_probe_ids);

static struct pci_driver edu_probe_driver = {
	.name = KBUILD_MODNAME,
	.id_table = edu_probe_ids,
	.probe = edu_probe,
	.remove = edu_probe_remove,
};
module_pci_driver(edu_probe_driver);

MODULE_AUTHOR("PCI compatibility lab");
MODULE_DESCRIPTION("QEMU EDU MSI, DMA, and reset-sentinel acceptance probe");
MODULE_LICENSE("GPL");
