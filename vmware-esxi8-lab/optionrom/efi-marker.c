#include <efi.h>
#include <efilib.h>
#include <efipciio.h>

#define OPROM_MARKER_OFFSET 0x1fff0
#define OPROM_MARKER_VALUE  0x4f50524d
#define OPROM_PCI_ID         0x10d38086
#define OPROM_STAGE_MAGIC    0x53544147

static EFI_GUID loaded_image_guid = LOADED_IMAGE_PROTOCOL;
static EFI_GUID pci_io_guid = EFI_PCI_IO_PROTOCOL_GUID;
static EFI_GUID stage_variable_guid = {
    0x7f0b5e31, 0x4381, 0x4c45,
    { 0x9a, 0x7e, 0x52, 0x11, 0x9f, 0x62, 0x84, 0x31 }
};
static EFI_GUID reboot_phase_guid = {
    0x12345678, 0x1234, 0x1234,
    { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc }
};
static CHAR16 stage_variable_name[] = L"PciOpromStage";
static CHAR16 reboot_phase_name[] = L"R01Phase";

typedef struct {
    UINT32 magic;
    UINT32 phase;
} OPROM_STAGE;

static void emit_stage(EFI_SYSTEM_TABLE *system_table)
{
    EFI_RUNTIME_SERVICES *runtime_services = system_table->RuntimeServices;
    UINT8 reboot_phase_data[32];
    UINTN reboot_phase_size = sizeof(reboot_phase_data);
    UINT32 reboot_phase_attributes = 0;
    OPROM_STAGE stage = { OPROM_STAGE_MAGIC, 1 };
    EFI_STATUS status;

    status = uefi_call_wrapper(runtime_services->GetVariable, 5,
                               reboot_phase_name, &reboot_phase_guid,
                               &reboot_phase_attributes,
                               &reboot_phase_size, reboot_phase_data);
    if (!EFI_ERROR(status))
        stage.phase = 2;

    (void)uefi_call_wrapper(
        runtime_services->SetVariable, 5,
        stage_variable_name, &stage_variable_guid,
        EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
        sizeof(stage), &stage
    );
}

static EFI_STATUS emit_marker(EFI_PCI_IO_PROTOCOL *pci_io)
{
    UINT32 pci_id = 0;
    UINT32 bar0 = 0;
    volatile UINT32 *marker_address;
    EFI_STATUS status;

    status = uefi_call_wrapper(pci_io->Pci.Read, 5, pci_io,
                               EfiPciIoWidthUint32, 0, 1, &pci_id);
    if (EFI_ERROR(status) || pci_id != OPROM_PCI_ID)
        return EFI_UNSUPPORTED;

    status = uefi_call_wrapper(pci_io->Pci.Read, 5, pci_io,
                               EfiPciIoWidthUint32, 0x10, 1, &bar0);
    if (EFI_ERROR(status) || (bar0 & 1) || !(bar0 & ~0x0fU))
        return EFI_UNSUPPORTED;

    /* Some firmware does not permit changing attributes on DirectPath I/O. */
    (void)uefi_call_wrapper(pci_io->Attributes, 4, pci_io,
                            EfiPciIoAttributeOperationEnable,
                            EFI_PCI_IO_ATTRIBUTE_MEMORY, NULL);
    marker_address = (volatile UINT32 *)(UINTN)(
        (bar0 & ~0x0fU) + OPROM_MARKER_OFFSET
    );
    *marker_address = OPROM_MARKER_VALUE;
    return EFI_SUCCESS;
}

static EFI_STATUS emit_from_handle(EFI_BOOT_SERVICES *boot_services,
                                   EFI_HANDLE handle)
{
    EFI_PCI_IO_PROTOCOL *pci_io;
    EFI_STATUS status;

    if (!handle)
        return EFI_NOT_FOUND;
    status = uefi_call_wrapper(boot_services->HandleProtocol, 3, handle,
                               &pci_io_guid, (VOID **)&pci_io);
    if (EFI_ERROR(status))
        return status;
    return emit_marker(pci_io);
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle,
                           EFI_SYSTEM_TABLE *system_table)
{
    EFI_BOOT_SERVICES *boot_services = system_table->BootServices;
    EFI_LOADED_IMAGE *loaded_image = NULL;
    EFI_HANDLE *handles = NULL;
    EFI_STATUS status;
    UINTN handle_count = 0;
    UINTN index;

    /* This observation point is independent of PCI protocol/BAR access. */
    emit_stage(system_table);

    status = uefi_call_wrapper(boot_services->HandleProtocol, 3, image_handle,
                               &loaded_image_guid,
                               (VOID **)&loaded_image);
    if (!EFI_ERROR(status)) {
        status = emit_from_handle(boot_services, loaded_image->DeviceHandle);
        if (!EFI_ERROR(status))
            return status;
    }

    status = uefi_call_wrapper(boot_services->LocateHandleBuffer, 5,
                               ByProtocol, &pci_io_guid, NULL,
                               &handle_count, &handles);
    if (EFI_ERROR(status))
        return status;

    status = EFI_NOT_FOUND;
    for (index = 0; index < handle_count; index++) {
        EFI_PCI_IO_PROTOCOL *pci_io;
        UINT32 pci_id = 0;
        UINTN segment = 0;
        UINTN bus = 0;
        UINTN device = 0;
        UINTN function = 0;

        if (EFI_ERROR(uefi_call_wrapper(
                boot_services->HandleProtocol, 3, handles[index],
                &pci_io_guid, (VOID **)&pci_io)))
            continue;
        if (EFI_ERROR(uefi_call_wrapper(
                pci_io->Pci.Read, 5, pci_io, EfiPciIoWidthUint32,
                0, 1, &pci_id)) || pci_id != OPROM_PCI_ID)
            continue;
        if (EFI_ERROR(uefi_call_wrapper(
                pci_io->GetLocation, 5, pci_io, &segment, &bus,
                &device, &function)) || function != 0)
            continue;
        status = emit_marker(pci_io);
        if (!EFI_ERROR(status))
            break;
    }

    (void)uefi_call_wrapper(boot_services->FreePool, 1, handles);
    return status;
}
