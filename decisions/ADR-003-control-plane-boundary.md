# ADR-003：单一控制面与持久状态边界

状态：`ACCEPTED`
日期：2026-07-22
Owner：Qman Control Plane

## 决定

参考架构使用一套 Qman API、单 active/standby DirectPath Controller、全局事务存储和每宿主一个
特权 Host Agent。PostgreSQL 是 repository 的参考实现，保存 assignedId、bundle lease、run generation
与 host epoch；Host Agent 的 SQLite 只作为 journal/cache，不能充当跨主机协调器。QEMU 非特权，
只消费有期限的 backend-specific launch grant：当前 Legacy 为受控 device path，未来
IOMMUFD/cdev 才为预打开 fd。

Legacy 与未来 IOMMUFD 共用 inventory → capability/HCL → bundle/lease → owner → reset → backend
prepare → launch → observe → commit → release/quarantine 流程。仅 backend adapter、renderer 与 attach receipt
可不同。

## 后果

接入现有 Qman 服务时可以替换进程或数据库产品，但不得改变事务和权限不变量。任何需要两套 API、
两套 FSM 或两套持久状态模型的实现都必须重新提交 ADR。
