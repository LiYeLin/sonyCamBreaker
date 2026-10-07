# A7C II 2.01：资源申请与 Capture 类型关联

本轮从 [资源编号映射](PHASE10_FINDINGS.md) 继续向上追踪。找到 `Camera::Capture::CapRsrc_VFX` 类的资源申请入口，以及资源 owner 的生成规则。**这是拍摄框架关联，不是照片 JPEG 使用 LUT 的证明。** 全程离线，未修改机身或原始固件。

## 1. 资源申请确实来自 Capture 类

原始 CP 二进制中的证据：

- 虚表头 `0xe769d8` 指向 RTTI `0xe76a10`；名字指针 `0xe76a14` 指向 `N6Camera7Capture11CapRsrc_VFXE`，即 `Camera::Capture::CapRsrc_VFX`。
- 同一虚表的 `0xe769e4` 指向 Thumb 函数 `0x4811dc`。
- 函数日志引用 `AcquireMain`（`0x48131c`），错误路径引用 `CapRsrc_VFX.cpp`（`0xfbf70a`）。
- 输入参数结构的 `+8` 字段为 0 时，在 `0x481228` 调用 `0x54d05c`；为 1 时，在 `0x481256` 调用 `0xbb2a78`。
- 两个包装函数分别以 kind=0、kind=1 调用资源写入函数 `0x54d2d4`；均先调用 `0x54d168` 选择资源。

因而 kind=0/1 是同一 Capture 资源类支持的两类请求，**不能擅自命名为照片/视频**。该结构字段的生产者和虚调用的实际拍摄时序仍待查。

## 2. 原始指令验证：资源写入与查询闭环

`0x54d2d4` 参数：r0=kind，r1=输出 token 指针，r2=资源组合编号，r3=标志（业务含义未知）。

- kind 0/1 分别写 type 1/2。
- 组合编号 0–3 写单槽，4 写全部四槽，5 写槽 0/1，6 写槽 2/3。
- 从组合内首个槽的旧 owner 取递增后的低 16 位，组合编号写入高 16 位；当标志为 0 时加上 `0x80000000`。验证输入的旧 owner 为小整数，未额外验证回绕和复用。
- 同组各槽写入相同 token，随后资源查询能返回原组合编号。

新增 `emulate_mlut_resource_allocation.py`，执行原始函数前导和写入代码；手动跳过 OS 加锁，停止于解锁之前，再调用上一轮原始查询代码片段。2 种 kind × 7 种组合 × 2 种标志，共 **28 组通过**。使用合成空闲资源表，未执行空闲选择器、并发保护、完整申请 API 或硬件初始化。

结果：`a7c2-2.01/cp-resource-allocation-resolution.json`。新增函数导出已按 Thumb 模式生成。总计 **30 项回归测试通过**，包括 RTTI/日志/调用地址校验与导出字节对照。

## 3. 调用者线索与下一步

扫描记录：

- `cp-resource-allocator-callers.json`：五个直接申请调用点。
- `cp-resource-acquire-callers.json`：包装函数上游；其中 `0x54d65e` 是对齐填充，不是入口，其无结果不能作为无调用证据。
- `cp-capture-resource-callers.json`：纠正入口为 `0x54d660`，找到调用点 `0x4e7e0a`；并找到上述 Capture 虚表引用。

下一步优先逆向 `CapRsrc_VFX` 参数结构的创建者、`0x4e7e0a` 的 acquire/token 保存与 MLUT 提交的联系。目标是证明同一资源是否出现在静态拍照到落盘的处理过程中，而不是仅凭 Capture 类名推断 JPEG 生效。

复现：

```sh
research/.venv/bin/python research/emulate_mlut_resource_allocation.py /tmp/a7c2-resource-allocation-new.json
research/.venv/bin/python -m unittest discover -s research/tests -v
```
