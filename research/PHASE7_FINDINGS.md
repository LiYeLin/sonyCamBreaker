# A7C II 2.01：CameraInfo 跨固件模块对应关系

本轮从 [参数封装](PHASE6_FINDINGS.md) 继续追踪，找到 CP 与 `av-cam` 中匹配的类和读取代码。**这是控制/描述数据的跨模块证据，不是照片 LUT 已生效的证据。** 未连接或修改相机。

## 1. 对象身份已确定

CP 构造函数使用的虚表 `0xd15d28` 指向 RTTI `0xd15d38`，其名字是：

```text
32C_DataflowInfra_Entry_CameraInfo
```

`av-cam.bin` 中的对应虚表、RTTI 也指向完全相同的名字。两边构造函数都设置 entry ID=5、payload 长度 `0x3a8`（936 字节）。对象头中的字段位置随 ARM32/AArch64 改变，不能把两个平台的对象内存布局直接互换；payload 长度及复制结构对应。

| 项目 | CP | av-cam 文件偏移 |
| --- | --- | --- |
| CameraInfo 构造 | VA `0x6888e6` | `0x8d830` |
| 整体 payload 复制 | VA `0x688954` | setter `0x8d8bc` / getter `0x8d8c8` |
| 类名 | `C_DataflowInfra_Entry_CameraInfo` | 相同 |
| entry ID / payload 长度 | 5 / 936 | 5 / 936 |

CP 地址沿用 `file_offset+0x108000`。av-cam 本轮离线视图为 `file_offset+0xffffffc001000000`；RTTI 指针、虚表函数地址和 ADRP 代码相互对应。它不证明真机运行时映射，也不能直接用于内存写入。

av-cam SHA-256：`90343f5f2edc0393ad8809d907cfe648dfd3a82ce0ef39cf06167929d8955096`。

## 2. av-cam 中已找到读取路径

以下地址均为 **av-cam 文件偏移**：

1. `0xa437c` 创建 CameraInfo 对象，调用 `0x94314`。
2. `0x94314` 转跳通用 parser `0x933c8`；它读取对象 entry ID，通过 `0x93e70` 查找数据，成功后调用复制函数。
3. `0xa43b8` 调用 `0x8d8c8`，将完整 936 字节 payload 复制给调用者，并返回成功标志。
4. `0x14796c` 和 `0x1482e4` 均调用上述 reader。第一处取得数据后进入 `0x1483b0`：做参数转换，并复制 payload `+0x28` 起的 `0x378` 字节。

另有 `0x1d9b90 / 0x1db5b4` 直接通过 parser 读取 CameraInfo。附近报错明确来自 `vdt_pin.cpp`，内容为找不到 `camera_info_entry` 并询问是否是 thumbnail。读取代码也出现在包含 `enc/sfmc_enc_input_yc.cpp` 日志的代码区域。

这些线索表明 CameraInfo 可供不同下游使用，**不能把它看作专属于静态 JPEG 的配置**。编码输入处还可能是在读取拍摄元数据，而不是执行图像变换。当前没有证明收到这些字段必然驱动 MLUT 硬件，更没有证明它改变 JPEG 像素。

## 3. 新工具与验证

新增 `inspect_camera_info_bridge.py`：

- 校验 CP 与 av-cam 两份文件的 SHA-256。
- 按各自指针宽度解析虚表 → RTTI → 类名，而不是只搜索同名字符串。
- 检查两边构造指令中的 ID 与长度常量。
- 保存指定代码区域的原始字节、带地址反汇编、直接调用候选与日志字符串。

结果为 `a7c2-2.01/camera-info-bridge.json`。原有二进制没有改变；没有执行 av-cam 代码。当前 **22 项测试通过**。新增测试覆盖 RTTI/常量和调用候选，不声称验证完整 ABI、实际跨模块传输或成像。

复现：

```sh
research/.venv/bin/python -m unittest discover -s research/tests -v
research/.venv/bin/python research/inspect_camera_info_bridge.py /tmp/a7c2-camera-info-new.json
```

## 下一步

优先区分 CameraInfo 的元数据消费者与真正的 MLUT 硬件控制消费者。继续追 `0x93e70` 的条目格式，并把 av-cam 的 MLUT 驱动调用同 CP 的 `ddl_VfxSetMlut` 路径对应起来；只有证明照片像素经过该模块，才考虑补丁方案。
