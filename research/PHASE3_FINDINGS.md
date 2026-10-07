# A7C II 2.01：CP 二次限制与 LUT 参数链

后续见 [PHASE4_FINDINGS.md](PHASE4_FINDINGS.md)：已把描述块中的两个未知字段关联为 l3d/reg 长度，并追到实际提交接口。下文保留本阶段的证据范围。

## 本轮结论

**只解除应用层的照片模式覆盖，还不足以保留用户 LUT。CP 内部有第二次参数归一化。**

已离线执行原始消息接收函数和下游参数构建函数，768 组组合通过。未修改固件字节、连接或修改相机；没有生成刷写补丁。尚未证明全分辨率 JPEG 应用 LUT。

本页延续 [上一阶段](PHASE2_FINDINGS.md)。地址仍为 `cpapp-b.bin` 加载视图 `file_offset + 0x108000`，不是可以直接写入真机的地址。CP 文件 SHA-256 仍是 `f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428`。

## 1. 已关联的参数链

```text
消息 0x4157 → 接收函数 0x8db56e → 状态结构 +0xaf8 等字段
                                      ↓
参数构建 0xb2c406 → 归一化 0xb31aac → MLUT 编号 0x4e8a5c
                                      ↓
                  四个标志更新 0xb2c5b6 + 条件复制 96 字节描述块
```

这里的箭头表示状态读写关系，不表示接收函数会直接调用构建函数。真实调度时序未验证；仿真手动依次调用两者，并构造共享上下文。

`GetVfxMlutLookname` 的两个直接调用位置为 `0x4bf6f6`、`0xb2c498`。两处之前都调用 `0xb31aac`。其指令可简化为：

```c
// 人工解释，不是 Sony 原源码。
normalize(base_look, shooting_mode, descriptor_word) {
    if (shooting_mode == 3) return 11;
    if (base_look == 10 && descriptor_word == 0) return 0;
    return base_look;
}
```

- `shooting_mode` 来自消息 +9。不能把它与应用层 `general_shooting_mode` 枚举混用：应用层照片为 0，而它生成的此字段为 3；部分普通视频设置也会生成 3。
- 第三个参数来自状态 `+0x78`，即 `+0x68` 描述块内部的 `+0x10`。其精确语义尚未确认，暂不命名为“LUT 已加载”。它为零时会阻止保留用户 LUT 的 base_look=10。
- `base_look=11` 经过编号函数得到 MLUT ID=0，随后四个候选路径标志被清零。
- `base_look=10` 得以保留时，构建函数复制状态 `+0x68` 的 96 字节至输出 `+0x13d0`。这只是描述块复制的证据，**不是 LUT 样本数据已经上传的证据**。

## 2. 原始代码仿真结果

固定 `color_gamut=1, input_gamut=0, target_display=0, state[+0x7c]=0`，四个输出标志初值为 `[0,1,0,1]`。

| 输入 base_look | CP shooting_mode | 描述块 +0x10 | 有效 base_look | MLUT ID | 四个标志 | 复制描述块 |
| --- | --- | --- | --- | --- | --- | --- |
| 10 | 3 | 1 | 11 | 0 | 0000 | 否 |
| 10 | 0 | 0 | 0 | 1 | 1111 | 否 |
| 10 | 0 | 1 | 10 | 11 | 1111 | 是 |
| 10 | 1 | 1 | 10 | 13 | 0101（保留） | 是 |

注意 MLUT ID=11 与 base_look=11 是不同枚举，不能因数字相同而混淆。

仿真矩阵覆盖 base_look `{0,7,8,9,10,11}`、CP shooting_mode `0..3`，以及五个二值条件，共 768 组。数据和上下文是合成的；运行的是原始 ARM/Thumb 指令，包括原始 memcpy，没有替换被调函数。执行停在 `0xb2c568`，即本次调查的字段写入完成之后、诊断尾段之前，不声称完整执行了函数返回或相机拍摄。

## 3. CAM / LV 线索与未完成部分

字符串交叉引用找到两个独立的诊断字段登记区域：

- `<CAM> baseLook / shootingMode`：字符串地址 `0xf97e41 / 0xf97e54`，登记指令 `0x4359be / 0x4359da`，对应该段对象指针的 `+0x200 / +0x204` 字段。
- `<LV> baseLook / shootingMode`：字符串地址 `0xf9a622 / 0xf9a634`，登记指令 `0x438040 / 0x43805c`，对应 `+0x5a4 / +0x5a8` 字段。

这些是字段登记代码，不是图像处理函数；尚未把它们与上述输出结构完整连接。也不能把 CAM 名字直接解释为“已证明拍照 JPEG 路径”。

下一步优先追踪：

1. 输出 `+0x13b8 / +0x13c0 / +0x13d0` 与四个标志的消费者，关联 CAM/LV 和编码输出。构建函数的七个直接调用位置已记录在 `cp-mlut-builder-callers.json`。
2. 状态 `+0x68 / +0x78 / +0x7c` 的写入者：查清描述块、真实 LUT 数据、缓冲所有权和生效时序。
3. 在取得照片输出链证据后，再单独评估真机临时执行和恢复路径。不要直接强改模式字段，更不要把本页地址当补丁清单。

## 4. 实现与验证

- 新增 `scan_thumb_calls.py`：Thumb-2 BL/B.W 及函数指针候选扫描，Capstone 交叉检查解码。数据、半条指令仍可能误报，命中需人工复查；漏扫间接调用及 ARM 调用。
- 扩展 `scan_cp_xrefs.py`：可指定字符串模式和输出路径。
- 新增 `emulate_cp_pipeline.py`：原始接收端 → 参数构建链仿真与独立预期值检查。
- CP 新导出四个函数；总计应用侧 14、CP 侧 7 个函数的伪代码、汇编和原始字节快照。
- 修正 Ghidra 新候选区域可能继承错误 ARM 模式的问题：只清理 manifest 明确圈定范围的代码单元，再按 Thumb 重解码；不改源二进制。
- **14 项自动化测试全部通过**，包含逐函数导出字节一致性、原有 68 组应用 helper 和 3 组 receiver 实验，以及新增 768 组组合。

复现测试：

```sh
research/.venv/bin/python -m unittest discover -s research/tests -v
```

仿真结果：`a7c2-2.01/cp-pipeline-emulation.json`。重新生成须提供新的输出文件名，脚本拒绝覆盖。
