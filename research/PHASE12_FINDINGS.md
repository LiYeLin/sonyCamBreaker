# A7C II 2.01：MLUT 申请 token 到提交参数

延续 [资源申请研究](PHASE11_FINDINGS.md)。本轮补齐 token 的静态传递关系，并验证保存/取出指令片段。**没有执行完整拍摄流程，没有证明静态 JPEG 使用 LUT。** 未连接相机，未修改原始固件。

## 1. 上游申请与保存

`0x4e7dd0` 包装函数在 `0x4e7e0a` 调用 `0x54d660`：r2 是输出 token 指针，r3=0。后者使用 kind=0 调用上一轮的资源 owner 写入函数。不能将这里的 kind=0 直接解释为照片模式。

其直接调用点为 `0x4baec0`，位于通用资源分派函数 `0x4ba9d0` 内：

- token 输出放在本函数栈 `+0xa8`，组合编号输出放在 `+0xa4`。
- `0x4bad0e` 的 TBH 表中，资源 case **23、30、37、44** 跳到该调用分支。这些是通用资源 case，不是前面 0–6 的 MLUT 组合编号，也不是四个硬件槽。
- 成功分支 `0x4bb050` 读取栈 `+0xa0/+0xa4/+0xa8`，将 token 写入资源记录 `0x1a539a8 + case*0x40 + 0xc`。
- `0x4bac16` 计算当前记录地址，`0x4bac3e` 保存它；后续 `0x4bb140..0x4bb1f6` 恢复该记录地址。`0x4bb228..0x4bb22c` 从记录 `+0xc` 复制 token 到调用者输出指针。

已有资源复用、冲突及错误分支尚未完整验证。

## 2. 输出指针与提交字段的对应

一个上游设置点 `0x4c1b02..0x4c1b08` 将对象 `+0x13b4` 指针放入调用栈 `+0x18`，随后在 `0x4c1b6c` 调用 `0xb30e92`。

逐层参数转发：

1. `0xb30fea` 从 frame pointer `+0x20` 取该指针，对应入口 SP `+0x18`；在 `0xb30ff8` 放到下一层调用栈 `+0x14`，并以资源类别参数 `0x10` 调用 `0x46f9c4`。
2. `0x46fa44` 从 frame pointer `+0x1c`（入口 SP `+0x14`）读取，再于 `0x46fa46` 放到下一层调用栈 `+0x18`，调用 `0x4ba9d0`。
3. 分派器 `0x4bb1f6` 从 frame pointer `+0x20`（入口 SP `+0x18`）取回输出地址，最终将 token 写入。

四个 MLUT 提交调用点 `0x4c2eae / 0xb2b4d4 / 0xb2b596 / 0xb2ba0e` 均传入：

```text
r0 = 对象[+0x13b4]       // 资源 token
r1 = 对象地址 + 0x13b8   // MLUT 参数结构
目标 = 0x4e876c
```

这建立了字段布局和转发关系，不代表已证明某次静态拍照一定选择类别 0x10 下的上述资源 case、成功申请并走到提交。模式到资源表的映射仍需追踪。

## 3. 验证与边界

新增 `emulate_mlut_token_flow.py`：

- 固定并校验 CP 原始文件 SHA-256。
- 从原始 TBH 表核对四个资源 case。
- 执行原始保存、复制和四处提交参数准备片段，4 × 4 共 **16 组通过**。
- 使用合成成功 token、资源列表和对象；中间省略的 bookkeeping 用显式寄存器赋值衔接，因此不是完整调用链仿真。
- 停在 MLUT 调用前；没有实际申请、提交、OS 同步、像素或 JPEG 处理。

结果 `a7c2-2.01/cp-mlut-token-flow.json`；调用候选记录 `cp-acquire-submit-callers.json`、`cp-resource-dispatch-callers.json`。当前 **31 项回归测试通过**。

## 下一步

追踪 `0xb0a332` 如何按场景/资源类别返回资源 case 列表，尤其类别 `0x10` 与 case 23/30/37/44 的关系。再对照静态拍摄模式入口，判断这里的申请究竟是预览、拍摄像素处理还是两者共用。已有证据仍不足以制作可刷写补丁。

复现：

```sh
research/.venv/bin/python research/emulate_mlut_token_flow.py /tmp/a7c2-token-flow-new.json
research/.venv/bin/python -m unittest discover -s research/tests -q
```
