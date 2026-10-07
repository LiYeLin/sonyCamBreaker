# A7C II 2.01：流编号来自两套配置的批量复制

延续 [流资源映射](PHASE13_FINDINGS.md)。已定位对象 `+0x1500` 的直接来源，但尚未确定两套源配置的业务含义。未连接或修改相机。

## 来源与选择规则

初始化函数 `0x4be1a4` 调用 `0xb2ddb4`，得到上下文 `0x173efe8`。令 `config = *(context+0xc)`：

- 选择源配置 A：`config+0x20`；或 B：`config+0x630`。
- `0x4be57a..0x4be58c` 将选中配置的 `+0x74..+0x83` 四个 32 位字段，批量复制到对象 `+0x14fc..+0x150b`。
- 因而流编号 `object+0x1500` 来自选中配置 `+0x78`，也就是 `config+0x98` 或 `config+0x6a8`。只搜索直接写 `+0x1500` 会漏掉这次批量复制。

选择条件来自三个尚未命名的字段：

```text
s = *(uint32_t *)(config+0x698)
f = *(uint8_t *)(*(context+0x2c)+1)
g = 地址 0x1a533ba 的 bit 1

选择 B：s==0，或 (s==1 且 (f|1)==3)，
        或 (s==2 且 f==3)，或 g==1
否则选择 A
```

这里不能把 s 当作此前 CP shooting_mode，也不能将 A/B 命名为照片/视频；尚无这样的字段同一性证据。

## 验证

新增 `emulate_stream_config_selection.py`：执行原始选择代码和上下文 getter，保留选中指针，再手动跳到原始 16 字节复制片段。其余初始化过程未执行。

对 s=0–3、f=0–3、g=0/1，**32 组通过**，核对选择结果及全部四个复制字段。两套源配置中的流编号 1/8 是测试人为赋值，用于辨别复制来源，**不是发现真实机身分别使用流 1/8**。

原始文件哈希已校验，结果保存在 `a7c2-2.01/cp-stream-config-selection.json`。全部 **33 项回归测试通过**。没有验证完整资源分配、像素处理或 JPEG 输出。

## 下一步

继续追踪 `config+0x98`、`config+0x6a8` 的写入者，以及 config 指针的初始化。现在已找到“源配置 → 流编号 → VFX 资源”的对应关系；真正未解的是源配置如何随静态拍摄、预览和视频切换，不能把合成测试的值当作答案。

复现：

```sh
research/.venv/bin/python research/emulate_stream_config_selection.py /tmp/a7c2-config-selection-new.json
research/.venv/bin/python -m unittest discover -s research/tests -q
```
