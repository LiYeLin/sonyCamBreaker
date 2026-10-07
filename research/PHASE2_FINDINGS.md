# A7C II 2.01：照片 LUT 反编译阶段记录

后续进展见 [PHASE3_FINDINGS.md](PHASE3_FINDINGS.md)：已追踪下游调用者并确认第二次参数限制。下文保留本阶段当时的验证范围。

## 结论

**已确认一处真实的软件限制，但尚未证明照片 JPEG 能使用自定义 LUT。**

1. 应用层在照片模式下覆盖 LUT 相关消息字段，位置在 `appFw.so` 的 `0x352c62c` 分支及 `0x352c630–0x352c63c` 写入。
2. 已把应用消息 `0x4157` 与 CP 固件中的接收函数对应起来。接收函数会保存自定义 LUT 对应的字段值，没有在该函数中发现针对这些输入的拒绝逻辑。
3. 下一步必须验证状态到照片图像处理的路径；菜单解禁或接收成功，都不是照片效果成功的证据。

本轮只修改研究工具、生成分析产物，未连接或修改相机，也没有生成可刷写补丁。

## 可复查证据

### 应用层（AArch64）

二进制：`a7c2-2.01/selected/files/lib/appFw.so`。
SHA-256：`2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b`。
以下为原始 ELF 虚拟地址，不包含运行时 ASLR 基址，不是刷写偏移。

| 入口 | 识别依据/行为 |
| --- | --- |
| `0x352c5dc` | `set_base_picture_setting_i`，函数名字符串、参数顺序与指令行为相互对应 |
| `0x3537fd0` | 生成 16 字节消息，ID `0x4157`，调用上述函数填充 payload |
| `0x35358b8` | 通用消息发送，最终调用 `osal_snd_msg@plt`，目标参数 `0x90030001` |
| `0x3428510` | `send_lut`，用户选择值 3–18 转换为槽位 0–15，再加载/提交数据 |
| `0x303dca0` | `get_select_lut_by_pp`，普通分支中 PP 值 12–15 选择四个 PPLUT 关联槽位；另有 cinematic 分支 |
| `0x352aad8` | 普通 PP 参数转换；OFF 与 PPLUT 值进入默认 PP 参数分支，PP1–11 则读取参数数组 |
| `0x35287f0` | Creative Look 相关颜色模式转换，主要是预设枚举映射，尚未发现任意矩阵上传入口 |

枚举顺序来自重定位指向的命名数组，并用录像专用 letter-box 函数分支交叉验证：`general_shooting_mode` 0 为 STILL、1 为 MOVIE；PP12–15 为 PPLUT1–4；LUT3–18 为 USER1–16。证据在 `enum-tables.json`、`photo-path-xrefs.json` 与相应汇编中。

`set_base_picture_setting_i` 的关键行为（人工简化，不是原源码）：

```c
// 先根据 LUT 选择和用户 LUT 是否存在填写 msg[8]。
if (general_shooting_mode == 0) {
    msg[8] = 11;
    msg[9] = 3;
} else {
    // 视频分支结合 log、PP、cinematic 参数选择消息字段。
    // 普通非 cinematic 的 PPLUT1–4，在 log==0 时可保留 LUT 对应字段。
}
```

固定条件：`exists=1, log=0, signal=0, gamut=0, cinema=1, look=0`。

| 输入 | msg[8] | msg[9] |
| --- | --- | --- |
| 照片、PPLUT1、USER1 | 11 | 3 |
| 视频、PPLUT1、USER1 | 10 | 0 |
| 视频、PP1、USER1 | 11 | 3 |
| 视频、PPLUT1、S709 | 9 | 0 |

这是执行**原始未修改机器码**的结果。不能把“将 mode 输入改成视频能生成另一组参数”直接等同于“让真实照片模式伪装成视频是安全的”。

### CP 接收端（ARM/Thumb 混合）

二进制：`a7c2-2.01/cp-selected/files/cpapp-b.bin`，由更新包 `/cp` 分区提取。
SHA-256：`f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428`。
本轮加载视图使用 `file_offset + 0x108000`；启动自地址、有效 Thumb 代码、字符串地址、分发表相互吻合。不据此推断真机物理内存可直接访问。

分发表 `0x10fc450` 的五个 32 位值：

```text
0x4157, 0x008db56f, 0, 0, 0x00366521
```

函数指针低位 1 表示 Thumb，对应入口 `0x8db56e` 和 `0x366520`。

| 消息偏移 | 接收端字段（日志确认） | 保存地址（该加载视图） |
| --- | --- | --- |
| +8 | base_look | `0x165b218` |
| +9 | shooting_mode | `0x165b21c` |
| +10 | input_gamut | `0x165b220` |
| +11 | color_gamut | `0x165b224` |
| +12 | target_display | `0x165b228` |

`0x8db56e` 将字段写入状态，更新计数并返回 1；`shooting_mode==3` 时不更新 `color_gamut`，而是保留旧值。

`CheckSetParamBasePictureSetting`（`0x366520`）在指定条件下比较这五个状态并记录差异；已检查指令没有拒绝返回值或状态修改，不能仅凭名字把它当成权限/能力检查。

另找到 `GetVfxMlutLookname` 候选函数 `0x4e8a5c`：base_look 为 11 的分支返回 0，base_look 为 10 的分支根据其他参数产生不同 MLUT 编号。**它的调用者与 CAM/LV/照片路径归属还未核实。**

## 验证范围与已知限制

- 10 个自动化测试通过：地址解码、原始文件哈希、Ghidra 导出代码字节与源文件一致性、应用 helper 和 CP receiver 仿真。
- 应用 helper：68 组输入，通过；CP receiver：3 组输入，通过，分发表关联同步校验。
- Ghidra 已导出应用侧 14 个函数、CP 侧 3 个函数的汇编、伪代码与字节快照。
- 仿真只覆盖被隔离的参数转换/保存函数。没有模拟 Sony OS、传输协议、传感器、ISP、JPEG 编码或真实错误恢复。
- 函数参数名/类型部分来自字符串和人工推断。自动伪代码可能把常量误认成指针，或错误处理尾调用/PIC；关键结论以原始汇编和仿真为准。
- 交叉引用扫描是有界扫描；未命中不代表没有调用，尤其是虚函数、函数表与跨处理器消息。
- Ghidra ET_DYN 默认基址与 Raw BinaryLoader 块地址规则不同。导出器显式处理两种布局；测试逐函数比较原始字节，防止地址错位却生成貌似合理的伪代码。

## 下一步，按证据推进

1. 在 CP 中追踪 `0x165b218` 等状态的读取者，以及 `GetVfxMlutLookname` 的调用者。区分 CAM、LV、视频路径；确认全分辨率静态照片的色彩/MLUT 阶段。
2. 验证 USER LUT 数据上传和参数生效的时序：只保留消息选择不等于 SRAM/共享缓冲中的 LUT 已准备好。
3. 比较静态照片普通 PP 的 Gamma/颜色处理与 LUT 路径，确认色域/传递曲线和资源限制。矩阵加曲线仅作为另一种实现路线，不冒充三维 LUT 完整替代。
4. 独立评估真机执行入口与恢复路径。当前没有证明 PMCA 能在这台 2.01 上读任意文件、开 shell 或运行临时程序。文件解密、CRC 通过和函数地址都不构成安全刷回能力。

本阶段没有确认可安全部署的补丁位置。**不要把文档中的分析地址直接用于内存或固件修改。**

## 复现入口

工具：Ghidra 11.4.2（官方发布包 SHA-256 `795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6`）、现有 Java 21、`requirements-analysis.txt` 中的固定依赖。均在本地研究目录使用，没有全局安装 Python 依赖。

```sh
research/.venv/bin/python -m unittest discover -s research/tests -v
```

Ghidra 工程位于 `research/ghidra-projects/A7C2.gpr`；分析脚本 `ghidra_scripts/ExportLutFunctions.java` 使用两个 manifest：`lut-functions.tsv`、`cp-functions.tsv`。

现有 JSON 结果可直接检查。扫描/仿真脚本默认拒绝覆盖已有 JSON；重新生成应指定新输出文件，固定输出脚本需先调整输出名。固件原文件始终保持不变。
