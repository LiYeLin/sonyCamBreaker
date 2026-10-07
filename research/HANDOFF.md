# Sony A7C II 照片 LUT 逆向：Agent 接手文档

更新：2026-10-08。工作目录 `/Users/liyelin/sonyCamBreaker`。本文是接手入口；详细证据仍以原始固件、脚本、测试及各阶段文档为准。无需前序聊天即可继续。

## 1. 目标、用户背景与当前结论

**最终目标：在 Sony A7C II / ILCE-7CM2 上实现机内静态照片自定义滤镜/LUT，优先让存储卡上的全分辨率 JPEG 真正应用效果。** HEIF 后续独立验证。不能以菜单开放、视频 LUT、LCD 预览、元数据变化或外部后期替代成功。

用户使用日版 A7C II，报告已用 PMCA 解锁语言并切英语；切中文会死机。用户给出版本 `2.0.1`，现按官方固件 **2.01** 研究；机身版本最终仍需核对。最初从旧机型 A7M2 的 APK 汉化/滤镜方案出发，随后转向新平台原生固件。

当前已做到：官方固件下载、解密、提取、反汇编/反编译，以及应用层限制、CP 参数构建、LUT 驱动、资源申请和配置选择的局部证据链。**未实现可部署功能、未生成可刷写补丁、未证明静态 JPEG 使用自定义 LUT。**

用户偏好简洁、说重点；实际研究和交接文档可以详尽。持续目标“继续推进目标”仍未完成。最近各轮有实际证据和代码进展，并非阻塞等待。

## 2. 安全与授权边界

- 至今没有连接、修改、刷写相机，也没有执行相机服务命令；原始固件文件未改。
- PMCA 语言属性可改，不等于有 root、任意文件读写、代码执行或 APK 运行环境。
- 真机 serviceshell 会认证/切模式，shell 可能开启 terminal，不是纯被动读取。
- 不自动执行 backup 写入、push/save、升级降级、旧型号 bootrom 地址或寄存器写入。
- 真机补丁实验前需单独确认执行能力、备份和经过验证的恢复办法。解密成功不等于可重新签名、安全刷回或恢复。
- A7 IV 研究的引脚、漏洞、无签名分区结论不能直接套用 A7C II。
- 官方更新包内含中文资源，不能仅凭日版切中文崩溃就断言中文资源必然被删除。也不建议再次切中文试错。
- 本目录不是 Git 仓库，内部有多个独立仓库。保留用户改动；编辑使用 `apply_patch`。不要全盘扫描个人目录。未获得委派要求，不使用子 Agent。

## 3. 文件与运行环境

### 仓库

| 路径 | 用途 / 已记录版本 |
| --- | --- |
| `Sony-PMCA-RE/` | https://github.com/ma1co/Sony-PMCA-RE ，`a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0` |
| `sony-pmca-ricoh-mod/` | 旧 PictureEffectPlus 修改方案，v1.8.0，提交前缀 `3dc7776` |
| `fwtool.py/` | 固件解析原仓库，提交 `cdba742b73eed5981480c326aeb30033aabf0223` |
| `research/fwtool-cxd90057/` | fwtool PR #52 独立 worktree，提交前缀 `72fbdd1`；本次解密使用此支持 |
| `ILCE-7M4-RE/` | A7 IV 参考研究，提交 `c3e69b60dc5a5f7e79377fb4d6f2a086c5264c9e` |

以上为分析时记录，不保证外部远端仍是该版本；接手可只读检查 `git -C <目录> rev-parse HEAD`，无需重新 clone/download。

### 固件与地址约定

所有下列路径相对于 `research/a7c2-2.01/`：

| 文件 | 格式 / 地址约定 | SHA-256 |
| --- | --- | --- |
| `BODYDATA.DAT` | 官方 2.01，1,139,929,560 字节 | `eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31` |
| `selected/files/lib/appFw.so` | AArch64 ELF；文中地址为原始 ELF VA，须按 LOAD 段转换文件偏移 | `2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b` |
| `cp-selected/files/cpapp-b.bin` | ARM32，主要 Thumb2；离线 VA = 文件偏移 + `0x108000` | `f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428` |
| `system-selected/files/av-cam.bin` | 原始 AArch64；离线 VA = 文件偏移 + `0xffffffc001000000`，报告优先写文件偏移 | `90343f5f2edc0393ad8809d907cfe648dfd3a82ce0ef39cf06167929d8955096` |

离线加载地址不代表已经核实的真机物理地址。appFw 的部分 LOAD 段存在 `0x10000` 差值，不能直接用 VA 当文件偏移。

DAT CRC、FDAT 头校验通过；CXD90057_k8 解密成功。内部版本 2.01、model `0x20030014`、region 0。提取物在 `unpacked/`、`partitions/0700_part_image/dev/`。nflasha15 为 `/usr` ext2；nflasha3 为 `/system` FAT；nflasha8 为 `/cp` FAT；nflasha7 为 rootfs。

挂载配置有 `/dev/nflasha30 /usr/data/lut`，但更新包没有 nflasha30，**未获取用户机身导入 LUT 的分区内容**。

### 工具

- Python：`research/.venv/bin/python`，pyelftools 0.33、Capstone 5.0.9、Unicorn 2.1.4；版本表 `requirements-analysis.txt`。
- Ghidra 11.4.2：`research/tools/ghidra_11.4.2_PUBLIC/`，Java 21 已可用。
- Ghidra 项目：`research/ghidra-projects/A7C2.gpr`，程序 `appFw.so`、`cpapp-b.bin`。
- 导出脚本 `ghidra_scripts/ExportLutFunctions.java`，清单 `lut-functions.tsv` / `cp-functions.tsv`。
- 导出结果 `a7c2-2.01/decompiled/` 和 `cp-decompiled/`，包含 `.c/.asm/.bytes.hex`。

## 4. 已证实的主要链路

以下箭头可表示字段读写关系，不必然是直接调用或已经验证的实际调度。

### A. 两层软件限制

1. appFw `0x352c5dc`（set_base_picture_setting_i）：应用 general_shooting_mode=0（STILL）强制 `msg[8]=11,msg[9]=3`；视频测试输入可保留 `[10,0]`。
2. `0x3537fd0` 构造 16 字节消息 `0x4157`，经 `0x35358b8` 发送。
3. CP 接收 `0x8db56e` 保存到状态基址 `0x165a720` 的 `+af8/+afc/+b00/+b04/+b08`；该接收函数没有拒绝测试输入。
4. CP 构建 `0xb2c406` 调用归一化 `0xb31aac`：CP mode=3 强制 base_look=11；base_look=10 但 l3d 长度=0 则归零。
5. `0x4e8a5c`（GetVfxMlutLookname）将 base 11 映为 MLUT ID 0。

**应用 STILL=0 与 CP mode=3 不是同一枚举。CP mode=3 也可能出现在普通视频设置中，不能看到 3 就认定静态照片。** 只改应用层限制不足以完成迁移。

### B. 参数结构与提交

处理对象：`+13b4` 为资源 token；`+13b8` MLUT ID；`+13bc` CP mode；`+13c0` effective base；`+13c4` color；`+13d0` 起为 96 字节描述。

描述前 24 字节：l3d 地址64、reg 地址64、l3d 长度32、reg 长度32。来自 CP 状态 `+68/+70/+78/+7c`。

`0x4e876c`（SetVfxMlutParam）接收 token 与对象 `+13b8`；ID=0/token=0 不提交，另有 cache/busy 条件。reg 长度=0 走 `0x54e15c`，非零走 `0x54e398`。完成回调 `0x4e89f0`。

驱动构建 `0xb799de` 要求 l3d 长度48000，`0xb79ab4` 要求 reg 长度124；IP索引无符号≤6。请求长度值分别12000/31，类型1/3；无效返回 -13。不是直接接收任意 .cube 文件。

56 字节请求经 `0xb83282` 投递；worker `0xb82c22` → dispatcher `0x53533c` → l3d handler `0xb82d7c` / reg handler `0xb82e00`。

`0xb8336c` 将 l3d 拆成24对、48个控制/数据描述，每段2000字节。控制目标偏移 `0x408`，数据目标偏移 `0x3000`。控制源表 `0xe953fc` 第0项指向运行时区域，值未知；余项能从文件读取。**不能仅由48000或分组模式推断 RGB、网格维度或 LUT 布局。**

`0xb77ff8` 算目标基址；`0x5353f4` 处理地址/描述链；`0xb83062` 提交并等待，回调 `0xb831f8`。未仿真真实 DMA/MMIO/中断，等待参数 `0x3e8` 单位未知。

### C. 资源 token 与流

- owner 表 `0x1a7e578` 有四项 `{owner,type}`。
- `0x54d2d4` 写 owner；kind0/1 对应 type1/2，业务意义未知。
- `0x54d788` 匹配 owner/type，掩码1/2/4/8/15/3/12映射索引0/1/2/3/4/5/6；`0xbb42da` 再恒等映射。
- 七个索引包含单槽/双槽/全槽组合，**不是七个已证实的物理引擎**。
- `Camera::Capture::CapRsrc_VFX` RTTI 已确认，虚表项指向 `0x4811dc`，日志 AcquireMain；类名仍不能证明最终照片像素处理。
- `0x4e7dd0` → `0x54d660` 申请；通用 dispatcher `0x4ba9d0` 的资源 case23/30/37/44进入此分支。
- token 暂存栈+a8，然后写资源记录 `0x1a539a8+case*0x40+c`，复制回处理对象 `+13b4`。
- 四个提交点 `0x4c2eae/0xb2b4d4/0xb2b596/0xb2ba0e` 均读取 `+13b4`，传 `+13b8` 给 MLUT。
- `0xb0a332` 按流编号和类别查资源；`0x46f6e0` 选择组成流表。类别0x10：流1/2/3/4分别资源23/30/37/44；流5为23+30，6为37+44，7为全部；8/9/10初始表为空。
- 名称分别为 GRP05_VFX / GRP06_VFX / GRP07_VFX / GRP08_VFX。流编号、通用资源case、MLUT组合索引是不同空间，不要混用。

### D. 当前最前沿：流编号的配置来源

处理对象 `+1500` 是流编号。初始化 `0x4be1a4` 选两套源配置之一，再在 `0x4be57a..0x4be58c` 批量复制16字节：源+74 → 对象+14fc，所以流来自源+78。

令 `context=0x173efe8`、`config=*(context+c)`：源A=config+20，源B=config+630，流字段分别 config+98 / config+6a8。

选择B的条件：`s==0 || (s==1 && (f|1)==3) || (s==2 && f==3) || g`；其中 s=config+698 的32位值，f为 `*(context+2c)+1` 的字节，g为地址0x1a533ba的bit1。否则选A。

32组选择/复制测试通过，但测试中A/B的流1/8是人为哨兵，**不是实际照片/视频流值**。

## 5. 本轮新增、尚未形成阶段报告的线索

以下仅完成局部反汇编核对，尚未新增专门测试；接手从这里继续，避免重复搜索：

1. **上下文指针的生产者已找到**：`0xb2ebce` 接收 r0=owner、r1=context；`0xb2ebe0/0xb2ebe4` 设置 `context+c=owner+e18`；`0xb2ec1e..0xb2ec24` 设置 `context+2c=owner+3d58`。
2. `0xb2e8e0` 调用该布局函数；`0xb2e656..0xb2e668` 将全局context0x173efe8传入。owner实际来源还需沿调用者核对，不能只凭邻近getter常量硬设。
3. 因此源流字段可继续按 **owner+eb0 / owner+14c0** 搜索；源配置块整体长至少0xc0c。
4. 已找到整块复制：`0x4da7b2..0x4da7be`、`0x4dad56..0x4dad62` 将两个owner的+e18块按长度0xc0c memcpy；`0x4d9978` 附近也有该长度复制。这解释为什么只搜直接STR目标偏移可能无结果。
5. `0x4d8fb2` 构造 owner+e18，在 `0x4d8fba` 调用 **`0xb0ae02`**；该函数处理配置字段，是优先继续跟踪的入口。
6. `0xb0af08/0xb0af10` 在上游 config+630 与 config+20之间选择，条件涉及计数比较 fp/r8；当前只证实读取源，尚未证实写入流字段。
7. `0xb0b5f4/0xb0b5f8` 有 source+134→dest+98 的复制，但 **尚未证明 dest 就是上述 config**。必须先确认函数边界/调用参数，不能凭相同偏移认定。
8. `0x4efcdc` 一带也写+698/+6a8，但伴随成对32位结果；没有对象同一性证据，暂作为偏移碰撞候选，不纳入已证实链路。
9. `0x43ff80` 是字段登记代码，附近名称 CUC_FK_32/33，不是流编号赋值证据。

本轮原始文件未改、无后台进程需要等待。最后成功测试为33项（2026-10-08交接时已重跑）。

## 6. 已尝试的路线、结果与不要重复踩的坑

| 路线 | 已做 / 结论 |
| --- | --- |
| 旧 APK 反编译/开源修改 | CameraEx 私有API、RGB矩阵/WB/1024点gamma提供参数语义参考；不是新机可直接安装的兼容层，矩阵+1D曲线不能表达任意3D LUT |
| PMCA 改语言 | 明确属性写入与文件/内存/terminal命令分离；未验证A7CII执行能力，不把语言成功扩张成root |
| 固件解密提取 | 已成功，不需要重新下载；CRC不等于签名验证 |
| 应用层模式限制 | 找到且执行原始代码验证；CP仍有第二层归一化 |
| 参数标志路由 | 原先只测四索引排列，后来确认[0,0,0,0]重复映射；现工具已允许重复，旧384组不是全覆盖 |
| CameraInfo到av-cam | RTTI一致、entryID5、payload936字节，已追到读取者；可能是编码/thumbnail元数据，不能冒充像素路径 |
| 实际LUT驱动 | 已确认长度、请求、worker、分段和完成同步；未确认数据格式/真实硬件执行 |
| 资源与流配置 | 已追到token、查表、配置选择；实际静态拍摄的流值仍未知 |
| 指令扫描 | Thumb半字扫描可能命中数据或指令后半部；直接调用扫描漏间接/ARM调用，必须查看上下文 |
| Ghidra | CP必须传 `thumb`；默认ARM/旧解码会产生伪代码错误。`0x688954`经Thumb/ARM thunk到memcpy需手工核对，警告不能忽略 |
| 仿真 | 仅执行注明的完整函数或片段；合成状态、手动跳转和跳过OS的边界必须披露。测试通过不等于整机行为 |
| 地址/枚举 | 相同偏移不等于同一对象；同一数值不等于同一枚举；七索引不等于七硬件引擎 |

## 7. 复现与工具入口

从项目根目录执行：

```sh
research/.venv/bin/python -m unittest discover -s research/tests -v
```

当前33项通过，包括固件hash、导出字节与原文件匹配、原始指令行为。它们不覆盖真实JPEG、机身恢复、完整OS调度或刷写。

大多数生成脚本使用独占创建 `open('x')`，输出必须为新路径，不要为了重跑删旧证据。例如：

```sh
research/.venv/bin/python research/emulate_stream_config_selection.py /tmp/a7c2-config-selection-new.json
research/.venv/bin/python research/emulate_mlut_stream_resources.py /tmp/a7c2-stream-resources-new.json
```

工具索引：

| 脚本 | 用途 |
| --- | --- |
| inspect_firmware.py / inspect_ext2.py | 本地容器/分区检查 |
| collect_lut_strings.py / extract_enum_tables.py | 字符串/枚举证据 |
| scan_lut_xrefs.py / scan_cp_xrefs.py | AArch64 / CP引用候选 |
| scan_direct_calls.py / scan_thumb_calls.py | 直接调用候选；后者支持原始CP文件 |
| emulate_picture_gate.py | 应用模式覆盖，68组 |
| emulate_cp_receiver.py / emulate_cp_pipeline.py | 接收与构建，后者768组 |
| emulate_mlut_handoff.py | 提交下层接口边界 |
| emulate_mlut_routing.py | 标志重排；`--initialized-maps`覆盖真实两种初始化 |
| inspect_camera_info_bridge.py | CP/av-cam RTTI、payload与调用证据 |
| emulate_mlut_driver_request.py | 长度/IP约束与手动请求分派，90组 |
| emulate_l3d_descriptors.py | 传输描述14组 |
| emulate_mlut_resource_mapping.py | owner查询35组 |
| emulate_mlut_resource_allocation.py | owner写入/解析28组 |
| emulate_mlut_token_flow.py | token保存/提交参数16组 |
| emulate_mlut_stream_resources.py | 原始非空资源查询7组，空表静态检查 |
| emulate_stream_config_selection.py | 配置选择/复制32组 |

具体CLI用 `--help` 和源码核对，不推测参数。产物JSON均在 `research/a7c2-2.01/`。

Ghidra CP重新导出命令（保留 `thumb`）：

```sh
research/tools/ghidra_11.4.2_PUBLIC/support/analyzeHeadless \
  research/ghidra-projects A7C2 -process cpapp-b.bin -noanalysis \
  -scriptPath research/ghidra_scripts \
  -postScript ExportLutFunctions.java research/cp-functions.tsv research/a7c2-2.01/cp-decompiled thumb \
  -log research/a7c2-2.01/ghidra-cp.log
```

不要用整库自动分析替代函数边界核实。导出脚本会修改Ghidra项目，不修改固件。运行完重跑字节一致性测试。

## 8. 后续研究优先级与成功门槛

### 优先1：完成实际拍摄场景绑定

从本轮新线索 `0xb2ebce`、`0xb0ae02`、owner+e18整块复制继续，确认源配置字段生产者；查明静态拍照/预览/视频各自流编号及资源类别0x10是否申请。重点产物应是实际调用者、字段来源、条件及可复现证据，而不是继续增加与模式无关的哨兵测试。

### 优先2：LUT 数据来源与格式

向上追 appFw send_lut、CP描述地址的生产者，找 CUBE 到48000字节l3d/124字节reg的转换和下发时序。不能靠总长度猜格式。第0个控制字的运行时初始化仍未解决。

### 优先3：最终照片像素路径

把 MLUT 所在资源与静态全分辨率图像处理、JPEG编码输入关联；区分CameraInfo元数据、预览和实际像素。必要时另开照片已有Creative Look/PP矩阵gamma控制路线，但不把有限参数调节说成任意3D LUT支持。

### 优先4：执行入口、部署与真机验证

离线资料不能证明机身支持当前服务命令、内存补丁或修改固件启动。需要用户配合确认机身版本、连接方式、可用服务能力及恢复条件；不得提前写设备。

最终最小实验：固定光照/曝光/白平衡，色卡拍基准和测试JPEG+RAW；从卡上读取JPEG比较实际像素，而不是拍LCD。再查连拍、重启、模式切换，HEIF另测。没有这类证据不能宣布目标完成。

## 9. 阶段证据阅读顺序

首次接手先读本文，再读 [PHASE14](PHASE14_FINDINGS.md)、[PHASE13](PHASE13_FINDINGS.md)、[PHASE12](PHASE12_FINDINGS.md)。按需要回看：

- [PHASE2](PHASE2_FINDINGS.md)：应用限制与CP消息。
- [PHASE3](PHASE3_FINDINGS.md)：CP第二道限制。
- [PHASE4](PHASE4_FINDINGS.md)：描述与提交。
- [PHASE5](PHASE5_FINDINGS.md)、[PHASE6](PHASE6_FINDINGS.md)：标志路由及重复映射修正。
- [PHASE7](PHASE7_FINDINGS.md)：CameraInfo跨模块，非像素证明。
- [PHASE8](PHASE8_FINDINGS.md)、[PHASE9](PHASE9_FINDINGS.md)：驱动/传输。
- [PHASE10](PHASE10_FINDINGS.md)、[PHASE11](PHASE11_FINDINGS.md)：资源组合/申请。

新Agent接手后：先跑33项测试确认基线，核对最新文件是否有新增改动，然后从第5节未完成线索继续。不要重新下载固件或把这些阶段文档当作已完成JPEG功能的证据。
