# A7C II 2.01 静态研究

**Agent 接手先读：[HANDOFF.md](HANDOFF.md)**。包含目标、完整进展、已尝试路线、最新未完成线索、工具命令和后续优先级（更新于2026-10-08）。

目标：机内静态照片自定义风格；优先 JPEG，HEIF 单独验证。不是把视频 LUT 预览当成照片落盘效果。

最新进展见 [PHASE14_FINDINGS.md](PHASE14_FINDINGS.md)：对象 `+0x1500` 来自两套源配置的批量复制，选择规则已验证，配置业务含义仍待追踪。尚未证明静态拍照完整路径或 JPEG 效果。流资源映射见 [PHASE13_FINDINGS.md](PHASE13_FINDINGS.md)，token 传递见 [PHASE12_FINDINGS.md](PHASE12_FINDINGS.md)，Capture 类型关联见 [PHASE11_FINDINGS.md](PHASE11_FINDINGS.md)。

用户输入版本为 `2.0.1`，本次按 Sony 官方 `2.01` 研究，最终应核对机身显示。未连接、修改或刷写相机。

## 源码与参考

- Sony-PMCA-RE：`../Sony-PMCA-RE`，提交 `a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0`。
- fwtool master：`../fwtool.py`，提交 `cdba742b73eed5981480c326aeb30033aabf0223`。
- CXD90057 支持：[PR #52](https://github.com/ma1co/fwtool.py/pull/52)，独立 worktree `fwtool-cxd90057`，提交 `72fbdd1`；没有覆盖 master。作者列出 ILCE-7CM2 解密成功，但仍须验证本次文件。
- A7 IV 底层研究：`../ILCE-7M4-RE`，提交 `c3e69b60dc5a5f7e79377fb4d6f2a086c5264c9e`。[原仓库](https://github.com/DavidBuchanan314/ILCE-7M4-RE)。它的地址、引脚、载荷和无签名验证结论，不直接适用于 A7C II。
- [官方固件入口](https://support.d-imaging.sony.co.jp/www/cscs/firm/?area=jp&lang=jp&mdl=ILCE-7CM2)：BODYDATA.DAT，预期 1,139,929,560 字节。
- [官方 Picture Profile 说明](https://helpguide.sony.net/ilc/2360/v1/en/contents/0412D_picture_profile.html)：PPLUT1–4 限视频，普通 PP 与其不同。

## 本次实际结果

- 官方文件完整下载：1,139,929,560 字节。
- SHA-256：`eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31`。
- DAT CRC 与 FDAT 头 CRC 校验通过；使用 `CXD90057_k8` 解密成功。
- 内部版本 `2.01`，model `0x20030014`，region `0`。详细清单：`a7c2-2.01/unpacked/inventory.json`。
- `/usr` 对应 `nflasha15`，是明文可解析的 ext2 更新镜像；扫描到 1,157 个文件系统条目。没有执行镜像中的任何程序。
- 挂载配置明确列出 `/dev/nflasha30 /usr/data/lut vfat 23068672 16384`。更新归档没有提供 nflasha30 镜像，故未读取机身已导入的 LUT。
- 提取 `appFw.so`、`libSysDef.so`、`libmpr.so` 至 `a7c2-2.01/selected/files/lib/`。
- `appFw.so` 是 AArch64 ELF，约 100 MB；其中存在以下可定位字符串：

| 文件偏移（不是代码地址） | 字符串线索 |
| --- | --- |
| `0x48c2be8` | `model::model_api::detail::set_pplut_link(...)` |
| `0x4c0f3c0` | `model::lut_common::get_select_lut_by_pp(...)` |
| `0x4c4b200` | `model::sequence_select_lut::send_lut_procam(...)` |
| `0x4c4b318` | `model::sequence_select_lut::send_lut(...)` |
| `0x4c7fd48` | `infra_wrapper_imaging::detail::set_base_picture_setting_i(...)` |

最后一个接口的字符串签名同时包含 LUT、Picture Profile、`general_shooting_mode_t` 与 `Camera::CamUserIf::set_param_base_picture_setting_msg*`。因此它是追踪“模式判断 → 画面参数消息”的优先候选，**还不是找到解除限制的补丁位置**。完整证据与二进制哈希：`a7c2-2.01/lut-string-evidence.json`。

中文相关新证据：更新包 `/usr/share/app/` 清单含 `string_simplifiedchinese_*.uxc`，也有中文字体和朗读资源。只能证明更新包包含这些文件，不能证明日版实际安装后存在、匹配或可正常加载；不据此建议再次切中文。

上述 AArch64 交叉引用、模式分支和消息关联已推进至 CP 参数构建。下一步追踪参数消费者与真实 LUT 数据时序，区分预览与 JPEG 输出。可离线继续，不必先冒险真机写入。

## 已从 PMCA 源码确认的边界

1. 改语言走 backup 属性，不代表有任意文件读写、root 或 APK 安装能力。
2. `SenserPlatformBackend` 的 backup、文件访问、内存访问、terminal 是不同命令。菜单显示这些功能，只说明 Python 后端注册了命令，不是机身能力检测。
3. `serviceshell` 会认证、切换设备模式；并非纯被动读取。`shell` 还会切换 terminal enable。
4. `/setting/updater/dat4` 是 PMCA 读取版本的小文件目标（源码 `pmca/platform/properties.py`），是否存在于这台 A7C II 尚待确认。
5. 不试旧机型硬编码 bootrom 地址、不写 backup、不 push、不 save、不升级/降级；失败状态码原样记录，不猜成固定的权限错误。

日版选中文崩溃与资源缺失相容，但仅凭崩溃不能排除资源版本或索引不匹配。此问题与照片管线分开研究。

## 优先追踪的两条路线

### A. 找照片已有色彩参数的加载入口

定位 Creative Look / Picture Profile 参数表、Gamma、矩阵以及负责 JPEG 处理的控制服务。对照旧 APK 的 `CameraEx` 调用，寻找新平台的等价控制消息/结构，而非照搬 Java API。

旧 APK 逆向的价值是展示参数含义与调用时序；真正难点是新平台如何访问、何时下发、能否在静态照片成像链路生效。矩阵 + 一维曲线也不能精确表示任意三维 LUT。

### B. 追踪视频 LUT 到照片模式的限制

查找 LUT 导入/解析、PPLUT 枚举、拍摄模式判断、切换模式时的参数重置，以及预览与全分辨率照片处理的差异。

只有拿到交叉引用/控制流证据后，才判断限制位于 UI、控制服务还是处理硬件。去掉菜单禁用条件不等于 JPEG 会套 LUT。

## 真机何时需要

- 固件下载、解密、文件清单、字符串与反汇编：不需要真机。
- 验证服务命令支持、运行时解密模块/内存、拍照输出：通常需要真机。
- 任何临时补丁前先建立经过验证的备份与恢复路径；不能把“解密成功”当成“可安全刷回”。

最小成像验证：固定曝光/白平衡/照明，同一色卡拍摄基准与测试 JPEG + RAW；读取卡上的 JPEG 比较，不以 LCD 截图判断成功；之后再测连拍、重启及 HEIF。

## 离线检查工具

`inspect_firmware.py` 只处理本地文件：校验 DAT CRC、解密、校验 FDAT 头、输出容器与归档清单。不连接设备、不执行固件、不直接展开归档成员。

```sh
research/.venv/bin/python research/inspect_firmware.py \
  research/a7c2-2.01/BODYDATA.DAT research/a7c2-2.01/unpacked
```

输出目录必须不存在，防止覆盖已有分析。完整结果以 `unpacked/inventory.json` 为准。CRC 是完整性检查，不是数字签名验证。
