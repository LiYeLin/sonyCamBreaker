# Sony A7C II 照片滤镜逆向研究

**新 Agent 接手入口：[研究交接文档](research/HANDOFF.md)**。

文档包含当前目标、用户约束、已验证进展、尝试过的路线、代码与证据位置、最新未完成线索、复现命令和后续研究方向。

当前仍处于离线研究阶段，尚未证明全分辨率照片 JPEG 能应用自定义 LUT；未连接或修改相机。详细阶段索引见 [research/README.md](research/README.md)。

私有仓库包含逆向所需的三份核心二进制：`cpapp-b.bin`、`appFw.so`和 `av-cam.bin`，详见 [research/FIRMWARE_INPUTS.md](research/FIRMWARE_INPUTS.md)。完整 `BODYDATA.DAT`、分区镜像、生成的反编译/JSON 产物、第三方仓库、Ghidra 和 Python 环境仍由 `.gitignore` 排除。
