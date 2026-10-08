# 已纳入仓库的固件分析输入

本私有仓库跟踪三份 A7C II 2.01 逆向工作直接依赖的原始提取二进制。它们仅用于研究和复现，不是可刷写固件包。

| 路径 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `a7c2-2.01/cp-selected/files/cpapp-b.bin` | 18,090,880 | `f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428` |
| `a7c2-2.01/selected/files/lib/appFw.so` | 99,960,744 | `2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b` |
| `a7c2-2.01/system-selected/files/av-cam.bin` | 13,797,088 | `90343f5f2edc0393ad8809d907cfe648dfd3a82ce0ef39cf06167929d8955096` |

完整官方 `BODYDATA.DAT` 为 1,139,929,560 字节，SHA-256：

```text
eb4943e6099754d64deaef5047942e9bfe258f232d0b7bc39fa23b3cd10e1e31
```

该文件超过 GitHub 普通 Git 单文件限制，未纳入仓库。原始来源、解密和提取步骤见 [README.md](README.md) 与 [HANDOFF.md](HANDOFF.md)。

校验：

```sh
shasum -a 256 \
  research/a7c2-2.01/cp-selected/files/cpapp-b.bin \
  research/a7c2-2.01/selected/files/lib/appFw.so \
  research/a7c2-2.01/system-selected/files/av-cam.bin
```
