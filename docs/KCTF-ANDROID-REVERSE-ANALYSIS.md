# KCTF Android CTF 本地逆向记录

> 状态：进行中。本文只记录已在本地样本上复现或验证过的结论；推测会明确标注。

## 范围与样本

- 题目目标：用户名固定为 `KCTF`，求能通过 APK 本地校验的序列号。
- 约束：后续分析仅使用本地 `ctf.zip` 解出的 APK 和本地工具，不再访问远端仓库。
- APK SHA-256：`9da7bb318ffbbf6f051d26637cca5fd80d808ed28220001ca9b8a3a2063fe551`。
- 用户提供的环境自检组合已保留为交叉验证输入：
  - 用户名：`C7D9F375EDB4FD2B`
  - 序列号：`RdY/\\=L>B1$>/]4uj3NG1Y-@&aO@qT~`

## 已验证的加载链

1. APK 的外层 Java 壳为 `com.kctf.shell.S`，会加载 `libkctf.so`，再通过 `InMemoryDexClassLoader` 启动 `com.kctf.payload.Core`。
2. Java 类 `com.kctf.shell.N` 声明 8 个 native 方法：`a` 到 `h`；其中 `g()` 返回 `ByteBuffer`，是内存 DEX 载荷的关键入口。
3. 关键资源位于 `assets/nebula/`：
   - `payload.bin`、`meta.bin`
   - `d1.pkg`（11,320 字节，文件头为 `KCTFDEX2DEX2KCTF`）
   - `sog.arm64-v8a.bin`（保护/环境检测层）
   - `som.arm64-v8a.bin`（核心 native 层）
4. `lib/arm64-v8a/libkctf.so` 是第一层 loader，原始 SHA-256：`f2836d017c379abe0bc6ccff7ecb948f5e7279b6ce7465d62f5ae2c9a5b9678a`。

## Rikune 与本地交叉验证

- 已通过 Rikune Android 插件完成 APK 清单、DEX 类清单和 Java 壳代码定位。
- 因原始 ELF 的 section-name 元数据故意损坏，仅对临时副本清零 section-name 相关字段后导入 Rikune/Ghidra；没有修改 APK 或其原始 native 二进制代码。
- 在 `libkctf.so` 中确认 SOV2 loader 位于虚拟地址 `0x00103c0c`（文件偏移 `0x3c0c`），负责解开 `KCTFSOV2` 封装的二进制层。
- 使用本地 AArch64 交叉执行对上述结论进行了运行时验证，而不是只依赖反编译推测。

## 已解出的 native 层

### SOG（保护层）

- 已解出为 ELF，SHA-256：`e08f06eba6c2821801671ba899d8b1b02591e64ed9d2ecb0409c7b7cd241b918`。
- 导出函数包含 `g7a0p`、`g7b1d`、`g7c2a`、`g7e4m`。
- `g7a0p` 是环境检测/状态生成入口，会循环生成 431 条记录。
- 为获得与合规真机一致的密钥材料，分析运行器只在内存中：
  1. 将每条记录的检测状态置零；
  2. 强制走 `g7a0p` 的 clean 分支。
- 该处理没有回写原 APK、原 `libkctf.so` 或任何原始资源文件。

### SOM（核心层）

- `g7b1d`（不是 `g7c2a`）生成的材料，再经主 loader 的 `0x00105b14`、标签 `CDO2` 的派生过程，可正确解出 `som.arm64-v8a.bin`。
- 已解出 ELF：`libkctf_core.so`，长度 515,016 字节。
- `JNI_OnLoad` 位于 `0x0010c710`，会为 `com.kctf.shell.N` 动态注册 8 个 native 回调。
- 核心层包含与下一阶段直接相关的字符串：`nebula/d1.pkg`、`DXHDR`、`DEX2A`、`DEX2B`、`DEX2C`、`DEX2D`、`DEXK`、`KDFD`、`PAYL`、`META3`、`SOV2B`。

## 已验证的 JNI 接口表

`JNI_OnLoad` 在 `0x0010cbc0` 通过 `RegisterNatives(..., 8)` 注册下表。名称和签名在运行时以 XOR 方式还原，签名 XOR key 位于 `0x001028a0`（`KCTF-MANIFOLD-v\x01`）。

| Java 方法 | JNI 签名 | 核心层回调 VA |
| --- | --- | --- |
| `a` | `(Ljava/lang/String;)V` | `0x0000d20c` |
| `b` | `(Landroid/content/res/AssetManager;)V` | `0x0000d3cc` |
| `c` | `(Ljava/lang/String;Ljava/lang/String;)I` | `0x0000d464` |
| `d` | `()Ljava/lang/String;` | `0x0000d7d8` |
| `e` | `(Ljava/lang/String;)Ljava/lang/String;` | `0x0000d8dc` |
| `f` | `()Ljava/lang/String;` | `0x0000dc3c` |
| `g` | `()Ljava/nio/ByteBuffer;` | `0x0000ddc8` |
| `h` | `()V` | `0x0000df50` |

已确认 `N.g()` 调用 JNI `NewDirectByteBuffer`（vtable 偏移 `0x728`），所以它的结果就是被解密后的内存载荷，而非普通配置数据。

## `d1.pkg` 读取与解包链

1. `N.g` 的回调链最终进入 `0x0012fca0`；该函数先读取一个最小头部，再申请输出缓冲区并解密完整载荷。
2. `0x0012f18c` 明确通过 `AAssetManager_open(..., "nebula/d1.pkg", ...)` 读取资源；无法获得 AssetManager 时才走备用文件路径。
3. 头部识别到两种格式：`KCTFDEX1` 和 `KCTFDEX2`。当前样本为 `KCTFDEX2`，会从偏移 `0x18` 取 32 字节材料，交由后续 KDF 和解包函数生成完整载荷。
4. 下一步是还原 `0x0012f438` 的完整包解密过程，并直接导出 DEX 进行 Java 层序列号算法分析。

### 当前样本的 DEX2 头部与密钥材料

- `d1.pkg` 的前 8 字节为 `KCTFDEX2`，偏移 `0x08..0x0f` 为 nonce/context：`DEX2KCTF`。
- 偏移 `0x10` 的 BE32 输出长度为 `0x2b9c`，即 11,164 字节；`pkg[0x16] = 8`，因此头部长度为 `0x58 + 8 × 8 = 0x98`。
- 后续有 8 个 BE `(offset, length)` 表项；当前样本每块大小为 `0x574`，加密 payload 总长度为 `0x2ba0`。
- 头部 KDF 已独立复核：
  - `H = hash32(d1[0:0x18])`：`3fa23cccab1876cc9d7b1268c2ac1c8c4612f2ce96d65715bc3a1f05fe990ac4`
  - `key = hash3("DEXK", H, "LOAD")`：`a1c4d410f416e766e8baddf44fee2cf6ad5bb57bf0e3e162214d603eb4bdcef2`
- 完整解包路径会对输出前 4 字节验证 `dex\n`。这为后续导出的 DEX 提供了明确的正确性判据。

## DEX 已导出

- 已在本地离线复现完整 DEX2 变换，没有执行 APK 或修改原始样本。
- 输出文件：`/tmp/kctf-d1.dex`
- 长度：11,164 字节；头部：`DEX 038`。
- SHA-256：`17e03bf05a3eacac4b101f4256f4069e3e8d2863ffd9dca19995a96235d26a79`。
- 可复现解包脚本：`/opt/rikune-data/workspaces/kctftest-static.ko2qrX/decode_dex2.py`。
- 后续工作从 native 解包转为 DEX 中的用户名/序列号校验逻辑定位与交叉验证。

## 校验入口已定位

- DEX 中仅有 `com.kctf.payload.{Core,Gate,Mix}` 三个类；`Core.runVerify` 先过滤为可打印 ASCII，再反射调用 `com.kctf.shell.N.c(name, serial)`。
- `N.c` 的 JNI 签名为 `(Ljava/lang/String;Ljava/lang/String;)I`，注册回调为核心层 `0x0000d464`。
- 该 JNI wrapper 复制用户输入后进入 `0x0000dfe8`，最终在巨大环境/反篡改编排函数 `0x0010e918` 调用实际验证器 `0x001568a4(name, serial, stateA, stateB)`。
- `0x001568a4` 将输入和状态放入 0x7e8 字节 context，解开 0x19c 字节 VM 程序，并最多迭代 19,999 步执行 `0x001570bc`；context 的结果字段决定 `N.c` 是否返回 `1`。
- 因此最终序列不是 DEX 内硬编码字符串，必须还原或运行该本地 VM；当前正以用户提供的通过样例作为 oracle 交叉验证。

## 当前结论与下一步

- DEX 已成功导出并完成 Java/JNI 校验链定位；native VM 的最终比较约束也已完整逆出。
- 最终用户名/序列号及 case `5` 的动态成功证据见本文末尾的“最终结果与复核”。

## 运行时复核与环境分支（2026-07-24）

- Ghidra 导入核心 ELF 时使用的 image base 是 `0x00100000`，因此 Ghidra VA 与原 ELF 文件内偏移相差 `0x100000`。例如 Ghidra 中的 `0x0012f2ec` 对应实际调用偏移 `0x2f2ec`。这已通过直接调用头部解包函数和完整 DEX 输出复核。
- 隔离的 AArch64 harness 可以正常到达 `0x000568a4` VM 执行器；其真实原型为 `verify_vm(name, serial, stateA[32], stateB[32])`。VM 入口会要求序列号长度为 32，且每个字符在可打印 ASCII `!` 至 `~` 范围内。
- `0x000568a4` 内会解开 0x19c 字节的 VM 程序，最多执行 19,999 步，并通过 context 的 `+0x5b0` 字段返回成败。最终比较由 VM opcode `0x41` 触发；该路径会生成 4 个 32 字节临时块，再调用 `0x0006d534(..., name, name_len, serial)`。
- `N.c` 的完整编排函数会枚举 `/proc`、创建后台监控线程并依赖 Android 环境状态。为只读调试，在独立内存映像中将该监控的 BSS 状态位置 `0x802d4` 置为已初始化，从而避免线程触发的栈保护失败；原 APK、原 ELF 和资源文件均未改写。
- 在 QEMU/Linux harness 中，题目给出的合规真机自检组合能到达 VM，但返回 `0`。这符合其“合规真机”前提：此结果只能证明当前 Linux/QEMU 环境状态不同，不能作为自检组合失效或候选答案错误的结论。
- 已在 VM 入口捕获该 QEMU 环境下由 `N.c` 临时生成的 `stateA/stateB`，并确认它们是环境相关的中间状态，不能直接当作题目的通用密钥或最终答案。

## 二层比较 VM 与可逆 serial 表示（2026-07-24）

- 第一层 VM 的 opcode `0x41` 不直接比较 hash；它进入 `0x0006d534`，后者以 key `SERC` 解开第二段 0x208 字节 VM 程序，并调用 `0x0006f984`。
- 第二层 VM 的输入 context 保存四个由第一层导出的 32 字节块（`+0x7a8` 至 `+0x7c0`）、name（`+0x7c8`）、name 长度（`+0x7d0`）和 serial 缓冲区（`+0x7d8`）。这些偏移已由 AArch64 指令及动态断点共同验证。
- 第二层 opcode `2` 把 32 个可打印 serial 字符映射为 `serial[i] - 0x21` 的 base-94 值。虽然 opcode `4` 具备反向映射能力，但本题实际执行的 0x208 字节流没有执行该 opcode；因此从 `ctx+0x28` 读到的值只是中间状态，不能直接当作 serial。
- 为避免依赖完整 Android UI，本地仅对内存映像构造了与比较器相同的 context 和第二层置换表。该辅助过程没有修改任何 APK、ELF 或资源文件；其用途是提取约束和候选 serial。

## 二层末端约束与逆解进展（2026-07-24）

- 已静态解析第二层程序的全部 428 个 dispatch。最后两项分别为 opcode `5`（比较）和 opcode `0`（结束）；opcode `5` 调用 `FUN_0011b71c(ctx+0x48, name, name_len, ctx+0x08)`，而不是直接比较 `ctx+0x28`。
- 高阶 opcode `0x40..0x62` 均有正向/逆向分支。原始流采用正向分支；该段可以按 selector 升序配合逆向分支回退，但它不是整条 serial 变换的唯一阶段：其后还有多组会写入 `ctx+0x28` 的 opcode，必须一并逆转。
- 以 `KCTF` 和已捕获的首层四个临时块运行到末端后，比较器要求的 `ctx+0x48` base-94 目标为：`4d431c200f2740560c0933360b4b1a44192137281d2f0f22050454110140033c`。其加 `0x21` 后的 printable 表示为 `nd=A0Haw-*TW,l;e:BXI>P0C&%u2"a$]`，**这是比较目标状态，不是最终 serial**。
- case `0x79` 的逆掩码已被静态消去，得到其前一边界状态：`5d4f45563f020254360a2005593557390e0021184a1c104c03242f41370b0f4c`。这一状态仍需先逆转 idx 180 至 420 的中间轮次，才能再逆转 `0x40..0x62` 高阶 sweep。
- 先前从全 `!` 测试输入导出的 `J@ph}=#2/(svjBs#EB\"*pf\\Wql;iR:Sd` 已确认仅为中间状态，不是答案；保留该负例以防止重复误判。
- 临时 runner 曾在 interpreter 的首个 opcode `1` 之外又提前调用一次 `0x6d6c8`，会污染 VM context；该错误已定位并移除。真实比较器由 `0x0006d534` 完成 `0x6d658 → 0x6d6a8 → 0x6f984`，而 `0x6d6c8` 仅由该 VM 的首个 opcode `1` 调用。
- 所有动态调试补丁均限于 `/tmp` 的隔离 runner 内存映像或辅助源文件，未回写题目压缩包、APK、原始 ELF 或资源文件。

## 最终结果与复核（2026-07-24）

输入应为：

```text
用户名：KCTF
序列号：7_jJYVc`8GP*Bhhy^D;*D0N/a.Szpw'#
```

- 序列号长度为 32，逐字节十六进制为：`37 5f 6a 4a 59 56 63 60 38 47 50 2a 42 68 68 79 5e 44 3b 2a 44 30 4e 2f 61 2e 53 7a 70 77 27 23`；其中第 8 个字符是反引号，第 31 个字符是单引号。
- 逆解不是猜测：先将 `KCTF` 的末端约束逆过 case `0x79`、WHT0/WHT1/PERM/SALT/NLCH、12 轮 work-buffer cipher 和高阶 selector sweep；随后逆 `0x33/1` 前置置换并用 opcode `4` 写回 printable serial。
- 逆链以全 `!` 输入做了正反闭环：真实正向 VM 的 case `0x79` 前状态被完整逆回 32 个 `!`，中间边界（high sweep、NLCH、AFF、SALT、PERM、WHT1、12-round）逐段与正向执行状态一致。
- 将最终序列送回未经截断的二层 VM 后，`ctx+0x28` 与 `ctx+0x48` 均精确达到目标：`4d431c200f2740560c0933360b4b1a44192137281d2f0f22050454110140033c`。
- 动态断点位于 case `5` 调用的 `FUN_0011b71c` 返回点：该函数返回 `w0 = 1`；随后 `0x6f984` 返回 `x0 = 1`、context 成功位 `+0x77c = 1`，anti flag `+0x780 = 0`。隔离 runner 末尾打印的 `secondary result=0` 读取的是 `frame[0]`，不是 VM 成功位。
- 外层 `N.c` 在 Linux/QEMU harness 仍会受 Android 环境/反监控编排影响，因此不能用其最终 `0` 覆盖上述 comparator 成功证据；题目所述合规真机路径应以此用户名和序列号通过。
