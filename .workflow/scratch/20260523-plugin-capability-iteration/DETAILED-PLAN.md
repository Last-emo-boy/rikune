# 插件能力链迭代计划

## 目标

这轮不是继续堆插件数量，而是把已有插件矩阵升级成可执行的纵向分析链。每条链必须能被 `tools.discover` 找到，能被 `tool.readiness` 解释，能输出标准 artifact/evidence，并且默认不执行 live sample。

## 纳入范围

- `memory-forensics`：Volatility 3 离线内存取证到 IOC / behavior / report。
- `vm-analysis`：VM 保护识别、opcode、语义 diff、constraint / SMT / keygen。
- `kb-collaboration`：分析记忆层、规则库、样本/函数知识复用。
- runtime plan：Windows / Linux / macOS / iOS / Android / WASM readiness deep probe 和 opt-in session template。
- supply-chain：SBOM、container、package、installer、firmware provenance graph。
- Android：APK / DEX / manifest / smali / native lib 静态行为图。
- Apple / iOS / macOS：container、signing、entitlements、runtime plan。
- WASM / WASI：imports / exports / capability / risk。
- Firmware / IoT：filesystem、kernel/module、SBOM、Qiling handoff。
- Office：OLE / VBA / macro / XLM / IOC。
- Unpacking / deobfuscation：detect -> plan -> dump -> reconstruct -> re-triage。
- Similarity / binary-diff：family clustering、diff summary、workflow feedback。
- Malware intel：config extract、ATT&CK、IOC、YARA / Sigma feedback loop。

## 执行波次

1. **Capability Backplane**
   - 定义 shared artifact/evidence/workflow recipe/readiness contract。
   - 对高级插件做 gap/risk audit，避免后续能力链各写各的。

2. **Core Intelligence Verticals**
   - 内存取证、VM/符号执行、KB 记忆层、runtime readiness。

3. **Platform And Supply-Chain Ecosystems**
   - 供应链 SBOM、Android、Apple、WASM、firmware/IoT。

4. **Malware Workflow Closure**
   - Office、unpacking、similarity/binary-diff、malware intel/YARA。

5. **Release Guard**
   - 文档、fixture matrix、readiness/discovery/help、contract tests、changelog。

## 关键约束

- 默认 CI 不启动动态 runtime，不执行样本，不访问网络。
- 所有外部工具只能通过 readiness/systemDeps/check 暴露可用性。
- 每条能力链至少要有一个 workflow recipe 和一个 focused unit test。
- 新增 artifacts/evidence 类型必须能被 reporting / visualization / sample profile 消费。
