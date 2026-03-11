# 使用示例

本文档提供 Windows EXE Decompiler MCP Server 的实际使用案例和最佳实践。

## 目录

- [场景 1: 快速威胁评估](#场景-1-快速威胁评估)
- [场景 2: 恶意软件家族识别](#场景-2-恶意软件家族识别)
- [场景 3: 加壳器检测与分析](#场景-3-加壳器检测与分析)
- [场景 4: .NET 程序初步分析](#场景-4-net-程序初步分析)
- [场景 5: IOC 提取](#场景-5-ioc-提取)
- [场景 6: 批量样本筛选](#场景-6-批量样本筛选)
- [场景 7: 导入表分析](#场景-7-导入表分析)
- [场景 8: 字符串分析](#场景-8-字符串分析)

## 场景 1: 快速威胁评估

**目标**: 在 5 分钟内评估未知样本的威胁等级

### 步骤 1: 摄入样本

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/tmp/suspicious.exe",
    "filename": "email_attachment.exe",
    "source": "phishing_email"
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "sample_id": "sha256:a1b2c3d4e5f6...",
    "size": 245760,
    "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows"
  }
}
```

### 步骤 2: 执行快速画像

```json
{
  "tool": "workflow.triage",
  "arguments": {
    "sample_id": "sha256:a1b2c3d4e5f6..."
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "summary": "高风险样本：检测到 Emotet 恶意软件特征，使用 UPX 加壳",
    "confidence": 0.92,
    "threat_level": "critical",
    "iocs": {
      "suspicious_imports": [
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory"
      ],
      "suspicious_strings": [
        "http://malicious-c2.com/gate.php",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
      ],
      "yara_matches": [
        "Emotet_Variant_2023",
        "UPX_Packer"
      ],
      "network_indicators": [
        "malicious-c2.com",
        "185.220.101.45"
      ]
    },
    "evidence": [
      "YARA 规则匹配 Emotet 恶意软件家族",
      "导入表包含进程注入相关 API",
      "字符串中发现 C2 服务器地址",
      "检测到 UPX 加壳器",
      "入口点位于非标准节区"
    ],
    "recommendation": "强烈建议在隔离环境进行深度分析，不要在生产环境执行"
  }
}
```

### 分析结论

- **威胁等级**: Critical（严重）
- **恶意软件家族**: Emotet
- **加壳器**: UPX
- **主要行为**: 进程注入、持久化、C2 通信
- **建议**: 立即隔离，进行深度分析

---

## 场景 2: 恶意软件家族识别

**目标**: 识别样本所属的恶意软件家族

### 步骤 1: 摄入样本

```json
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/samples/ransomware.exe"
  }
}
```

### 步骤 2: YARA 扫描

```json
{
  "tool": "yara.scan",
  "arguments": {
    "sample_id": "sha256:b2c3d4e5f6g7...",
    "rule_set": "malware_families"
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "matches": [
      {
        "rule": "WannaCry_Ransomware",
        "tags": ["ransomware", "wannacry", "cryptor"],
        "meta": {
          "description": "WannaCry ransomware variant",
          "author": "Security Researcher",
          "date": "2023-05-15",
          "family": "WannaCry"
        },
        "strings": [
          {
            "offset": 12345,
            "identifier": "$str1",
            "data": "tasksche.exe"
          },
          {
            "offset": 23456,
            "identifier": "$str2",
            "data": ".WNCRY"
          }
        ]
      }
    ],
    "ruleset_version": "2024.01"
  }
}
```

### 步骤 3: 提取 IOC

```json
{
  "tool": "strings.extract",
  "arguments": {
    "sample_id": "sha256:b2c3d4e5f6g7...",
    "min_len": 8
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "strings": [
      {"value": "tasksche.exe", "offset": 12345, "encoding": "ascii"},
      {"value": ".WNCRY", "offset": 23456, "encoding": "ascii"},
      {"value": "msg/m_bulgarian.wnry", "offset": 34567, "encoding": "ascii"},
      {"value": "Ooops, your files have been encrypted!", "offset": 45678, "encoding": "ascii"}
    ],
    "count": 1247
  }
}
```

### 分析结论

- **恶意软件家族**: WannaCry Ransomware
- **特征字符串**: `tasksche.exe`, `.WNCRY`, 勒索信息
- **行为**: 文件加密、勒索
- **建议**: 隔离受感染系统，不要支付赎金

---

## 场景 3: 加壳器检测与分析

**目标**: 检测样本是否加壳，识别加壳器类型

### 步骤 1: 加壳器检测

```json
{
  "tool": "packer.detect",
  "arguments": {
    "sample_id": "sha256:c3d4e5f6g7h8..."
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "is_packed": true,
    "packers": [
      {
        "name": "Themida",
        "confidence": 0.95,
        "method": "yara"
      },
      {
        "name": "VMProtect",
        "confidence": 0.65,
        "method": "entropy"
      }
    ],
    "entropy": {
      "average": 7.2,
      "max": 7.8,
      "suspicious_sections": [
        {
          "name": ".vmp0",
          "entropy": 7.8
        },
        {
          "name": ".vmp1",
          "entropy": 7.6
        }
      ]
    },
    "entry_point": {
      "section": ".vmp0",
      "is_suspicious": true
    }
  }
}
```

### 步骤 2: PE 指纹分析

```json
{
  "tool": "pe.fingerprint",
  "arguments": {
    "sample_id": "sha256:c3d4e5f6g7h8...",
    "fast": false
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "sections": [
      {
        "name": ".text",
        "virtual_size": 102400,
        "raw_size": 102400,
        "entropy": 6.2
      },
      {
        "name": ".vmp0",
        "virtual_size": 524288,
        "raw_size": 524288,
        "entropy": 7.8
      },
      {
        "name": ".vmp1",
        "virtual_size": 262144,
        "raw_size": 262144,
        "entropy": 7.6
      }
    ]
  }
}
```

### 分析结论

- **加壳器**: Themida（高置信度）+ VMProtect（中等置信度）
- **特征**: 
  - 节区名称异常（`.vmp0`, `.vmp1`）
  - 高熵值（7.6-7.8）
  - 入口点在非标准节区
- **建议**: 需要脱壳后才能进行深度分析

---

## 场景 4: .NET 程序初步分析

**目标**: 快速识别 .NET 程序并提取基础信息

### 步骤 1: 运行时检测

```json
{
  "tool": "runtime.detect",
  "arguments": {
    "sample_id": "sha256:d4e5f6g7h8i9..."
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "is_dotnet": true,
    "dotnet_version": "v4.0.30319",
    "target_framework": ".NETFramework,Version=v4.5",
    "suspected": [
      {
        "runtime": "dotnet",
        "confidence": 1.0,
        "evidence": [
          "CLR header present",
          "mscoree.dll imported",
          ".NET metadata found"
        ]
      }
    ]
  }
}
```

### 步骤 2: 导入表分析

```json
{
  "tool": "pe.imports.extract",
  "arguments": {
    "sample_id": "sha256:d4e5f6g7h8i9...",
    "group_by_dll": true
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "mscoree.dll": ["_CorExeMain"],
    "kernel32.dll": ["GetProcAddress", "LoadLibraryA"]
  }
}
```

### 步骤 3: 字符串提取

```json
{
  "tool": "strings.extract",
  "arguments": {
    "sample_id": "sha256:d4e5f6g7h8i9...",
    "min_len": 10
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "strings": [
      {"value": "System.Windows.Forms", "encoding": "utf-16le"},
      {"value": "System.Net.Http", "encoding": "utf-16le"},
      {"value": "MyNamespace.MainForm", "encoding": "utf-16le"},
      {"value": "http://api.example.com/data", "encoding": "ascii"}
    ]
  }
}
```

### 分析结论

- **运行时**: .NET Framework 4.5
- **程序类型**: Windows Forms 应用
- **依赖**: System.Windows.Forms, System.Net.Http
- **网络活动**: 可能连接到 `api.example.com`
- **建议**: 使用 V0.3 的 .NET 专项工具进行深度分析

---

## 场景 5: IOC 提取

**目标**: 从样本中提取 IOC（Indicators of Compromise）

### 完整工作流

```json
// 1. 摄入样本
{
  "tool": "sample.ingest",
  "arguments": {
    "path": "/samples/trojan.exe"
  }
}

// 2. 执行快速画像
{
  "tool": "workflow.triage",
  "arguments": {
    "sample_id": "sha256:e5f6g7h8i9j0..."
  }
}
```

### 提取的 IOC

**响应**（IOC 部分）:
```json
{
  "iocs": {
    "suspicious_imports": [
      "InternetOpenA",
      "InternetConnectA",
      "HttpSendRequestA",
      "CreateProcessA",
      "RegSetValueExA"
    ],
    "suspicious_strings": [
      "http://185.220.101.45/update.php",
      "http://malware-c2.onion/gate",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "cmd.exe /c powershell -enc ...",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    ],
    "yara_matches": [
      "Generic_Trojan_Downloader",
      "Suspicious_Network_Activity"
    ],
    "network_indicators": [
      "185.220.101.45",
      "malware-c2.onion",
      "update.php",
      "gate"
    ]
  }
}
```

### IOC 分类

**网络 IOC**:
- IP: `185.220.101.45`
- 域名: `malware-c2.onion`
- URL: `http://185.220.101.45/update.php`

**文件系统 IOC**:
- 注册表键: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- 命令: `cmd.exe /c powershell -enc ...`

**行为 IOC**:
- 网络通信（HTTP）
- 进程创建
- 注册表修改（持久化）

---

## 场景 6: 批量样本筛选

**目标**: 快速筛选大量样本，识别高风险样本

### 批量摄入

```typescript
const samples = [
  "/samples/sample1.exe",
  "/samples/sample2.exe",
  "/samples/sample3.exe",
  // ... 100 个样本
]

// 并发摄入
const ingestResults = await Promise.all(
  samples.map(path => 
    callTool("sample.ingest", {path})
  )
)

const sampleIds = ingestResults.map(r => r.data.sample_id)
```

### 批量快速扫描

```typescript
// 仅使用 YARA 扫描进行快速筛选
const yaraResults = await Promise.all(
  sampleIds.map(id =>
    callTool("yara.scan", {
      sample_id: id,
      rule_set: "malware_families"
    })
  )
)

// 筛选出有匹配的样本
const maliciousSamples = yaraResults
  .filter(r => r.ok && r.data.matches.length > 0)
  .map((r, i) => ({
    sample_id: sampleIds[i],
    matches: r.data.matches.map(m => m.rule)
  }))

console.log(`发现 ${maliciousSamples.length} 个恶意样本`)
```

### 对高风险样本进行深度分析

```typescript
// 对匹配恶意家族规则的样本进行完整画像
const triageResults = await Promise.all(
  maliciousSamples.map(s =>
    callTool("workflow.triage", {
      sample_id: s.sample_id
    })
  )
)

// 生成汇总报告
const summary = triageResults.map((r, i) => ({
  sample_id: maliciousSamples[i].sample_id,
  threat_level: r.data.threat_level,
  family: r.data.yara_matches[0],
  iocs: r.data.iocs
}))
```

### 输出示例

```json
[
  {
    "sample_id": "sha256:abc123...",
    "threat_level": "critical",
    "family": "Emotet_Variant_2023",
    "iocs": {
      "network_indicators": ["malicious-c2.com"]
    }
  },
  {
    "sample_id": "sha256:def456...",
    "threat_level": "high",
    "family": "TrickBot_Loader",
    "iocs": {
      "network_indicators": ["185.220.101.45"]
    }
  }
]
```

---

## 场景 7: 导入表分析

**目标**: 分析程序的功能依赖和可疑 API 调用

### 提取导入表

```json
{
  "tool": "pe.imports.extract",
  "arguments": {
    "sample_id": "sha256:f6g7h8i9j0k1...",
    "group_by_dll": true
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "kernel32.dll": [
      "CreateFileA",
      "ReadFile",
      "WriteFile",
      "CreateProcessA",
      "VirtualAlloc",
      "VirtualProtect"
    ],
    "advapi32.dll": [
      "RegOpenKeyExA",
      "RegSetValueExA",
      "RegCloseKey"
    ],
    "ws2_32.dll": [
      "WSAStartup",
      "socket",
      "connect",
      "send",
      "recv"
    ],
    "user32.dll": [
      "MessageBoxA",
      "FindWindowA"
    ]
  }
}
```

### 可疑 API 分析

**文件操作**:
- `CreateFileA`, `ReadFile`, `WriteFile` - 文件读写

**进程操作**:
- `CreateProcessA` - 创建新进程（可能执行其他程序）
- `VirtualAlloc`, `VirtualProtect` - 内存分配和保护修改（可能用于代码注入）

**注册表操作**:
- `RegOpenKeyExA`, `RegSetValueExA` - 注册表修改（可能用于持久化）

**网络操作**:
- `WSAStartup`, `socket`, `connect`, `send`, `recv` - 网络通信

### 威胁评估

基于导入表，该样本可能具有以下行为:
1. 文件读写
2. 进程创建/注入
3. 注册表持久化
4. 网络通信

**风险等级**: High（高）

---

## 场景 8: 字符串分析

**目标**: 从字符串中发现敏感信息和行为线索

### 步骤 1: 提取基础字符串

```json
{
  "tool": "strings.extract",
  "arguments": {
    "sample_id": "sha256:g7h8i9j0k1l2...",
    "min_len": 6,
    "encoding": "all"
  }
}
```

**响应**（部分）:
```json
{
  "ok": true,
  "data": {
    "strings": [
      {"value": "http://malicious.com/payload.exe", "encoding": "ascii"},
      {"value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "encoding": "ascii"},
      {"value": "cmd.exe /c del /f /q %s", "encoding": "ascii"},
      {"value": "Mozilla/5.0 (Windows NT 10.0)", "encoding": "ascii"},
      {"value": "admin:password123", "encoding": "ascii"}
    ]
  }
}
```

### 步骤 2: FLOSS 解码（如果字符串较少）

```json
{
  "tool": "strings.floss.decode",
  "arguments": {
    "sample_id": "sha256:g7h8i9j0k1l2...",
    "timeout_sec": 60
  }
}
```

**响应**:
```json
{
  "ok": true,
  "data": {
    "decoded_strings": [
      {
        "value": "http://hidden-c2.com/gate.php",
        "method": "stack",
        "address": "0x401234"
      },
      {
        "value": "SecretKey123!@#",
        "method": "tight",
        "address": "0x402345"
      }
    ],
    "stack_strings": [
      {"value": "http://hidden-c2.com/gate.php", "address": "0x401234"}
    ]
  }
}
```

### 字符串分类

**网络相关**:
- `http://malicious.com/payload.exe` - 下载地址
- `http://hidden-c2.com/gate.php` - C2 服务器
- `Mozilla/5.0 (Windows NT 10.0)` - User-Agent

**持久化相关**:
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` - 自启动注册表键

**命令执行**:
- `cmd.exe /c del /f /q %s` - 删除文件命令

**凭据**:
- `admin:password123` - 硬编码凭据
- `SecretKey123!@#` - 加密密钥

### 威胁评估

- **网络活动**: 下载 payload，连接 C2 服务器
- **持久化**: 注册表自启动
- **反取证**: 删除文件
- **凭据泄露**: 硬编码凭据

**风险等级**: Critical（严重）

---

## 最佳实践

### 1. 分层分析策略

```
第一层（快速筛选）: YARA 扫描
    ↓ 匹配恶意规则
第二层（基础画像）: workflow.triage
    ↓ 威胁等级 High/Critical
第三层（深度分析）: 详细工具分析
```

### 2. 缓存利用

```typescript
// 第一次分析
const result1 = await callTool("pe.fingerprint", {sample_id: id})
// 耗时: 0.5s

// 第二次查询（缓存命中）
const result2 = await callTool("pe.fingerprint", {sample_id: id})
// 耗时: < 0.01s
```

### 3. 错误处理

```typescript
async function analyzeWithRetry(sampleId) {
  try {
    return await callTool("workflow.triage", {sample_id: sampleId})
  } catch (error) {
    if (error.code === "E_TIMEOUT") {
      // 超时重试
      return await callTool("workflow.triage", {
        sample_id: sampleId,
        timeout_ms: 600000  // 增加超时时间
      })
    }
    throw error
  }
}
```

### 4. 结果聚合

```typescript
async function comprehensiveAnalysis(sampleId) {
  const [fingerprint, imports, strings, yara, packer] = await Promise.all([
    callTool("pe.fingerprint", {sample_id: sampleId}),
    callTool("pe.imports.extract", {sample_id: sampleId}),
    callTool("strings.extract", {sample_id: sampleId}),
    callTool("yara.scan", {sample_id: sampleId, rule_set: "all"}),
    callTool("packer.detect", {sample_id: sampleId})
  ])
  
  return {
    fingerprint: fingerprint.data,
    imports: imports.data,
    strings: strings.data,
    yara: yara.data,
    packer: packer.data
  }
}
```

## 下一步

- 查看 [使用指南](USAGE.md) 了解工具详细说明
- 查看 [常见问题](FAQ.md) 解决常见问题
- 查看 [README.md](../README.md) 了解安装和配置
