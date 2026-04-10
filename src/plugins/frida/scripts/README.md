# Frida Scripts Library

预建的 Frida 注入脚本库，用于 Windows 逆向分析中的运行时监控和数据提取。

## 可用脚本

### api_trace.js
**用途**: Windows API 追踪与参数日志

**功能**:
- 追踪常用 Windows API 调用
- 记录函数参数和返回值
- 支持模块过滤

**使用示例**:
```bash
frida -n target.exe -l api_trace.js
```

### string_decoder.js
**用途**: 运行时字符串解密

**功能**:
- 解密运行时动态生成的字符串
- 监控字符串相关的内存操作
- 输出解密的字符串内容

**使用示例**:
```bash
frida -n target.exe -l string_decoder.js
```

### anti_debug_bypass.js
**用途**: 反调试检测中和

**功能**:
- 绕过常见反调试检查
- 修改 `IsDebuggerPresent` 返回值
- 处理时间检测

**使用示例**:
```bash
frida -n target.exe -l anti_debug_bypass.js
```

### crypto_finder.js
**用途**: 加密 API 检测

**功能**:
- 检测加密库调用（AES, RSA, 等）
- 识别加密密钥和参数
- 追踪加密/解密操作

**使用示例**:
```bash
frida -n target.exe -l crypto_finder.js
```

### file_registry_monitor.js
**用途**: 文件/注册表操作追踪

**功能**:
- 监控文件创建、读取、写入操作
- 追踪注册表查询和修改
- 记录持久化相关行为

**使用示例**:
```bash
frida -n target.exe -l file_registry_monitor.js
```

## 自定义脚本

可以通过 `frida.script.inject` MCP 工具注入自定义 Frida 脚本：

```json
{
  "tool": "frida.script.inject",
  "arguments": {
    "sample_id": "sha256:...",
    "script_type": "custom",
    "custom_script_path": "/path/to/script.js",
    "mode": "spawn"
  }
}
```

## 故障排除

详见 [`docs/EXAMPLES.md`](../docs/EXAMPLES.md#frida-故障排除) 中的 Frida 故障排除指南。
