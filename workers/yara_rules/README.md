# YARA 规则集

本目录包含用于样本扫描的 YARA 规则集。

## 规则集列表

### default.yar
基本的测试规则集，包含：
- `Test_Rule`: 检测 DOS stub 消息
- `PE_File`: 检测 PE 文件格式

### packers.yar
加壳器和保护器检测规则集，包含：
- `UPX_Packer`: 检测 UPX 加壳器
- `Themida_Packer`: 检测 Themida/WinLicense
- `VMProtect_Packer`: 检测 VMProtect
- `ASPack_Packer`: 检测 ASPack
- `PECompact_Packer`: 检测 PECompact

### malware_families.yar
恶意软件家族检测规则集，包含：
- `Generic_Trojan`: 通用木马检测（基于进程注入 API）
- `Suspicious_Network_Activity`: 可疑网络活动
- `Keylogger_Indicators`: 键盘记录器指标
- `Ransomware_Indicators`: 勒索软件指标
- `Persistence_Mechanism`: 持久化机制

## 使用方法

在调用 `yara.scan` 工具时，通过 `rule_set` 参数指定规则集名称（不含 .yar 扩展名）：

```python
args = {
    'rule_set': 'packers',  # 使用 packers.yar
    'timeout_ms': 30000
}
result = worker.yara_scan(sample_path, args)
```

## 添加自定义规则

1. 在本目录创建新的 `.yar` 文件
2. 编写符合 YARA 语法的规则
3. 使用文件名（不含扩展名）作为 rule_set 参数

**规则模板：**
```yara
rule Rule_Name
{
    meta:
        description = "规则描述"
        author = "作者名称"
        date = "2024-01-01"
        severity = "high|medium|low"
        
    strings:
        $string1 = "pattern" ascii
        $string2 = { 6A 40 68 00 30 00 00 }
        
    condition:
        uint16(0) == 0x5A4D and any of ($string*)
}
```

## 规则编写指南

### 元数据字段

推荐在规则中包含以下元数据：
- `description`: 规则描述
- `author`: 作者名称
- `date`: 创建日期
- `severity`: 严重程度（critical, high, medium, low）
- `reference`: 参考链接

### 字符串模式

- ASCII 字符串：`$str = "text" ascii`
- 宽字符串：`$str = "text" wide`
- 十六进制模式：`$hex = { 6A 40 68 ?? ?? ?? ?? }`
- 正则表达式：`$regex = /pattern/`

### 条件表达式

- PE 文件检测：`uint16(0) == 0x5A4D`
- 字符串匹配：`$string1 or $string2`
- 数量条件：`#string1 > 5`
- 位置条件：`$string1 at 0x1000`

## 规则测试

使用 YARA 命令行工具测试规则：

```bash
# 测试单个规则文件
yara default.yar /path/to/sample.exe

# 测试所有规则
yara -r . /path/to/sample.exe
```

## 规则来源

本目录的规则是为测试和演示目的创建的简化版本。在生产环境中，建议使用：

- [YARA-Rules](https://github.com/Yara-Rules/rules): 社区维护的规则集
- [Awesome YARA](https://github.com/InQuest/awesome-yara): YARA 资源列表
- [VirusTotal YARA](https://github.com/VirusTotal/yara): 官方规则示例

## 注意事项

1. **性能**: 规则数量和复杂度会影响扫描性能
2. **误报**: 简单的规则可能产生误报，需要仔细调整
3. **更新**: 定期更新规则以检测新的威胁
4. **版权**: 使用第三方规则时注意版权和许可证

## 参考资料

- [YARA 官方文档](https://yara.readthedocs.io/)
- [YARA 规则编写指南](https://yara.readthedocs.io/en/stable/writingrules.html)
- [YARA 模块文档](https://yara.readthedocs.io/en/stable/modules.html)
