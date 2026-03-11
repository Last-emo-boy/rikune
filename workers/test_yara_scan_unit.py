"""
YARA 扫描功能的单元测试（不需要 YARA 库）
"""

import pytest
import os
from static_worker import StaticWorker, YARA_AVAILABLE


class TestYaraScanUnit:
    """测试 YARA 扫描功能的基本单元测试"""
    
    @pytest.fixture
    def worker(self):
        """创建 StaticWorker 实例"""
        return StaticWorker()
    
    def test_yara_availability_flag(self):
        """测试 YARA 可用性标志"""
        # YARA_AVAILABLE 应该是布尔值
        assert isinstance(YARA_AVAILABLE, bool)
    
    def test_yara_scan_in_tool_handlers(self, worker):
        """测试 yara.scan 是否在工具处理器中注册"""
        assert 'yara.scan' in worker.tool_handlers
        assert callable(worker.tool_handlers['yara.scan'])
    
    def test_yara_scan_method_exists(self, worker):
        """测试 yara_scan 方法是否存在"""
        assert hasattr(worker, 'yara_scan')
        assert callable(worker.yara_scan)
    
    def test_yara_rules_directory_structure(self):
        """测试 YARA 规则目录结构"""
        # 检查 yara_rules 目录是否存在
        rules_dir = os.path.join(os.path.dirname(__file__), 'yara_rules')
        assert os.path.exists(rules_dir), "yara_rules directory should exist"
        assert os.path.isdir(rules_dir), "yara_rules should be a directory"
        
        # 检查规则文件是否存在
        expected_rulesets = ['default.yar', 'packers.yar', 'malware_families.yar']
        for ruleset in expected_rulesets:
            rule_file = os.path.join(rules_dir, ruleset)
            assert os.path.exists(rule_file), f"{ruleset} should exist"
            assert os.path.isfile(rule_file), f"{ruleset} should be a file"
    
    def test_yara_rules_content(self):
        """测试 YARA 规则文件内容"""
        rules_dir = os.path.join(os.path.dirname(__file__), 'yara_rules')
        
        # 检查 default.yar
        default_rule = os.path.join(rules_dir, 'default.yar')
        with open(default_rule, 'r', encoding='utf-8') as f:
            content = f.read()
            assert 'rule' in content.lower()
            assert 'PE_File' in content or 'Test_Rule' in content
        
        # 检查 packers.yar
        packers_rule = os.path.join(rules_dir, 'packers.yar')
        with open(packers_rule, 'r', encoding='utf-8') as f:
            content = f.read()
            assert 'UPX_Packer' in content
            assert 'Themida_Packer' in content or 'VMProtect_Packer' in content
        
        # 检查 malware_families.yar
        malware_rule = os.path.join(rules_dir, 'malware_families.yar')
        with open(malware_rule, 'r', encoding='utf-8') as f:
            content = f.read()
            assert 'rule' in content.lower()
    
    @pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA is not available")
    def test_yara_scan_requires_rule_set(self, worker):
        """测试 yara_scan 需要 rule_set 参数"""
        import tempfile
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 100)
            temp_path = f.name
        
        try:
            # 测试缺少 rule_set 参数
            args = {'timeout_ms': 30000}
            result = worker.yara_scan(temp_path, args)
            
            # 应该使用默认规则集
            assert 'rule_set' in result
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    @pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA is not available")
    def test_yara_scan_nonexistent_ruleset_error(self, worker):
        """测试不存在的规则集应该抛出错误"""
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * 100)
            temp_path = f.name
        
        try:
            args = {
                'rule_set': 'nonexistent_ruleset_12345',
                'timeout_ms': 30000
            }
            
            with pytest.raises(RuntimeError) as exc_info:
                worker.yara_scan(temp_path, args)
            
            assert "not found" in str(exc_info.value).lower()
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def test_get_ruleset_version_method(self, worker):
        """测试 _get_ruleset_version 方法"""
        assert hasattr(worker, '_get_ruleset_version')
        assert callable(worker._get_ruleset_version)
        
        # 测试使用实际的规则文件
        rules_dir = os.path.join(os.path.dirname(__file__), 'yara_rules')
        rule_file = os.path.join(rules_dir, 'default.yar')
        
        if os.path.exists(rule_file):
            version = worker._get_ruleset_version(rule_file)
            
            # 版本应该是字符串
            assert isinstance(version, str)
            assert len(version) > 0
            
            # 相同文件应该返回相同版本
            version2 = worker._get_ruleset_version(rule_file)
            assert version == version2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
