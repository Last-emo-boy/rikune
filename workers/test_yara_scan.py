"""
测试 YARA 规则扫描功能
"""

import pytest
import os
import tempfile
from static_worker import StaticWorker, WorkerRequest, SampleInfo, WorkerContext, PolicyContext, YARA_AVAILABLE


# 如果 YARA 不可用，跳过所有测试
pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA is not available")


class TestYaraScan:
    """测试 YARA 扫描功能"""
    
    @pytest.fixture
    def worker(self):
        """创建 StaticWorker 实例"""
        return StaticWorker()
    
    @pytest.fixture
    def sample_pe_file(self):
        """创建一个简单的 PE 文件用于测试"""
        # 创建一个最小的 PE 文件
        pe_header = (
            b'MZ'  # DOS signature
            + b'\x90' * 58  # DOS stub
            + b'\x00\x00\x00\x00'  # PE offset placeholder
        )
        
        # 添加 DOS stub 消息
        dos_stub = b'This program cannot be run in DOS mode.\r\r\n$'
        pe_header += dos_stub
        
        # 填充到合适的大小
        pe_header += b'\x00' * (128 - len(pe_header))
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            f.write(pe_header)
            temp_path = f.name
        
        yield temp_path
        
        # 清理
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    @pytest.fixture
    def sample_upx_file(self):
        """创建一个包含 UPX 特征的测试文件"""
        # 创建包含 UPX 标记的文件
        upx_data = (
            b'MZ'  # DOS signature
            + b'\x90' * 58
            + b'\x00\x00\x00\x00'
            + b'This program cannot be run in DOS mode.\r\r\n$'
            + b'\x00' * 50
            + b'UPX0'  # UPX marker
            + b'\x00' * 100
            + b'UPX1'  # UPX marker
            + b'\x00' * 100
        )
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            f.write(upx_data)
            temp_path = f.name
        
        yield temp_path
        
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_yara_scan_default_ruleset(self, worker, sample_pe_file):
        """测试使用默认规则集扫描"""
        args = {
            'rule_set': 'default',
            'timeout_ms': 30000
        }
        
        result = worker.yara_scan(sample_pe_file, args)
        
        # 验证返回结构
        assert 'matches' in result
        assert 'ruleset_version' in result
        assert 'timed_out' in result
        assert 'rule_set' in result
        assert 'confidence_summary' in result
        assert 'import_evidence' in result
        
        # 验证规则集名称
        assert result['rule_set'] == 'default'
        
        # 验证未超时
        assert result['timed_out'] is False
        
        # 验证匹配结果
        assert isinstance(result['matches'], list)
        
        # 应该匹配 PE_File 和 Test_Rule
        assert len(result['matches']) >= 1
        
        # 检查匹配的规则
        rule_names = [match['rule'] for match in result['matches']]
        assert 'PE_File' in rule_names or 'Test_Rule' in rule_names
        
        for match in result['matches']:
            assert 'confidence' in match
            assert 'evidence' in match
            assert match['confidence']['level'] in ['low', 'medium', 'high']
            assert isinstance(match['confidence']['score'], float)
    
    def test_yara_scan_packers_ruleset(self, worker, sample_upx_file):
        """测试使用 packers 规则集扫描"""
        args = {
            'rule_set': 'packers',
            'timeout_ms': 30000
        }
        
        result = worker.yara_scan(sample_upx_file, args)
        
        # 验证返回结构
        assert 'matches' in result
        assert result['rule_set'] == 'packers'
        
        # 应该匹配 UPX_Packer 规则
        rule_names = [match['rule'] for match in result['matches']]
        assert 'UPX_Packer' in rule_names
        
        # 验证匹配详情
        upx_match = next(m for m in result['matches'] if m['rule'] == 'UPX_Packer')
        assert 'tags' in upx_match
        assert 'meta' in upx_match
        assert 'strings' in upx_match
        assert 'confidence' in upx_match
        assert 'evidence' in upx_match
        
        # 验证元数据
        assert 'description' in upx_match['meta']
        assert 'author' in upx_match['meta']
    
    def test_yara_scan_malware_families_ruleset(self, worker, sample_pe_file):
        """测试使用 malware_families 规则集扫描"""
        args = {
            'rule_set': 'malware_families',
            'timeout_ms': 30000
        }
        
        result = worker.yara_scan(sample_pe_file, args)
        
        # 验证返回结构
        assert 'matches' in result
        assert result['rule_set'] == 'malware_families'
        
        # 简单的 PE 文件可能不匹配任何恶意软件规则
        assert isinstance(result['matches'], list)
    
    def test_yara_scan_nonexistent_ruleset(self, worker, sample_pe_file):
        """测试使用不存在的规则集"""
        args = {
            'rule_set': 'nonexistent_ruleset',
            'timeout_ms': 30000
        }
        
        with pytest.raises(RuntimeError) as exc_info:
            worker.yara_scan(sample_pe_file, args)
        
        assert "not found" in str(exc_info.value)
    
    def test_yara_scan_timeout(self, worker, sample_pe_file):
        """测试超时控制"""
        # 使用非常短的超时时间
        args = {
            'rule_set': 'default',
            'timeout_ms': 1  # 1 毫秒，几乎肯定会超时
        }
        
        result = worker.yara_scan(sample_pe_file, args)
        
        # 即使超时，也应该返回结果
        assert 'matches' in result
        assert 'timed_out' in result
        
        # 可能超时（取决于系统性能）
        # 如果超时，matches 可能为空或包含部分结果
        assert isinstance(result['matches'], list)
    
    def test_yara_scan_match_strings(self, worker, sample_upx_file):
        """测试匹配字符串的提取"""
        args = {
            'rule_set': 'packers',
            'timeout_ms': 30000
        }
        
        result = worker.yara_scan(sample_upx_file, args)
        
        # 找到 UPX 匹配
        upx_matches = [m for m in result['matches'] if m['rule'] == 'UPX_Packer']
        
        if upx_matches:
            upx_match = upx_matches[0]
            
            # 验证字符串匹配
            assert 'strings' in upx_match
            assert isinstance(upx_match['strings'], list)
            
            # 应该有匹配的字符串
            if upx_match['strings']:
                string_match = upx_match['strings'][0]
                assert 'identifier' in string_match
                assert 'offset' in string_match
                assert 'matched_data' in string_match
    
    def test_yara_scan_ruleset_version(self, worker, sample_pe_file):
        """测试规则集版本记录"""
        args = {
            'rule_set': 'default',
            'timeout_ms': 30000
        }
        
        result1 = worker.yara_scan(sample_pe_file, args)
        result2 = worker.yara_scan(sample_pe_file, args)
        
        # 相同的规则集应该有相同的版本
        assert result1['ruleset_version'] == result2['ruleset_version']
        
        # 版本应该是非空字符串
        assert isinstance(result1['ruleset_version'], str)
        assert len(result1['ruleset_version']) > 0
    
    def test_yara_scan_via_execute(self, worker, sample_pe_file):
        """测试通过 execute 方法调用 YARA 扫描"""
        request = WorkerRequest(
            job_id="test_job_001",
            tool="yara.scan",
            sample=SampleInfo(
                sample_id="sha256:test123",
                path=sample_pe_file
            ),
            args={
                'rule_set': 'default',
                'timeout_ms': 30000
            },
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"yara": "4.3.1"}
            )
        )
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert response.job_id == "test_job_001"
        assert response.data is not None
        
        # 验证数据结构
        assert 'matches' in response.data
        assert 'ruleset_version' in response.data
        assert 'timed_out' in response.data


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
