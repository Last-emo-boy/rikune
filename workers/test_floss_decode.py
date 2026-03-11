"""
测试 FLOSS 字符串解码功能

测试策略：
1. 测试 FLOSS 工具集成
2. 测试超时控制
3. 测试部分结果处理
4. 测试不同解码模式
"""

import pytest
import json
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
from static_worker import StaticWorker, WorkerRequest, SampleInfo, WorkerContext, PolicyContext


# Mock shutil.which at module level for all tests
@pytest.fixture(autouse=True)
def mock_floss_available():
    """自动 mock FLOSS 工具可用性"""
    with patch('shutil.which', return_value='/usr/bin/floss'):
        yield


class TestFlossDecoding:
    """测试 FLOSS 字符串解码"""
    
    @pytest.fixture
    def worker(self):
        """创建 StaticWorker 实例"""
        return StaticWorker()
    
    @pytest.fixture
    def sample_file(self):
        """创建测试样本文件"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.exe') as f:
            # 写入一些测试数据
            f.write(b'MZ\x90\x00' + b'\x00' * 100)
            temp_path = f.name
        
        yield temp_path
        
        # 清理
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_floss_decode_basic(self, worker, sample_file):
        """测试基本的 FLOSS 解码功能"""
        # Mock subprocess.run
        mock_output = {
            "strings": {
                "decoded_strings": [
                    {
                        "string": "http://malware.com",
                        "offset": 0x1000,
                        "decoding_routine": "decode_xor"
                    },
                    {
                        "string": "C:\\Windows\\System32\\cmd.exe",
                        "offset": 0x2000,
                        "decoding_routine": "decode_base64"
                    }
                ]
            }
        }
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=json.dumps(mock_output),
                stderr=""
            )
            
            result = worker.floss_decode(sample_file, {})
            
            # 验证结果
            assert result['count'] == 2
            assert result['timeout_occurred'] is False
            assert result['partial_results'] is False
            assert len(result['decoded_strings']) == 2
            
            # 验证第一个字符串
            first_string = result['decoded_strings'][0]
            assert first_string['string'] == "http://malware.com"
            assert first_string['offset'] == 0x1000
            assert first_string['type'] == "decoded"
            assert first_string['decoding_method'] == "decode_xor"
            
            # 验证第二个字符串
            second_string = result['decoded_strings'][1]
            assert second_string['string'] == "C:\\Windows\\System32\\cmd.exe"
            assert second_string['offset'] == 0x2000
            assert second_string['type'] == "decoded"
            assert second_string['decoding_method'] == "decode_base64"
    
    def test_floss_decode_with_timeout(self, worker, sample_file):
        """测试 FLOSS 解码超时控制"""
        import subprocess
        
        with patch('subprocess.run') as mock_run:
            # 模拟超时
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=['floss'],
                timeout=60
            )
            
            with patch('subprocess.Popen') as mock_popen:
                # 模拟部分结果
                mock_process = Mock()
                mock_process.communicate.side_effect = subprocess.TimeoutExpired(
                    cmd=['floss'],
                    timeout=60
                )
                mock_process.kill.return_value = None
                
                # 第二次 communicate 返回部分输出
                partial_output = {
                    "strings": {
                        "decoded_strings": [
                            {
                                "string": "partial_result",
                                "offset": 0x1000,
                                "decoding_routine": "decode_xor"
                            }
                        ]
                    }
                }
                mock_process.communicate.return_value = (json.dumps(partial_output), "")
                mock_popen.return_value = mock_process
                
                result = worker.floss_decode(sample_file, {'timeout': 60})
                
                # 验证超时标志
                assert result['timeout_occurred'] is True
                assert result['partial_results'] is True
    
    def test_floss_decode_multiple_modes(self, worker, sample_file):
        """测试多种解码模式"""
        mock_output = {
            "strings": {
                "static_strings": [
                    {"string": "static_str", "offset": 0x100}
                ],
                "stack_strings": [
                    {"string": "stack_str", "offset": 0x200, "function": "sub_401000"}
                ],
                "tight_strings": [
                    {"string": "tight_str", "offset": 0x300, "function": "sub_402000"}
                ],
                "decoded_strings": [
                    {"string": "decoded_str", "offset": 0x400, "decoding_routine": "xor"}
                ]
            }
        }
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=json.dumps(mock_output),
                stderr=""
            )
            
            result = worker.floss_decode(
                sample_file,
                {'modes': ['static', 'stack', 'tight', 'decoded']}
            )
            
            # 验证所有模式的字符串都被提取
            assert result['count'] == 4
            
            # 验证每种类型
            types = [s['type'] for s in result['decoded_strings']]
            assert 'static' in types
            assert 'stack' in types
            assert 'tight' in types
            assert 'decoded' in types
    
    def test_floss_decode_custom_timeout(self, worker, sample_file):
        """测试自定义超时时间"""
        mock_output = {
            "strings": {
                "decoded_strings": []
            }
        }
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=json.dumps(mock_output),
                stderr=""
            )
            
            result = worker.floss_decode(sample_file, {'timeout': 30})
            
            # 验证 subprocess.run 被调用时使用了正确的超时
            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs['timeout'] == 30
    
    def test_floss_decode_invalid_timeout(self, worker, sample_file):
        """测试无效的超时参数"""
        with pytest.raises(ValueError, match="timeout must be at least 1 second"):
            worker.floss_decode(sample_file, {'timeout': 0})
    
    def test_floss_decode_invalid_mode(self, worker, sample_file):
        """测试无效的解码模式"""
        with pytest.raises(ValueError, match="Invalid mode"):
            worker.floss_decode(sample_file, {'modes': ['invalid_mode']})
    
    def test_floss_decode_tool_not_found(self, worker, sample_file):
        """测试 FLOSS 工具未安装"""
        # Override the autouse fixture for this specific test
        with patch('shutil.which', return_value=None):
            with pytest.raises(Exception, match="FLOSS tool not found"):
                worker.floss_decode(sample_file, {})
    
    def test_floss_decode_json_parse_error(self, worker, sample_file):
        """测试 JSON 解析错误"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="invalid json",
                stderr=""
            )
            
            with pytest.raises(Exception, match="Failed to parse FLOSS JSON output"):
                worker.floss_decode(sample_file, {})
    
    def test_floss_decode_partial_results_on_error(self, worker, sample_file):
        """测试错误时的部分结果处理"""
        mock_output = {
            "strings": {
                "decoded_strings": [
                    {"string": "partial", "offset": 0x1000, "decoding_routine": "xor"}
                ]
            }
        }
        
        with patch('subprocess.run') as mock_run:
            # 返回非零退出码但有输出
            mock_run.return_value = Mock(
                returncode=1,
                stdout=json.dumps(mock_output),
                stderr="Some error occurred"
            )
            
            result = worker.floss_decode(sample_file, {})
            
            # 应该返回部分结果
            assert result['partial_results'] is True
            assert result['count'] == 1
            assert result['decoded_strings'][0]['string'] == "partial"
    
    def test_floss_decode_empty_output(self, worker, sample_file):
        """测试空输出"""
        mock_output = {
            "strings": {
                "decoded_strings": []
            }
        }
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=json.dumps(mock_output),
                stderr=""
            )
            
            result = worker.floss_decode(sample_file, {})
            
            assert result['count'] == 0
            assert result['decoded_strings'] == []
            assert result['timeout_occurred'] is False
            assert result['partial_results'] is False
    
    def test_floss_decode_default_mode(self, worker, sample_file):
        """测试默认解码模式（仅 decoded）"""
        mock_output = {
            "strings": {
                "static_strings": [
                    {"string": "static_str", "offset": 0x100}
                ],
                "decoded_strings": [
                    {"string": "decoded_str", "offset": 0x400, "decoding_routine": "xor"}
                ]
            }
        }
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=json.dumps(mock_output),
                stderr=""
            )
            
            # 不指定 modes，应该只返回 decoded
            result = worker.floss_decode(sample_file, {})
            
            assert result['count'] == 1
            assert result['decoded_strings'][0]['type'] == 'decoded'
            assert result['decoded_strings'][0]['string'] == 'decoded_str'


class TestFlossIntegration:
    """集成测试 - 通过 Worker 执行"""
    
    @pytest.fixture
    def worker(self):
        """创建 StaticWorker 实例"""
        return StaticWorker()
    
    @pytest.fixture
    def sample_file(self):
        """创建测试样本文件"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.exe') as f:
            f.write(b'MZ\x90\x00' + b'\x00' * 100)
            temp_path = f.name
        
        yield temp_path
        
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    def test_execute_floss_decode(self, worker, sample_file):
        """测试通过 execute 方法调用 FLOSS 解码"""
        mock_output = {
            "strings": {
                "decoded_strings": [
                    {"string": "test", "offset": 0x1000, "decoding_routine": "xor"}
                ]
            }
        }
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=json.dumps(mock_output),
                stderr=""
            )
            
            request = WorkerRequest(
                job_id="test-job-1",
                tool="strings.floss.decode",
                sample=SampleInfo(
                    sample_id="sha256:test",
                    path=sample_file
                ),
                args={'timeout': 60},
                context=WorkerContext(
                    request_time_utc="2024-01-01T00:00:00Z",
                    policy=PolicyContext(
                        allow_dynamic=False,
                        allow_network=False
                    ),
                    versions={"floss": "3.0.0"}
                )
            )
            
            response = worker.execute(request)
            
            assert response.ok is True
            assert response.job_id == "test-job-1"
            assert len(response.errors) == 0
            assert response.data['count'] == 1
            assert response.data['decoded_strings'][0]['string'] == "test"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
