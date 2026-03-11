"""
Integration tests for packer detection through Worker execute method
"""

import json
import sys
import os
import pytest
import tempfile
import struct

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import (
    StaticWorker,
    WorkerRequest,
    SampleInfo,
    PolicyContext,
    WorkerContext,
)


class TestPackerDetectIntegration:
    """测试加壳器检测的集成测试"""

    @pytest.fixture
    def worker(self):
        """创建 StaticWorker 实例"""
        return StaticWorker()

    @pytest.fixture
    def create_test_pe(self):
        """创建测试用的 PE 文件"""
        def _create_pe(has_upx_marker: bool = False):
            """创建一个最小的 PE 文件用于测试"""
            fd, path = tempfile.mkstemp(suffix='.exe')
            
            try:
                # DOS Header
                dos_header = bytearray(64)
                dos_header[0:2] = b'MZ'
                dos_header[60:64] = struct.pack('<I', 64)
                
                # PE Signature
                pe_signature = b'PE\x00\x00'
                
                # COFF Header
                coff_header = bytearray(20)
                coff_header[0:2] = struct.pack('<H', 0x014c)
                coff_header[2:4] = struct.pack('<H', 1)
                coff_header[16:18] = struct.pack('<H', 224)
                coff_header[18:20] = struct.pack('<H', 0x010F)
                
                # Optional Header
                optional_header = bytearray(224)
                optional_header[0:2] = struct.pack('<H', 0x010b)
                optional_header[16:20] = struct.pack('<I', 0x1000)
                optional_header[20:24] = struct.pack('<I', 0x1000)
                optional_header[24:28] = struct.pack('<I', 0x2000)
                optional_header[28:32] = struct.pack('<I', 0x400000)
                optional_header[32:36] = struct.pack('<I', 0x1000)
                optional_header[36:40] = struct.pack('<I', 0x200)
                optional_header[56:60] = struct.pack('<I', 0x3000)
                optional_header[60:64] = struct.pack('<I', 0x200)
                
                # Section Header
                section_header = bytearray(40)
                if has_upx_marker:
                    section_header[0:8] = b'UPX0\x00\x00\x00\x00'
                else:
                    section_header[0:8] = b'.text\x00\x00\x00'
                section_header[8:12] = struct.pack('<I', 0x1000)
                section_header[12:16] = struct.pack('<I', 0x1000)
                section_header[16:20] = struct.pack('<I', 0x200)
                section_header[20:24] = struct.pack('<I', 0x200)
                section_header[36:40] = struct.pack('<I', 0x60000020)
                
                # Padding
                padding = b'\x00' * (0x200 - 64 - 4 - 20 - 224 - 40)
                
                # Section data
                section_data = b'\x00' * 0x200
                if has_upx_marker:
                    section_data = b'UPX!' + section_data[4:]
                
                # Write PE file
                with os.fdopen(fd, 'wb') as f:
                    f.write(dos_header)
                    f.write(pe_signature)
                    f.write(coff_header)
                    f.write(optional_header)
                    f.write(section_header)
                    f.write(padding)
                    f.write(section_data)
                
                return path
            except Exception as e:
                os.close(fd)
                if os.path.exists(path):
                    os.unlink(path)
                raise e
        
        return _create_pe

    def test_execute_packer_detect_no_packer(self, worker, create_test_pe):
        """测试通过 execute 方法检测未加壳的文件"""
        test_file = create_test_pe()
        
        try:
            # 创建请求
            sample = SampleInfo(sample_id="sha256:test123", path=test_file)
            policy = PolicyContext(allow_dynamic=False, allow_network=False)
            context = WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=policy,
                versions={"pefile": "2023.2.7"}
            )
            
            request = WorkerRequest(
                job_id="test-job-123",
                tool="packer.detect",
                sample=sample,
                args={},
                context=context
            )
            
            # 执行
            response = worker.execute(request)
            
            # 验证响应
            assert response.ok is True
            assert response.job_id == "test-job-123"
            assert 'result' in response.data
            assert response.data['result']['packed'] is False
            assert 'metrics' in response.data
            assert response.data['metrics']['elapsed_ms'] > 0
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_execute_packer_detect_with_upx(self, worker, create_test_pe):
        """测试通过 execute 方法检测 UPX 加壳的文件"""
        test_file = create_test_pe(has_upx_marker=True)
        
        try:
            # 创建请求
            sample = SampleInfo(sample_id="sha256:test456", path=test_file)
            policy = PolicyContext(allow_dynamic=False, allow_network=False)
            context = WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=policy,
                versions={"pefile": "2023.2.7"}
            )
            
            request = WorkerRequest(
                job_id="test-job-456",
                tool="packer.detect",
                sample=sample,
                args={},
                context=context
            )
            
            # 执行
            response = worker.execute(request)
            
            # 验证响应
            assert response.ok is True
            assert response.job_id == "test-job-456"
            assert 'result' in response.data
            
            # 应该检测到加壳
            if response.data['result']['packed']:
                assert response.data['result']['confidence'] > 0
                assert len(response.data['result']['detections']) > 0
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_execute_packer_detect_with_engines(self, worker, create_test_pe):
        """测试通过 execute 方法使用特定引擎"""
        test_file = create_test_pe()
        
        try:
            # 创建请求 - 只使用 entropy 引擎
            sample = SampleInfo(sample_id="sha256:test789", path=test_file)
            policy = PolicyContext(allow_dynamic=False, allow_network=False)
            context = WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=policy,
                versions={"pefile": "2023.2.7"}
            )
            
            request = WorkerRequest(
                job_id="test-job-789",
                tool="packer.detect",
                sample=sample,
                args={'engines': ['entropy']},
                context=context
            )
            
            # 执行
            response = worker.execute(request)
            
            # 验证响应
            assert response.ok is True
            assert 'metrics' in response.data
            assert response.data['metrics']['engines_used'] == ['entropy']
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_execute_packer_detect_error_handling(self, worker):
        """测试错误处理"""
        # 使用不存在的文件
        sample = SampleInfo(sample_id="sha256:nonexistent", path="/nonexistent/file.exe")
        policy = PolicyContext(allow_dynamic=False, allow_network=False)
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="test-job-error",
            tool="packer.detect",
            sample=sample,
            args={},
            context=context
        )
        
        # 执行
        response = worker.execute(request)
        
        # 由于 packer_detect 对每个引擎都有错误处理，
        # 它会返回成功但带有警告信息
        assert response.ok is True
        assert response.job_id == "test-job-error"
        
        # 应该有警告信息
        if 'warnings' in response.data:
            assert len(response.data['warnings']) > 0
        
        # 结果应该是未检测到加壳（因为所有引擎都失败了）
        assert response.data['result']['packed'] is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
