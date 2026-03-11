"""
Integration tests for strings_extract with real PE files
"""

import os
import sys
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


class TestStringsExtractIntegration:
    """测试字符串提取集成功能"""

    def setup_method(self):
        """设置测试环境"""
        self.worker = StaticWorker()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def create_minimal_pe(self) -> str:
        """创建一个最小的 PE 文件用于测试"""
        pe_file = os.path.join(self.temp_dir, "minimal.exe")
        
        # 创建一个简单的 PE 文件结构
        # DOS Header
        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'  # DOS signature
        dos_header[60:64] = struct.pack('<I', 64)  # e_lfanew (PE header offset)
        
        # PE Header
        pe_header = bytearray()
        pe_header += b'PE\x00\x00'  # PE signature
        
        # COFF Header
        pe_header += struct.pack('<H', 0x014c)  # Machine (i386)
        pe_header += struct.pack('<H', 1)  # NumberOfSections
        pe_header += struct.pack('<I', 0)  # TimeDateStamp
        pe_header += struct.pack('<I', 0)  # PointerToSymbolTable
        pe_header += struct.pack('<I', 0)  # NumberOfSymbols
        pe_header += struct.pack('<H', 224)  # SizeOfOptionalHeader
        pe_header += struct.pack('<H', 0x0102)  # Characteristics
        
        # Optional Header (simplified)
        optional_header = bytearray(224)
        optional_header[0:2] = struct.pack('<H', 0x010b)  # Magic (PE32)
        
        # Section Header
        section_header = bytearray(40)
        section_header[0:8] = b'.text\x00\x00\x00'  # Name
        section_header[8:12] = struct.pack('<I', 0x1000)  # VirtualSize
        section_header[12:16] = struct.pack('<I', 0x1000)  # VirtualAddress
        section_header[16:20] = struct.pack('<I', 0x200)  # SizeOfRawData
        section_header[20:24] = struct.pack('<I', 0x200)  # PointerToRawData
        section_header[36:40] = struct.pack('<I', 0x60000020)  # Characteristics
        
        # 添加一些测试字符串到文件中
        test_strings = (
            b'\x00\x00\x00\x00'
            b'Hello World from PE file\x00'
            b'\x00\x00'
            b'http://example.com/malware\x00'
            b'\x00\x00'
            b'C:\\Windows\\System32\\kernel32.dll\x00'
            b'\x00\x00'
            b'T\x00e\x00s\x00t\x00 \x00U\x00n\x00i\x00c\x00o\x00d\x00e\x00\x00\x00'  # UTF-16LE
            b'\x00' * 100
        )
        
        # 组装 PE 文件
        pe_content = dos_header + pe_header + optional_header + section_header
        # 填充到 0x200 (section start)
        pe_content += b'\x00' * (0x200 - len(pe_content))
        pe_content += test_strings
        
        with open(pe_file, 'wb') as f:
            f.write(pe_content)
        
        return pe_file

    def test_strings_extract_from_pe_file(self):
        """测试从 PE 文件提取字符串"""
        pe_file = self.create_minimal_pe()
        
        # 创建 WorkerRequest
        sample = SampleInfo(
            sample_id="sha256:test123",
            path=pe_file
        )
        policy = PolicyContext(
            allow_dynamic=False,
            allow_network=False
        )
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-test-strings",
            tool="strings.extract",
            sample=sample,
            args={
                "min_len": 4,
                "encoding": "all"
            },
            context=context
        )
        
        # 执行
        response = self.worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert len(response.errors) == 0
        assert response.data is not None
        
        # 验证提取的字符串
        strings = response.data['strings']
        assert len(strings) > 0
        
        string_values = [s['string'] for s in strings]
        
        # 验证包含预期的字符串
        assert any('Hello World' in s for s in string_values)
        assert any('example.com' in s or 'http://' in s for s in string_values)
        assert any('kernel32' in s or 'System32' in s for s in string_values)
        
        # 验证 Unicode 字符串
        unicode_strings = [s for s in strings if s['encoding'] == 'utf-16le']
        if len(unicode_strings) > 0:
            unicode_values = [s['string'] for s in unicode_strings]
            assert any('Test' in s or 'Unicode' in s for s in unicode_values)

    def test_strings_extract_ascii_only(self):
        """测试仅提取 ASCII 字符串"""
        pe_file = self.create_minimal_pe()
        
        sample = SampleInfo(
            sample_id="sha256:test123",
            path=pe_file
        )
        policy = PolicyContext(
            allow_dynamic=False,
            allow_network=False
        )
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-test-strings-ascii",
            tool="strings.extract",
            sample=sample,
            args={
                "min_len": 6,
                "encoding": "ascii"
            },
            context=context
        )
        
        response = self.worker.execute(request)
        
        assert response.ok is True
        assert response.data['encoding_filter'] == 'ascii'
        assert response.data['min_len'] == 6
        
        # 验证所有字符串都是 ASCII
        strings = response.data['strings']
        for s in strings:
            assert s['encoding'] == 'ascii'
            assert len(s['string']) >= 6

    def test_strings_extract_with_offsets(self):
        """测试字符串偏移量正确性"""
        pe_file = self.create_minimal_pe()
        
        sample = SampleInfo(
            sample_id="sha256:test123",
            path=pe_file
        )
        policy = PolicyContext(
            allow_dynamic=False,
            allow_network=False
        )
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-test-strings-offsets",
            tool="strings.extract",
            sample=sample,
            args={
                "min_len": 4,
                "encoding": "ascii"
            },
            context=context
        )
        
        response = self.worker.execute(request)
        
        assert response.ok is True
        
        # 读取文件内容
        with open(pe_file, 'rb') as f:
            file_content = f.read()
        
        # 验证偏移量
        strings = response.data['strings']
        for s in strings:
            offset = s['offset']
            string_value = s['string']
            
            # 验证偏移量处确实包含该字符串
            actual_bytes = file_content[offset:offset+len(string_value)]
            try:
                actual_string = actual_bytes.decode('ascii')
                assert string_value in actual_string or actual_string in string_value
            except UnicodeDecodeError:
                # 如果无法解码，跳过验证
                pass

    def test_strings_extract_performance(self):
        """测试字符串提取性能"""
        pe_file = self.create_minimal_pe()
        
        sample = SampleInfo(
            sample_id="sha256:test123",
            path=pe_file
        )
        policy = PolicyContext(
            allow_dynamic=False,
            allow_network=False
        )
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-test-strings-perf",
            tool="strings.extract",
            sample=sample,
            args={
                "min_len": 4,
                "encoding": "all"
            },
            context=context
        )
        
        response = self.worker.execute(request)
        
        assert response.ok is True
        
        # 验证性能指标
        assert 'elapsed_ms' in response.metrics
        elapsed_ms = response.metrics['elapsed_ms']
        
        # 对于小文件，应该在 1 秒内完成
        assert elapsed_ms < 1000, f"String extraction took {elapsed_ms}ms, expected < 1000ms"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
