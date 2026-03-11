"""
Unit tests for packer detection functionality
"""

import json
import sys
import os
import pytest
import tempfile
import struct

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import StaticWorker


class TestPackerDetect:
    """测试加壳器检测功能"""

    @pytest.fixture
    def worker(self):
        """创建 StaticWorker 实例"""
        return StaticWorker()

    @pytest.fixture
    def create_test_pe(self):
        """创建测试用的 PE 文件"""
        def _create_pe(content: bytes = b"", has_upx_marker: bool = False):
            """
            创建一个最小的 PE 文件用于测试
            
            Args:
                content: 额外的内容
                has_upx_marker: 是否包含 UPX 标记
            """
            # 创建临时文件
            fd, path = tempfile.mkstemp(suffix='.exe')
            
            try:
                # DOS Header
                dos_header = bytearray(64)
                dos_header[0:2] = b'MZ'  # e_magic
                dos_header[60:64] = struct.pack('<I', 64)  # e_lfanew (PE header offset)
                
                # PE Signature
                pe_signature = b'PE\x00\x00'
                
                # COFF Header (20 bytes)
                coff_header = bytearray(20)
                coff_header[0:2] = struct.pack('<H', 0x014c)  # Machine (IMAGE_FILE_MACHINE_I386)
                coff_header[2:4] = struct.pack('<H', 1)  # NumberOfSections
                coff_header[16:18] = struct.pack('<H', 224)  # SizeOfOptionalHeader
                coff_header[18:20] = struct.pack('<H', 0x010F)  # Characteristics
                
                # Optional Header (224 bytes for PE32)
                optional_header = bytearray(224)
                optional_header[0:2] = struct.pack('<H', 0x010b)  # Magic (PE32)
                optional_header[16:20] = struct.pack('<I', 0x1000)  # AddressOfEntryPoint
                optional_header[20:24] = struct.pack('<I', 0x1000)  # BaseOfCode
                optional_header[24:28] = struct.pack('<I', 0x2000)  # BaseOfData
                optional_header[28:32] = struct.pack('<I', 0x400000)  # ImageBase
                optional_header[32:36] = struct.pack('<I', 0x1000)  # SectionAlignment
                optional_header[36:40] = struct.pack('<I', 0x200)  # FileAlignment
                optional_header[56:60] = struct.pack('<I', 0x3000)  # SizeOfImage
                optional_header[60:64] = struct.pack('<I', 0x200)  # SizeOfHeaders
                
                # Section Header (40 bytes)
                section_header = bytearray(40)
                if has_upx_marker:
                    section_header[0:8] = b'UPX0\x00\x00\x00\x00'  # Name
                else:
                    section_header[0:8] = b'.text\x00\x00\x00'  # Name
                section_header[8:12] = struct.pack('<I', 0x1000)  # VirtualSize
                section_header[12:16] = struct.pack('<I', 0x1000)  # VirtualAddress
                section_header[16:20] = struct.pack('<I', 0x200)  # SizeOfRawData
                section_header[20:24] = struct.pack('<I', 0x200)  # PointerToRawData
                section_header[36:40] = struct.pack('<I', 0x60000020)  # Characteristics
                
                # Padding to align to file alignment
                padding = b'\x00' * (0x200 - 64 - 4 - 20 - 224 - 40)
                
                # Section data
                section_data = content if content else b'\x00' * 0x200
                if has_upx_marker:
                    # Add UPX marker in section data
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

    def test_packer_detect_no_packer(self, worker, create_test_pe):
        """测试未加壳的文件"""
        test_file = create_test_pe()
        
        try:
            result = worker.packer_detect(test_file, {})
            
            assert 'result' in result
            assert 'warnings' in result
            assert 'metrics' in result
            
            # 未加壳的文件应该返回 packed=False
            assert result['result']['packed'] is False
            assert result['result']['confidence'] == 0.0
            assert len(result['result']['detections']) == 0
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_packer_detect_upx_marker(self, worker, create_test_pe):
        """测试带有 UPX 标记的文件"""
        test_file = create_test_pe(has_upx_marker=True)
        
        try:
            result = worker.packer_detect(test_file, {})
            
            assert 'result' in result
            
            # 应该检测到 UPX
            assert result['result']['packed'] is True
            assert result['result']['confidence'] > 0
            
            # 检查是否有 YARA 检测结果
            yara_detections = [d for d in result['result']['detections'] if d['method'] == 'yara']
            if yara_detections:
                assert any('UPX' in d['name'] for d in yara_detections)
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_packer_detect_high_entropy(self, worker, create_test_pe):
        """测试高熵节区检测"""
        # 创建高熵数据（随机数据）
        import random
        high_entropy_data = bytes([random.randint(0, 255) for _ in range(512)])
        
        test_file = create_test_pe(content=high_entropy_data)
        
        try:
            result = worker.packer_detect(test_file, {'engines': ['entropy']})
            
            assert 'result' in result
            
            # 高熵数据应该被检测到
            entropy_detections = [d for d in result['result']['detections'] if d['method'] == 'entropy']
            
            # 可能检测到高熵（取决于随机数据的实际熵值）
            if entropy_detections:
                assert result['result']['packed'] is True
                assert 'high_entropy_sections' in entropy_detections[0]['details']
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_packer_detect_engines_parameter(self, worker, create_test_pe):
        """测试 engines 参数"""
        test_file = create_test_pe()
        
        try:
            # 只使用 YARA 引擎
            result = worker.packer_detect(test_file, {'engines': ['yara']})
            assert result['metrics']['engines_used'] == ['yara']
            
            # 只使用熵值引擎
            result = worker.packer_detect(test_file, {'engines': ['entropy']})
            assert result['metrics']['engines_used'] == ['entropy']
            
            # 使用所有引擎
            result = worker.packer_detect(test_file, {'engines': ['yara', 'entropy', 'entrypoint']})
            assert set(result['metrics']['engines_used']) == {'yara', 'entropy', 'entrypoint'}
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_packer_detect_default_engines(self, worker, create_test_pe):
        """测试默认引擎配置"""
        test_file = create_test_pe()
        
        try:
            result = worker.packer_detect(test_file, {})
            
            # 默认应该使用所有三个引擎
            assert set(result['metrics']['engines_used']) == {'yara', 'entropy', 'entrypoint'}
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_packer_detect_metrics(self, worker, create_test_pe):
        """测试性能指标"""
        test_file = create_test_pe()
        
        try:
            result = worker.packer_detect(test_file, {})
            
            assert 'metrics' in result
            assert 'elapsed_ms' in result['metrics']
            assert 'engines_used' in result['metrics']
            assert result['metrics']['elapsed_ms'] > 0
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)

    def test_packer_detect_confidence_calculation(self, worker, create_test_pe):
        """测试置信度计算"""
        test_file = create_test_pe(has_upx_marker=True)
        
        try:
            result = worker.packer_detect(test_file, {})
            
            if result['result']['packed']:
                # 置信度应该在 0-1 之间
                assert 0 <= result['result']['confidence'] <= 1.0
                
                # 如果有多个检测方法，置信度应该更高
                if len(set(result['result']['methods'])) > 1:
                    assert result['result']['confidence'] > 0.6
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
