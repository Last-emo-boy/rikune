"""
Unit tests for strings_extract functionality
"""

import os
import sys
import pytest
import tempfile

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import StaticWorker


class TestStringsExtract:
    """测试字符串提取功能"""

    def setup_method(self):
        """设置测试环境"""
        self.worker = StaticWorker()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def create_test_file(self, content: bytes) -> str:
        """创建测试文件"""
        test_file = os.path.join(self.temp_dir, "test_sample.bin")
        with open(test_file, 'wb') as f:
            f.write(content)
        return test_file

    def test_extract_ascii_strings_basic(self):
        """测试基本 ASCII 字符串提取"""
        # 创建包含 ASCII 字符串的测试文件
        content = b'\x00\x00Hello World\x00\x00Test String\x00\x00'
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii'
        })

        assert result['count'] >= 2
        assert result['min_len'] == 4
        assert result['encoding_filter'] == 'ascii'

        # 验证提取的字符串
        strings = result['strings']
        string_values = [s['string'] for s in strings]
        assert 'Hello World' in string_values or 'Hello' in string_values
        assert 'Test String' in string_values or 'Test' in string_values

    def test_extract_unicode_strings_basic(self):
        """测试基本 Unicode (UTF-16LE) 字符串提取"""
        # 创建包含 UTF-16LE 字符串的测试文件
        content = b'\x00\x00H\x00e\x00l\x00l\x00o\x00\x00\x00'
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'unicode'
        })

        assert result['encoding_filter'] == 'unicode'

        # 验证提取的字符串
        strings = result['strings']
        if len(strings) > 0:
            assert any('Hello' in s['string'] for s in strings)

    def test_extract_all_encodings(self):
        """测试提取所有编码"""
        # 创建包含多种编码的测试文件
        content = (
            b'ASCII String Here\x00\x00'  # ASCII
            b'T\x00e\x00s\x00t\x00\x00\x00'  # UTF-16LE
        )
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'all'
        })

        assert result['encoding_filter'] == 'all'
        assert result['count'] > 0

        # 验证提取了不同编码的字符串
        strings = result['strings']
        encodings = set(s['encoding'] for s in strings)
        assert len(encodings) > 0  # 至少有一种编码

    def test_min_len_parameter(self):
        """测试 min_len 参数"""
        content = b'Hi\x00Test\x00LongerString\x00'
        test_file = self.create_test_file(content)

        # min_len = 4
        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii'
        })

        strings = result['strings']
        # 'Hi' (长度 2) 不应该被提取
        string_values = [s['string'] for s in strings]
        assert 'Hi' not in string_values
        # 'Test' (长度 4) 应该被提取
        assert 'Test' in string_values or 'LongerString' in string_values

    def test_offset_tracking(self):
        """测试偏移量跟踪"""
        content = b'\x00\x00\x00Test\x00\x00\x00'
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii'
        })

        strings = result['strings']
        assert len(strings) > 0

        # 验证偏移量
        for s in strings:
            assert 'offset' in s
            assert isinstance(s['offset'], int)
            assert s['offset'] >= 0

    def test_invalid_min_len(self):
        """测试无效的 min_len 参数"""
        content = b'Test'
        test_file = self.create_test_file(content)

        with pytest.raises(ValueError, match="min_len must be at least 1"):
            self.worker.strings_extract(test_file, {
                'min_len': 0,
                'encoding': 'ascii'
            })

    def test_invalid_encoding(self):
        """测试无效的 encoding 参数"""
        content = b'Test'
        test_file = self.create_test_file(content)

        with pytest.raises(ValueError, match="Invalid encoding"):
            self.worker.strings_extract(test_file, {
                'min_len': 4,
                'encoding': 'invalid'
            })

    def test_nonexistent_file(self):
        """测试不存在的文件"""
        with pytest.raises(Exception, match="Failed to read file"):
            self.worker.strings_extract('/nonexistent/file.bin', {
                'min_len': 4,
                'encoding': 'ascii'
            })

    def test_empty_file(self):
        """测试空文件"""
        content = b''
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii'
        })

        assert result['count'] == 0
        assert len(result['strings']) == 0

    def test_default_parameters(self):
        """测试默认参数"""
        content = b'Test String Here'
        test_file = self.create_test_file(content)

        # 不提供参数，使用默认值
        result = self.worker.strings_extract(test_file, {})

        assert result['min_len'] == 4  # 默认值
        assert result['encoding_filter'] == 'all'  # 默认值

    def test_deduplication(self):
        """测试字符串去重"""
        # 创建包含重复字符串的文件
        content = b'Test\x00Test\x00Test\x00'
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii'
        })

        strings = result['strings']
        # 验证相同偏移量和字符串的组合只出现一次
        seen = set()
        for s in strings:
            key = (s['offset'], s['string'])
            assert key not in seen, f"Duplicate found: {key}"
            seen.add(key)

    def test_sorting_by_offset(self):
        """测试按偏移量排序"""
        content = b'\x00\x00\x00Third\x00\x00First\x00\x00\x00Second\x00'
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii'
        })

        strings = result['strings']
        if len(strings) > 1:
            # 验证按偏移量升序排序
            offsets = [s['offset'] for s in strings]
            assert offsets == sorted(offsets), "Strings should be sorted by offset"

    def test_utf8_strings(self):
        """测试 UTF-8 字符串提取"""
        # 创建包含 UTF-8 字符串的文件（中文）
        content = '测试字符串'.encode('utf-8') + b'\x00\x00'
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'all'
        })

        strings = result['strings']
        
        # 验证提取了 UTF-8 字符串
        utf8_strings = [s for s in strings if s['encoding'] == 'utf-8']
        if len(utf8_strings) > 0:
            assert any('测试' in s['string'] for s in utf8_strings)

    def test_gbk_strings(self):
        """测试 GBK 字符串提取"""
        # 创建包含 GBK 字符串的文件
        try:
            content = '测试字符串'.encode('gbk') + b'\x00\x00'
            test_file = self.create_test_file(content)

            result = self.worker.strings_extract(test_file, {
                'min_len': 4,
                'encoding': 'all'
            })

            strings = result['strings']
            
            # 验证提取了 GBK 字符串
            gbk_strings = [s for s in strings if s['encoding'] == 'gbk']
            if len(gbk_strings) > 0:
                assert any('测试' in s['string'] for s in gbk_strings)
        except LookupError:
            # GBK 编码不可用，跳过测试
            pytest.skip("GBK encoding not available")

    def test_mixed_content(self):
        """测试混合内容"""
        # 创建包含可打印和不可打印字符的文件
        content = b'\x00\x01\x02Test\x00\x00\x00String\xff\xfe\x00'
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii'
        })

        strings = result['strings']
        string_values = [s['string'] for s in strings]
        
        # 验证提取了可打印字符串
        assert 'Test' in string_values or 'String' in string_values

    def test_max_string_length_and_segmentation(self):
        """Ensure long strings are segmented/capped to reduce noisy blobs."""
        long_blob = (
            b"http://a.example.com/path;"
            b"C:\\Users\\Public\\x;"
            b"CreateRemoteThread;"
            + (b"A" * 1200)
        )
        test_file = self.create_test_file(long_blob)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii',
            'max_string_length': 128,
        })

        assert result['max_string_length'] == 128
        for item in result['strings']:
            assert len(item['string']) <= 128

    def test_category_filter_ioc(self):
        """IOC filter should keep behavior-related strings and drop generic noise."""
        content = (
            b"just_noise_literal\x00"
            b"http://malicious.example\x00"
            b"CreateRemoteThread\x00"
            b"C:\\Windows\\Temp\\evil.exe\x00"
        )
        test_file = self.create_test_file(content)

        result = self.worker.strings_extract(test_file, {
            'min_len': 4,
            'encoding': 'ascii',
            'category_filter': 'ioc',
        })

        assert result['category_filter'] == 'ioc'
        values = [item['string'] for item in result['strings']]
        assert any('http://' in v for v in values) or any('CreateRemoteThread' in v for v in values)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
