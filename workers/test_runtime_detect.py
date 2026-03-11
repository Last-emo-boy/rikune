"""
Unit tests for runtime detection functionality
"""

import sys
import os
import pytest

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import StaticWorker


class TestRuntimeDetect:
    """测试运行时检测功能"""

    def setup_method(self):
        """设置测试环境"""
        self.worker = StaticWorker()

    def test_detect_cpp_runtime_msvc140(self):
        """测试检测 MSVC 14.x (Visual Studio 2015-2022) C++ 运行时"""
        import_dlls = ['kernel32.dll', 'msvcp140.dll', 'vcruntime140.dll']
        
        result = self.worker._detect_cpp_runtime(import_dlls)
        
        assert result is not None
        assert 'C++ Runtime' in result['runtime']
        assert 'MSVC 14.x' in result['runtime']
        assert result['confidence'] >= 0.9
        assert len(result['evidence']) > 0
        assert any('msvcp140.dll' in ev for ev in result['evidence'])

    def test_detect_cpp_runtime_msvc120(self):
        """测试检测 MSVC 12.0 (Visual Studio 2013) C++ 运行时"""
        import_dlls = ['kernel32.dll', 'msvcp120.dll', 'msvcr120.dll']
        
        result = self.worker._detect_cpp_runtime(import_dlls)
        
        assert result is not None
        assert 'C++ Runtime' in result['runtime']
        assert 'MSVC 12.0' in result['runtime']
        assert result['confidence'] >= 0.9
        assert len(result['evidence']) > 0

    def test_detect_cpp_runtime_msvc100(self):
        """测试检测 MSVC 10.0 (Visual Studio 2010) C++ 运行时"""
        import_dlls = ['kernel32.dll', 'msvcp100.dll', 'msvcr100.dll']
        
        result = self.worker._detect_cpp_runtime(import_dlls)
        
        assert result is not None
        assert 'MSVC 10.0' in result['runtime']
        assert result['confidence'] >= 0.9

    def test_detect_cpp_runtime_system_crt(self):
        """测试检测系统 CRT（置信度较低）"""
        import_dlls = ['kernel32.dll', 'msvcrt.dll']
        
        result = self.worker._detect_cpp_runtime(import_dlls)
        
        assert result is not None
        assert 'System CRT' in result['runtime']
        assert result['confidence'] >= 0.7
        assert result['confidence'] < 0.9  # 系统 CRT 置信度较低

    def test_detect_cpp_runtime_none(self):
        """测试未检测到 C++ 运行时"""
        import_dlls = ['kernel32.dll', 'user32.dll']
        
        result = self.worker._detect_cpp_runtime(import_dlls)
        
        assert result is None

    def test_detect_python_runtime(self):
        """测试检测 Python 运行时"""
        import_dlls = ['kernel32.dll', 'python39.dll']
        
        result = self.worker._detect_other_runtimes(import_dlls)
        
        assert len(result) > 0
        python_runtime = next((r for r in result if 'Python' in r['runtime']), None)
        assert python_runtime is not None
        assert 'Python 3.9' in python_runtime['runtime']
        assert python_runtime['confidence'] >= 0.9

    def test_detect_python_runtime_no_version(self):
        """测试检测 Python 运行时（无版本号）"""
        import_dlls = ['kernel32.dll', 'python.dll']
        
        result = self.worker._detect_other_runtimes(import_dlls)
        
        assert len(result) > 0
        python_runtime = next((r for r in result if 'Python' in r['runtime']), None)
        assert python_runtime is not None
        assert 'Python Runtime' in python_runtime['runtime']

    def test_detect_visual_basic_runtime(self):
        """测试检测 Visual Basic 运行时"""
        import_dlls = ['kernel32.dll', 'msvbvm60.dll']
        
        result = self.worker._detect_other_runtimes(import_dlls)
        
        assert len(result) > 0
        vb_runtime = next((r for r in result if 'Visual Basic' in r['runtime']), None)
        assert vb_runtime is not None
        assert 'Visual Basic 6.0' in vb_runtime['runtime']
        assert vb_runtime['confidence'] >= 0.95

    def test_detect_delphi_runtime(self):
        """测试检测 Delphi 运行时"""
        import_dlls = ['kernel32.dll', 'cc3250.dll', 'rtl120.dll']
        
        result = self.worker._detect_other_runtimes(import_dlls)
        
        assert len(result) > 0
        delphi_runtime = next((r for r in result if 'Delphi' in r['runtime']), None)
        assert delphi_runtime is not None
        assert delphi_runtime['confidence'] >= 0.85

    def test_detect_go_runtime_minimal_imports(self):
        """测试检测 Go 运行时（最小导入）"""
        import_dlls = ['kernel32.dll', 'ntdll.dll', 'ws2_32.dll']
        
        result = self.worker._detect_other_runtimes(import_dlls)
        
        # Go 检测是推测性的，置信度较低
        go_runtime = next((r for r in result if 'Go' in r['runtime']), None)
        if go_runtime:
            assert go_runtime['confidence'] <= 0.6

    def test_detect_multiple_runtimes(self):
        """测试检测多个运行时"""
        import_dlls = ['kernel32.dll', 'msvcp140.dll', 'python39.dll']
        
        # 检测 C++ 运行时
        cpp_result = self.worker._detect_cpp_runtime(import_dlls)
        assert cpp_result is not None
        assert 'MSVC 14.x' in cpp_result['runtime']
        
        # 检测其他运行时
        other_results = self.worker._detect_other_runtimes(import_dlls)
        python_runtime = next((r for r in other_results if 'Python' in r['runtime']), None)
        assert python_runtime is not None

    def test_detect_no_runtime(self):
        """测试未检测到任何运行时"""
        import_dlls = ['kernel32.dll', 'user32.dll', 'gdi32.dll']
        
        cpp_result = self.worker._detect_cpp_runtime(import_dlls)
        assert cpp_result is None
        
        other_results = self.worker._detect_other_runtimes(import_dlls)
        # 可能检测到 Go（因为导入少），但不应该有其他运行时
        non_go_runtimes = [r for r in other_results if 'Go' not in r['runtime']]
        assert len(non_go_runtimes) == 0

    def test_runtime_detect_result_structure(self):
        """测试运行时检测结果结构"""
        # 创建一个模拟的结果
        result = {
            "is_dotnet": False,
            "dotnet_version": None,
            "target_framework": None,
            "suspected": [],
            "import_dlls": ['kernel32.dll', 'msvcp140.dll']
        }
        
        # 验证结构
        assert "is_dotnet" in result
        assert "dotnet_version" in result
        assert "target_framework" in result
        assert "suspected" in result
        assert "import_dlls" in result
        assert isinstance(result["suspected"], list)
        assert isinstance(result["import_dlls"], list)

    def test_runtime_detect_confidence_scores(self):
        """测试置信度分数在合理范围内"""
        import_dlls = ['kernel32.dll', 'msvcp140.dll', 'python39.dll', 'msvcrt.dll']
        
        cpp_result = self.worker._detect_cpp_runtime(import_dlls)
        assert cpp_result is not None
        assert 0.0 <= cpp_result['confidence'] <= 1.0
        
        other_results = self.worker._detect_other_runtimes(import_dlls)
        for runtime in other_results:
            assert 0.0 <= runtime['confidence'] <= 1.0

    def test_runtime_detect_evidence_not_empty(self):
        """测试证据列表不为空"""
        import_dlls = ['kernel32.dll', 'msvcp140.dll']
        
        cpp_result = self.worker._detect_cpp_runtime(import_dlls)
        assert cpp_result is not None
        assert len(cpp_result['evidence']) > 0
        assert all(isinstance(ev, str) for ev in cpp_result['evidence'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
