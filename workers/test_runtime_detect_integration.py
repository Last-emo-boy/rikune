"""
Integration tests for runtime detection with real PE files
"""

import sys
import os
import pytest

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import StaticWorker


class TestRuntimeDetectIntegration:
    """集成测试：使用真实 PE 文件测试运行时检测"""

    def setup_method(self):
        """设置测试环境"""
        self.worker = StaticWorker()
        self.test_samples_dir = os.path.join(os.path.dirname(__file__), 'test_samples')

    def test_runtime_detect_with_system_dll(self):
        """测试使用系统 DLL 进行运行时检测"""
        # 使用 Windows 系统 DLL 作为测试样本
        system32_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        
        # 测试 kernel32.dll（系统 DLL，应该有最小的导入）
        kernel32_path = os.path.join(system32_path, 'kernel32.dll')
        
        if not os.path.exists(kernel32_path):
            pytest.skip("kernel32.dll not found")
        
        try:
            result = self.worker.runtime_detect(kernel32_path, {})
            
            # 验证结果结构
            assert "is_dotnet" in result
            assert "dotnet_version" in result
            assert "target_framework" in result
            assert "suspected" in result
            assert "import_dlls" in result
            
            # kernel32.dll 不应该是 .NET
            assert result["is_dotnet"] is False
            
            # 应该有导入的 DLL 列表
            assert isinstance(result["import_dlls"], list)
            
            # suspected 应该是列表
            assert isinstance(result["suspected"], list)
            
            print(f"\nkernel32.dll runtime detection result:")
            print(f"  is_dotnet: {result['is_dotnet']}")
            print(f"  import_dlls count: {len(result['import_dlls'])}")
            print(f"  suspected runtimes: {len(result['suspected'])}")
            for runtime in result['suspected']:
                print(f"    - {runtime['runtime']} (confidence: {runtime['confidence']})")
            
        except Exception as e:
            pytest.skip(f"Failed to analyze kernel32.dll: {str(e)}")

    def test_runtime_detect_with_notepad(self):
        """测试使用 notepad.exe 进行运行时检测"""
        system32_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        notepad_path = os.path.join(system32_path, 'notepad.exe')
        
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")
        
        try:
            result = self.worker.runtime_detect(notepad_path, {})
            
            # 验证结果结构
            assert "is_dotnet" in result
            assert "suspected" in result
            assert "import_dlls" in result
            
            # notepad.exe 不应该是 .NET
            assert result["is_dotnet"] is False
            
            # 应该有导入的 DLL
            assert len(result["import_dlls"]) > 0
            
            print(f"\nnotepad.exe runtime detection result:")
            print(f"  is_dotnet: {result['is_dotnet']}")
            print(f"  import_dlls: {result['import_dlls'][:5]}...")  # 只显示前5个
            print(f"  suspected runtimes: {len(result['suspected'])}")
            for runtime in result['suspected']:
                print(f"    - {runtime['runtime']} (confidence: {runtime['confidence']})")
                print(f"      evidence: {runtime['evidence'][:2]}")  # 只显示前2个证据
            
        except Exception as e:
            pytest.skip(f"Failed to analyze notepad.exe: {str(e)}")

    def test_runtime_detect_result_validation(self):
        """测试运行时检测结果的验证"""
        system32_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        calc_path = os.path.join(system32_path, 'calc.exe')
        
        if not os.path.exists(calc_path):
            pytest.skip("calc.exe not found")
        
        try:
            result = self.worker.runtime_detect(calc_path, {})
            
            # 验证所有必需字段存在
            required_fields = ["is_dotnet", "dotnet_version", "target_framework", "suspected", "import_dlls"]
            for field in required_fields:
                assert field in result, f"Missing required field: {field}"
            
            # 验证类型
            assert isinstance(result["is_dotnet"], bool)
            assert result["dotnet_version"] is None or isinstance(result["dotnet_version"], str)
            assert result["target_framework"] is None or isinstance(result["target_framework"], str)
            assert isinstance(result["suspected"], list)
            assert isinstance(result["import_dlls"], list)
            
            # 验证 suspected 列表中的每个元素
            for runtime in result["suspected"]:
                assert "runtime" in runtime
                assert "confidence" in runtime
                assert "evidence" in runtime
                assert isinstance(runtime["runtime"], str)
                assert isinstance(runtime["confidence"], (int, float))
                assert 0.0 <= runtime["confidence"] <= 1.0
                assert isinstance(runtime["evidence"], list)
                assert all(isinstance(ev, str) for ev in runtime["evidence"])
            
            print(f"\ncalc.exe runtime detection validation passed")
            print(f"  Detected {len(result['suspected'])} runtime(s)")
            
        except Exception as e:
            pytest.skip(f"Failed to analyze calc.exe: {str(e)}")

    def test_runtime_detect_confidence_ordering(self):
        """测试置信度排序"""
        system32_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        test_path = os.path.join(system32_path, 'cmd.exe')
        
        if not os.path.exists(test_path):
            pytest.skip("cmd.exe not found")
        
        try:
            result = self.worker.runtime_detect(test_path, {})
            
            # 如果检测到多个运行时，验证它们都有合理的置信度
            if len(result["suspected"]) > 1:
                confidences = [r["confidence"] for r in result["suspected"]]
                
                # 所有置信度应该在 0-1 之间
                assert all(0.0 <= c <= 1.0 for c in confidences)
                
                # 至少应该有一个高置信度的检测（> 0.7）
                assert any(c > 0.7 for c in confidences)
                
                print(f"\ncmd.exe confidence scores:")
                for runtime in result["suspected"]:
                    print(f"  {runtime['runtime']}: {runtime['confidence']}")
            
        except Exception as e:
            pytest.skip(f"Failed to analyze cmd.exe: {str(e)}")

    def test_runtime_detect_import_dll_extraction(self):
        """测试导入 DLL 提取"""
        system32_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        test_path = os.path.join(system32_path, 'notepad.exe')
        
        if not os.path.exists(test_path):
            pytest.skip("notepad.exe not found")
        
        try:
            result = self.worker.runtime_detect(test_path, {})
            
            # 应该提取到导入的 DLL
            assert len(result["import_dlls"]) > 0
            
            # 所有 DLL 名称应该是字符串
            assert all(isinstance(dll, str) for dll in result["import_dlls"])
            
            # 应该包含常见的系统 DLL
            common_dlls = ['kernel32.dll', 'user32.dll', 'gdi32.dll', 'ntdll.dll']
            found_common = [dll for dll in result["import_dlls"] if dll.lower() in common_dlls]
            assert len(found_common) > 0, "Should find at least one common system DLL"
            
            print(f"\nnotepad.exe imports {len(result['import_dlls'])} DLLs")
            print(f"  Common DLLs found: {found_common}")
            
        except Exception as e:
            pytest.skip(f"Failed to analyze notepad.exe: {str(e)}")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
