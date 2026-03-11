"""
Unit tests for PE imports and exports extraction
"""

import pytest
import sys
import os
from pathlib import Path

# Add workers directory to path
sys.path.insert(0, str(Path(__file__).parent))

from static_worker import (
    StaticWorker,
    WorkerRequest,
    SampleInfo,
    PolicyContext,
    WorkerContext
)


class TestPEImportsExtract:
    """测试 PE 导入表提取"""

    @pytest.fixture
    def worker(self):
        """创建 Worker 实例"""
        return StaticWorker()

    @pytest.fixture
    def test_pe_path(self):
        """获取测试 PE 文件路径"""
        # 使用 Windows 系统自带的 notepad.exe 作为测试样本
        notepad_path = r"C:\Windows\System32\notepad.exe"
        if os.path.exists(notepad_path):
            return notepad_path
        
        # 如果 notepad.exe 不存在，跳过测试
        pytest.skip("Test PE file not found")

    def test_imports_extract_grouped(self, worker, test_pe_path):
        """测试按 DLL 分组的导入表提取"""
        request = WorkerRequest(
            job_id="test-imports-grouped",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
            ),
            args={"group_by_dll": True},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert len(response.errors) == 0
        
        # 验证数据结构
        data = response.data
        assert data is not None
        assert "imports" in data
        assert "delayed_imports" in data
        assert "total_dlls" in data
        assert "total_delayed_dlls" in data
        assert "total_functions" in data
        assert "total_delayed_functions" in data
        
        # 验证导入表是字典
        assert isinstance(data["imports"], dict)
        assert isinstance(data["delayed_imports"], dict)
        
        # 验证至少有一些导入
        assert data["total_dlls"] > 0
        assert data["total_functions"] > 0
        
        # 验证每个 DLL 的函数列表
        for dll_name, functions in data["imports"].items():
            assert isinstance(dll_name, str)
            assert isinstance(functions, list)
            assert len(functions) > 0
            
            # 验证函数名
            for func_name in functions:
                assert isinstance(func_name, str)
                assert len(func_name) > 0
        
        # 打印结果以便调试
        print("\n=== Imports (Grouped by DLL) ===")
        print(f"Total DLLs: {data['total_dlls']}")
        print(f"Total Functions: {data['total_functions']}")
        print(f"Total Delayed DLLs: {data['total_delayed_dlls']}")
        print(f"Total Delayed Functions: {data['total_delayed_functions']}")
        
        # 打印前几个 DLL 的导入
        for i, (dll_name, functions) in enumerate(list(data["imports"].items())[:3]):
            print(f"\n{dll_name}:")
            for func in functions[:5]:
                print(f"  - {func}")
            if len(functions) > 5:
                print(f"  ... and {len(functions) - 5} more")

    def test_imports_extract_ungrouped(self, worker, test_pe_path):
        """测试不分组的导入表提取"""
        request = WorkerRequest(
            job_id="test-imports-ungrouped",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
            ),
            args={"group_by_dll": False},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert len(response.errors) == 0
        
        # 验证数据结构
        data = response.data
        assert data is not None
        assert "imports" in data
        
        # 即使不分组，结果仍然是字典（DLL -> 函数列表）
        assert isinstance(data["imports"], dict)

    def test_imports_extract_default_grouping(self, worker, test_pe_path):
        """测试默认分组行为（应该是 True）"""
        request = WorkerRequest(
            job_id="test-imports-default",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
            ),
            args={},  # 不指定 group_by_dll
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert len(response.errors) == 0
        
        # 验证数据结构
        data = response.data
        assert data is not None
        assert "imports" in data

    def test_imports_extract_delayed_imports(self, worker, test_pe_path):
        """测试延迟加载导入表提取"""
        request = WorkerRequest(
            job_id="test-imports-delayed",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
            ),
            args={"group_by_dll": True},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        
        # 验证延迟导入字段存在
        data = response.data
        assert "delayed_imports" in data
        assert isinstance(data["delayed_imports"], dict)
        
        # 打印延迟导入信息
        if data["total_delayed_dlls"] > 0:
            print("\n=== Delayed Imports ===")
            for dll_name, functions in data["delayed_imports"].items():
                print(f"\n{dll_name}:")
                for func in functions[:5]:
                    print(f"  - {func}")
        else:
            print("\n=== No Delayed Imports Found ===")

    def test_imports_extract_common_dlls(self, worker, test_pe_path):
        """测试常见 DLL 的识别"""
        request = WorkerRequest(
            job_id="test-imports-common",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
            ),
            args={"group_by_dll": True},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        assert response.ok is True
        data = response.data
        
        # 检查常见的 Windows DLL
        common_dlls = ["kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll"]
        dll_names_lower = [dll.lower() for dll in data["imports"].keys()]
        
        found_common = [dll for dll in common_dlls if dll.lower() in dll_names_lower]
        
        print(f"\n=== Common DLLs Found ===")
        print(f"Found: {found_common}")
        
        # 至少应该找到一些常见 DLL
        assert len(found_common) > 0


class TestPEExportsExtract:
    """测试 PE 导出表提取"""

    @pytest.fixture
    def worker(self):
        """创建 Worker 实例"""
        return StaticWorker()

    @pytest.fixture
    def test_dll_path(self):
        """获取测试 DLL 文件路径（DLL 通常有导出表）"""
        # 使用 Windows 系统自带的 kernel32.dll 作为测试样本
        kernel32_path = r"C:\Windows\System32\kernel32.dll"
        if os.path.exists(kernel32_path):
            return kernel32_path
        
        # 如果 kernel32.dll 不存在，跳过测试
        pytest.skip("Test DLL file not found")

    def test_exports_extract_basic(self, worker, test_dll_path):
        """测试基本导出表提取"""
        request = WorkerRequest(
            job_id="test-exports-basic",
            tool="pe.exports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_dll_path
            ),
            args={},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert len(response.errors) == 0
        
        # 验证数据结构
        data = response.data
        assert data is not None
        assert "exports" in data
        assert "forwarders" in data
        assert "total_exports" in data
        assert "total_forwarders" in data
        
        # 验证导出表是列表
        assert isinstance(data["exports"], list)
        assert isinstance(data["forwarders"], list)
        
        # kernel32.dll 应该有大量导出
        assert data["total_exports"] > 0
        
        # 打印结果以便调试
        print("\n=== Exports ===")
        print(f"Total Exports: {data['total_exports']}")
        print(f"Total Forwarders: {data['total_forwarders']}")
        
        # 打印前几个导出函数
        print("\nFirst 10 exports:")
        for exp in data["exports"][:10]:
            name = exp.get("name", "N/A")
            ordinal = exp.get("ordinal", "N/A")
            address = exp.get("address", "N/A")
            print(f"  - {name} (Ordinal: {ordinal}, Address: 0x{address:X})")

    def test_exports_extract_structure(self, worker, test_dll_path):
        """测试导出表结构"""
        request = WorkerRequest(
            job_id="test-exports-structure",
            tool="pe.exports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_dll_path
            ),
            args={},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        assert response.ok is True
        data = response.data
        
        # 验证每个导出函数的结构
        for exp in data["exports"][:5]:  # 只检查前几个
            assert "ordinal" in exp
            assert "address" in exp
            assert "name" in exp
            
            # 验证类型
            assert isinstance(exp["ordinal"], int)
            assert isinstance(exp["address"], int)
            # name 可能是 None（按序号导出）
            if exp["name"] is not None:
                assert isinstance(exp["name"], str)

    def test_exports_extract_forwarders(self, worker, test_dll_path):
        """测试转发器识别"""
        request = WorkerRequest(
            job_id="test-exports-forwarders",
            tool="pe.exports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_dll_path
            ),
            args={},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        assert response.ok is True
        data = response.data
        
        # 验证转发器字段存在
        assert "forwarders" in data
        assert isinstance(data["forwarders"], list)
        
        # 打印转发器信息
        if data["total_forwarders"] > 0:
            print("\n=== Forwarders ===")
            for fwd in data["forwarders"][:10]:
                name = fwd.get("name", "N/A")
                forwarder = fwd.get("forwarder", "N/A")
                print(f"  - {name} -> {forwarder}")
        else:
            print("\n=== No Forwarders Found ===")

    def test_exports_extract_common_functions(self, worker, test_dll_path):
        """测试常见导出函数的识别"""
        request = WorkerRequest(
            job_id="test-exports-common",
            tool="pe.exports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_dll_path
            ),
            args={},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        assert response.ok is True
        data = response.data
        
        # 提取所有导出函数名
        export_names = [exp.get("name") for exp in data["exports"] if exp.get("name")]
        export_names_lower = [name.lower() for name in export_names if name]
        
        # 检查一些常见的 kernel32.dll 导出函数
        common_functions = ["createfilea", "createfilew", "readfile", "writefile", "closehandle"]
        found_common = [func for func in common_functions if func in export_names_lower]
        
        print(f"\n=== Common Functions Found ===")
        print(f"Found: {found_common}")
        
        # kernel32.dll 应该有这些常见函数
        assert len(found_common) > 0


class TestPEImportsExportsEdgeCases:
    """测试边缘情况"""

    @pytest.fixture
    def worker(self):
        """创建 Worker 实例"""
        return StaticWorker()

    def test_imports_extract_invalid_file(self, worker, tmp_path):
        """测试无效文件"""
        # 创建一个无效的 PE 文件
        invalid_file = tmp_path / "invalid.exe"
        invalid_file.write_bytes(b"Not a PE file")
        
        request = WorkerRequest(
            job_id="test-imports-invalid",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=str(invalid_file)
            ),
            args={"group_by_dll": True},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 应该失败
        assert response.ok is False
        assert len(response.errors) > 0

    def test_exports_extract_invalid_file(self, worker, tmp_path):
        """测试无效文件"""
        # 创建一个无效的 PE 文件
        invalid_file = tmp_path / "invalid.dll"
        invalid_file.write_bytes(b"Not a PE file")
        
        request = WorkerRequest(
            job_id="test-exports-invalid",
            tool="pe.exports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=str(invalid_file)
            ),
            args={},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 应该失败
        assert response.ok is False
        assert len(response.errors) > 0

    def test_imports_extract_nonexistent_file(self, worker):
        """测试不存在的文件"""
        request = WorkerRequest(
            job_id="test-imports-nonexistent",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path="/nonexistent/file.exe"
            ),
            args={"group_by_dll": True},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        response = worker.execute(request)
        
        # 应该失败
        assert response.ok is False
        assert len(response.errors) > 0


if __name__ == "__main__":
    # 运行测试
    pytest.main([__file__, "-v", "-s"])
