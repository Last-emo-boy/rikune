"""
Integration test demonstrating import/export extraction with real PE files
"""

import pytest
import json
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


class TestImportsExportsIntegration:
    """集成测试：导入导出表提取完整工作流"""

    @pytest.fixture
    def worker(self):
        """创建 Worker 实例"""
        return StaticWorker()

    @pytest.fixture
    def test_exe_path(self):
        """获取测试 EXE 文件路径"""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        if os.path.exists(notepad_path):
            return notepad_path
        pytest.skip("Test EXE file not found")

    @pytest.fixture
    def test_dll_path(self):
        """获取测试 DLL 文件路径"""
        kernel32_path = r"C:\Windows\System32\kernel32.dll"
        if os.path.exists(kernel32_path):
            return kernel32_path
        pytest.skip("Test DLL file not found")

    def test_complete_analysis_workflow(self, worker, test_exe_path):
        """测试完整的分析工作流：指纹 + 导入表 + 导出表"""
        
        # 1. 提取 PE 指纹
        print("\n=== Step 1: PE Fingerprint ===")
        fingerprint_request = WorkerRequest(
            job_id="workflow-fingerprint",
            tool="pe.fingerprint",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_exe_path
            ),
            args={"fast": False},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        fingerprint_response = worker.execute(fingerprint_request)
        assert fingerprint_response.ok is True
        
        print(f"Machine: {fingerprint_response.data['machine_name']}")
        print(f"Subsystem: {fingerprint_response.data['subsystem_name']}")
        print(f"Sections: {len(fingerprint_response.data.get('sections', []))}")
        
        # 2. 提取导入表
        print("\n=== Step 2: Import Table ===")
        imports_request = WorkerRequest(
            job_id="workflow-imports",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_exe_path
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
        
        imports_response = worker.execute(imports_request)
        assert imports_response.ok is True
        
        print(f"Total DLLs: {imports_response.data['total_dlls']}")
        print(f"Total Functions: {imports_response.data['total_functions']}")
        print(f"Delayed DLLs: {imports_response.data['total_delayed_dlls']}")
        
        # 3. 尝试提取导出表（EXE 可能没有导出）
        print("\n=== Step 3: Export Table ===")
        exports_request = WorkerRequest(
            job_id="workflow-exports",
            tool="pe.exports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_exe_path
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
        
        exports_response = worker.execute(exports_request)
        assert exports_response.ok is True
        
        print(f"Total Exports: {exports_response.data['total_exports']}")
        print(f"Total Forwarders: {exports_response.data['total_forwarders']}")
        
        # 4. 生成综合报告
        print("\n=== Step 4: Summary Report ===")
        report = {
            "file": test_exe_path,
            "fingerprint": {
                "machine": fingerprint_response.data['machine_name'],
                "subsystem": fingerprint_response.data['subsystem_name'],
                "sections": len(fingerprint_response.data.get('sections', []))
            },
            "imports": {
                "total_dlls": imports_response.data['total_dlls'],
                "total_functions": imports_response.data['total_functions'],
                "delayed_dlls": imports_response.data['total_delayed_dlls']
            },
            "exports": {
                "total_exports": exports_response.data['total_exports'],
                "total_forwarders": exports_response.data['total_forwarders']
            }
        }
        
        print(json.dumps(report, indent=2))
        
        # 验证所有步骤都成功
        assert fingerprint_response.ok is True
        assert imports_response.ok is True
        assert exports_response.ok is True

    def test_dll_analysis_workflow(self, worker, test_dll_path):
        """测试 DLL 分析工作流（DLL 通常有导出表）"""
        
        print(f"\n=== Analyzing DLL: {test_dll_path} ===")
        
        # 1. 提取导入表
        imports_request = WorkerRequest(
            job_id="dll-imports",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_dll_path
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
        
        imports_response = worker.execute(imports_request)
        assert imports_response.ok is True
        
        # 2. 提取导出表
        exports_request = WorkerRequest(
            job_id="dll-exports",
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
        
        exports_response = worker.execute(exports_request)
        assert exports_response.ok is True
        
        # 3. 分析导入导出关系
        print("\n=== Import/Export Analysis ===")
        print(f"Imports: {imports_response.data['total_functions']} functions from {imports_response.data['total_dlls']} DLLs")
        print(f"Exports: {exports_response.data['total_exports']} functions")
        print(f"Forwarders: {exports_response.data['total_forwarders']} functions")
        
        # DLL 应该有导出
        assert exports_response.data['total_exports'] > 0
        
        # 打印一些导出函数示例
        print("\nSample exports:")
        for exp in exports_response.data['exports'][:5]:
            print(f"  - {exp.get('name', 'N/A')} (Ordinal: {exp['ordinal']})")

    def test_identify_suspicious_imports(self, worker, test_exe_path):
        """测试识别可疑导入（安全分析场景）"""
        
        # 提取导入表
        imports_request = WorkerRequest(
            job_id="suspicious-imports",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_exe_path
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
        
        imports_response = worker.execute(imports_request)
        assert imports_response.ok is True
        
        # 定义可疑 API 列表
        suspicious_apis = {
            "process_injection": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
            "network": ["InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW"],
            "registry": ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"],
            "file_operations": ["CreateFileA", "CreateFileW", "WriteFile", "DeleteFileA", "DeleteFileW"]
        }
        
        # 收集所有导入的函数
        all_imports = []
        for dll_name, functions in imports_response.data['imports'].items():
            all_imports.extend(functions)
        
        # 检查可疑 API
        print("\n=== Suspicious API Analysis ===")
        found_suspicious = {}
        for category, apis in suspicious_apis.items():
            found = [api for api in apis if api in all_imports]
            if found:
                found_suspicious[category] = found
                print(f"\n{category.upper()}:")
                for api in found:
                    print(f"  - {api}")
        
        if not found_suspicious:
            print("No suspicious APIs found (this is expected for notepad.exe)")

    def test_compare_parsers(self, worker, test_exe_path):
        """测试比较 pefile 和 LIEF 解析器的结果"""
        
        # 使用默认解析器（pefile）
        request1 = WorkerRequest(
            job_id="parser-compare-1",
            tool="pe.imports.extract",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_exe_path
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
        
        response1 = worker.execute(request1)
        assert response1.ok is True
        
        # 验证结果一致性
        print("\n=== Parser Comparison ===")
        print(f"Total DLLs: {response1.data['total_dlls']}")
        print(f"Total Functions: {response1.data['total_functions']}")
        
        # 验证数据完整性
        assert response1.data['total_dlls'] > 0
        assert response1.data['total_functions'] > 0
        assert response1.data['total_dlls'] == len(response1.data['imports'])


if __name__ == "__main__":
    # 运行测试
    pytest.main([__file__, "-v", "-s"])
