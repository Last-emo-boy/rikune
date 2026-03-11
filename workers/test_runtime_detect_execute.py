"""
Test runtime detection through the execute method
"""

import sys
import os
import pytest

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import (
    StaticWorker,
    WorkerRequest,
    SampleInfo,
    PolicyContext,
    WorkerContext,
)


class TestRuntimeDetectExecute:
    """测试通过 execute 方法调用 runtime.detect"""

    def setup_method(self):
        """设置测试环境"""
        self.worker = StaticWorker()

    def test_runtime_detect_tool_registered(self):
        """测试 runtime.detect 工具已注册"""
        assert 'runtime.detect' in self.worker.tool_handlers
        assert callable(self.worker.tool_handlers['runtime.detect'])

    def test_execute_runtime_detect_with_system_dll(self):
        """测试通过 execute 方法调用 runtime.detect"""
        system32_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        notepad_path = os.path.join(system32_path, 'notepad.exe')
        
        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")
        
        # 创建请求
        sample = SampleInfo(
            sample_id="sha256:test123",
            path=notepad_path
        )
        
        policy = PolicyContext(
            allow_dynamic=False,
            allow_network=False
        )
        
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7", "lief": "0.14.0"}
        )
        
        request = WorkerRequest(
            job_id="test-job-123",
            tool="runtime.detect",
            sample=sample,
            args={},
            context=context
        )
        
        # 执行请求
        response = self.worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert response.job_id == "test-job-123"
        assert len(response.errors) == 0
        
        # 验证数据结构
        assert response.data is not None
        assert "is_dotnet" in response.data
        assert "dotnet_version" in response.data
        assert "target_framework" in response.data
        assert "suspected" in response.data
        assert "import_dlls" in response.data
        
        # 验证指标
        assert "elapsed_ms" in response.metrics
        assert response.metrics["elapsed_ms"] > 0
        assert response.metrics["tool"] == "runtime.detect"
        
        print(f"\nRuntime detection result:")
        print(f"  is_dotnet: {response.data['is_dotnet']}")
        print(f"  import_dlls count: {len(response.data['import_dlls'])}")
        print(f"  suspected runtimes: {len(response.data['suspected'])}")
        print(f"  elapsed_ms: {response.metrics['elapsed_ms']}")

    def test_execute_runtime_detect_error_handling(self):
        """测试 runtime.detect 错误处理"""
        # 使用不存在的文件
        sample = SampleInfo(
            sample_id="sha256:test123",
            path="/nonexistent/file.exe"
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
            job_id="test-job-error",
            tool="runtime.detect",
            sample=sample,
            args={},
            context=context
        )
        
        # 执行请求
        response = self.worker.execute(request)
        
        # 应该返回错误
        assert response.ok is False
        assert response.job_id == "test-job-error"
        assert len(response.errors) > 0
        assert response.data is None


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
