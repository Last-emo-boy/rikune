"""
测试 LIEF 备用解析器
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# 添加 workers 目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from static_worker import (
    StaticWorker,
    WorkerRequest,
    SampleInfo,
    PolicyContext,
    WorkerContext
)


class TestPEFallback:
    """测试 LIEF 备用解析器"""

    @pytest.fixture
    def worker(self):
        """创建 Worker 实例"""
        return StaticWorker()

    @pytest.fixture
    def test_pe_path(self):
        """获取测试 PE 文件路径"""
        notepad_path = r"C:\Windows\System32\notepad.exe"
        if os.path.exists(notepad_path):
            return notepad_path
        pytest.skip("Test PE file not found")

    def test_lief_fallback_on_pefile_failure(self, worker, test_pe_path):
        """测试当 pefile 失败时使用 LIEF 备用解析器"""
        request = WorkerRequest(
            job_id="test-job-fallback",
            tool="pe.fingerprint",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
            ),
            args={"fast": True},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        # 模拟 pefile 失败
        with patch.object(worker, '_pe_fingerprint_pefile', side_effect=Exception("pefile failed")):
            response = worker.execute(request)
            
            # 应该成功（使用 LIEF）
            assert response.ok is True
            assert len(response.errors) == 0
            
            # 验证使用了 LIEF
            data = response.data
            assert data is not None
            assert "_parser" in data
            assert data["_parser"] == "lief"
            assert "_pefile_error" in data
            
            print(f"\nFallback successful! Used LIEF parser")
            print(f"pefile error: {data['_pefile_error']}")

    def test_both_parsers_fail(self, worker, test_pe_path):
        """测试当两个解析器都失败时的错误处理"""
        request = WorkerRequest(
            job_id="test-job-both-fail",
            tool="pe.fingerprint",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
            ),
            args={"fast": True},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={"pefile": "2023.2.7", "lief": "0.14.0"}
            )
        )
        
        # 模拟两个解析器都失败
        with patch.object(worker, '_pe_fingerprint_pefile', side_effect=Exception("pefile failed")):
            with patch.object(worker, '_pe_fingerprint_lief', side_effect=Exception("lief failed")):
                response = worker.execute(request)
                
                # 应该失败
                assert response.ok is False
                assert len(response.errors) > 0
                assert "Both parsers failed" in response.errors[0]
                
                print(f"\nBoth parsers failed as expected")
                print(f"Error: {response.errors[0]}")

    def test_lief_direct_usage(self, worker, test_pe_path):
        """测试直接使用 LIEF 解析器"""
        # 直接调用 LIEF 解析器
        result = worker._pe_fingerprint_lief(test_pe_path, fast=True)
        
        # 验证结果
        assert result is not None
        assert "machine" in result
        assert "subsystem" in result
        assert "timestamp" in result
        assert "entry_point" in result
        
        print(f"\nDirect LIEF usage successful")
        print(f"Machine: {result['machine_name']}")
        print(f"Subsystem: {result['subsystem_name']}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
