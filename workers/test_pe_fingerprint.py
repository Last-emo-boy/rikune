"""
测试 PE 指纹提取功能
"""

import pytest
import json
import sys
import os
from pathlib import Path

# 添加 workers 目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from static_worker import (
    StaticWorker,
    WorkerRequest,
    SampleInfo,
    PolicyContext,
    WorkerContext,
    parse_request,
    response_to_dict
)


class TestPEFingerprint:
    """测试 PE 指纹提取"""

    def test_pe_fingerprint_fast_mode(self):
        """测试快速模式 PE 指纹提取"""
        worker = StaticWorker()
        
        # 创建测试请求
        request = WorkerRequest(
            job_id="test-job-1",
            tool="pe.fingerprint",
            sample=SampleInfo(
                sample_id="sha256:test",
                path="test_sample.exe"  # 需要实际的测试文件
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
        
        # 注意：这个测试需要实际的 PE 文件才能运行
        # 在实际环境中，应该使用测试样本
        
    def test_pe_fingerprint_full_mode(self):
        """测试完整模式 PE 指纹提取"""
        worker = StaticWorker()
        
        request = WorkerRequest(
            job_id="test-job-2",
            tool="pe.fingerprint",
            sample=SampleInfo(
                sample_id="sha256:test",
                path="test_sample.exe"
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
        
        # 注意：这个测试需要实际的 PE 文件才能运行
        
    def test_entropy_calculation(self):
        """测试熵值计算"""
        worker = StaticWorker()
        
        # 测试全零数据（熵值应该为 0）
        zero_data = b'\x00' * 1000
        entropy = worker._calculate_entropy(zero_data)
        assert entropy == 0.0
        
        # 测试随机数据（熵值应该接近 8）
        import random
        random_data = bytes([random.randint(0, 255) for _ in range(10000)])
        entropy = worker._calculate_entropy(random_data)
        assert 7.0 < entropy < 8.0
        
        # 测试空数据
        empty_data = b''
        entropy = worker._calculate_entropy(empty_data)
        assert entropy == 0.0
    
    def test_parse_request(self):
        """测试请求解析"""
        request_dict = {
            "job_id": "test-job-1",
            "tool": "pe.fingerprint",
            "sample": {
                "sample_id": "sha256:abc123",
                "path": "/path/to/sample.exe"
            },
            "args": {"fast": True},
            "context": {
                "request_time_utc": "2024-01-01T00:00:00Z",
                "policy": {
                    "allow_dynamic": False,
                    "allow_network": False
                },
                "versions": {
                    "pefile": "2023.2.7",
                    "lief": "0.14.0"
                }
            }
        }
        
        request = parse_request(request_dict)
        
        assert request.job_id == "test-job-1"
        assert request.tool == "pe.fingerprint"
        assert request.sample.sample_id == "sha256:abc123"
        assert request.sample.path == "/path/to/sample.exe"
        assert request.args["fast"] is True
        assert request.context.policy.allow_dynamic is False
    
    def test_unknown_tool(self):
        """测试未知工具处理"""
        worker = StaticWorker()
        
        request = WorkerRequest(
            job_id="test-job-3",
            tool="unknown.tool",
            sample=SampleInfo(
                sample_id="sha256:test",
                path="test_sample.exe"
            ),
            args={},
            context=WorkerContext(
                request_time_utc="2024-01-01T00:00:00Z",
                policy=PolicyContext(
                    allow_dynamic=False,
                    allow_network=False
                ),
                versions={}
            )
        )
        
        response = worker.execute(request)
        
        assert response.ok is False
        assert len(response.errors) > 0
        assert "Unknown tool" in response.errors[0]


if __name__ == "__main__":
    # 运行测试
    pytest.main([__file__, "-v"])
