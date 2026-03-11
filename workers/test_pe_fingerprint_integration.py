"""
集成测试 PE 指纹提取功能（使用真实 PE 文件）
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
    WorkerContext
)


class TestPEFingerprintIntegration:
    """集成测试 PE 指纹提取"""

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

    def test_pe_fingerprint_fast_mode_real_file(self, worker, test_pe_path):
        """测试快速模式 PE 指纹提取（真实文件）"""
        request = WorkerRequest(
            job_id="test-job-fast",
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
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert len(response.errors) == 0
        
        # 验证数据
        data = response.data
        assert data is not None
        assert "machine" in data
        assert "machine_name" in data
        assert "subsystem" in data
        assert "subsystem_name" in data
        assert "timestamp" in data
        assert "entry_point" in data
        assert "image_base" in data
        
        # 快速模式不应包含节区信息
        assert "sections" not in data
        
        # 打印结果以便调试
        print("\n=== Fast Mode Result ===")
        print(json.dumps(data, indent=2))

    def test_pe_fingerprint_full_mode_real_file(self, worker, test_pe_path):
        """测试完整模式 PE 指纹提取（真实文件）"""
        request = WorkerRequest(
            job_id="test-job-full",
            tool="pe.fingerprint",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
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
        
        response = worker.execute(request)
        
        # 验证响应
        assert response.ok is True
        assert len(response.errors) == 0
        
        # 验证数据
        data = response.data
        assert data is not None
        assert "machine" in data
        assert "subsystem" in data
        
        # 完整模式应包含节区信息
        assert "sections" in data
        assert isinstance(data["sections"], list)
        assert len(data["sections"]) > 0
        
        # 验证节区信息
        for section in data["sections"]:
            assert "name" in section
            assert "virtual_address" in section
            assert "entropy" in section
            assert 0.0 <= section["entropy"] <= 8.0
        
        # 应包含签名信息
        assert "signature" in data
        assert "present" in data["signature"]
        
        # 打印结果以便调试
        print("\n=== Full Mode Result ===")
        print(json.dumps(data, indent=2))

    def test_pe_fingerprint_imphash(self, worker, test_pe_path):
        """测试 Imphash 计算"""
        request = WorkerRequest(
            job_id="test-job-imphash",
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
        
        response = worker.execute(request)
        
        assert response.ok is True
        data = response.data
        
        # Imphash 应该存在（如果文件有导入表）
        if "imphash" in data and data["imphash"]:
            assert isinstance(data["imphash"], str)
            assert len(data["imphash"]) == 32  # MD5 哈希长度
            print(f"\nImphash: {data['imphash']}")

    def test_pe_fingerprint_section_entropy(self, worker, test_pe_path):
        """测试节区熵值计算"""
        request = WorkerRequest(
            job_id="test-job-entropy",
            tool="pe.fingerprint",
            sample=SampleInfo(
                sample_id="sha256:test",
                path=test_pe_path
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
        
        response = worker.execute(request)
        
        assert response.ok is True
        data = response.data
        
        # 验证节区熵值
        assert "sections" in data
        for section in data["sections"]:
            entropy = section["entropy"]
            assert 0.0 <= entropy <= 8.0
            
            # 打印节区信息
            print(f"\nSection: {section['name']}, Entropy: {entropy}")
            
            # .text 节区通常有较高的熵值（代码）
            # .data 节区熵值可能较低（数据）
            # .rsrc 节区熵值取决于资源内容


if __name__ == "__main__":
    # 运行测试
    pytest.main([__file__, "-v", "-s"])
