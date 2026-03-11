"""
Integration tests for Static Worker stdin/stdout communication
"""

import json
import subprocess
import sys
import os


def test_worker_communication():
    """测试 Worker 与 Node.js 的进程间通信"""
    
    # 准备测试请求
    request = {
        "job_id": "test-job-123",
        "tool": "unknown.tool",  # 使用未知工具来测试错误处理
        "sample": {
            "sample_id": "sha256:test123",
            "path": "/path/to/test.exe"
        },
        "args": {},
        "context": {
            "request_time_utc": "2024-01-01T00:00:00Z",
            "policy": {
                "allow_dynamic": False,
                "allow_network": False
            },
            "versions": {
                "pefile": "2023.2.7"
            }
        }
    }
    
    # 启动 Worker 进程
    worker_path = os.path.join(os.path.dirname(__file__), "static_worker.py")
    process = subprocess.Popen(
        [sys.executable, worker_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # 发送请求
    request_json = json.dumps(request) + "\n"
    stdout, stderr = process.communicate(input=request_json, timeout=5)
    
    # 解析响应
    response = json.loads(stdout.strip())
    
    # 验证响应
    assert response["job_id"] == "test-job-123"
    assert response["ok"] is False
    assert len(response["errors"]) == 1
    assert "Unknown tool" in response["errors"][0]
    
    print("✓ Worker communication test passed")


def test_worker_multiple_requests():
    """测试 Worker 处理多个请求"""
    
    # 准备多个测试请求
    requests = [
        {
            "job_id": f"test-job-{i}",
            "tool": "unknown.tool",
            "sample": {
                "sample_id": f"sha256:test{i}",
                "path": f"/path/to/test{i}.exe"
            },
            "args": {},
            "context": {
                "request_time_utc": "2024-01-01T00:00:00Z",
                "policy": {
                    "allow_dynamic": False,
                    "allow_network": False
                },
                "versions": {
                    "pefile": "2023.2.7"
                }
            }
        }
        for i in range(3)
    ]
    
    # 启动 Worker 进程
    worker_path = os.path.join(os.path.dirname(__file__), "static_worker.py")
    process = subprocess.Popen(
        [sys.executable, worker_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # 发送所有请求
    input_data = "\n".join(json.dumps(req) for req in requests) + "\n"
    stdout, stderr = process.communicate(input=input_data, timeout=5)
    
    # 解析所有响应
    responses = [json.loads(line) for line in stdout.strip().split("\n") if line]
    
    # 验证响应数量
    assert len(responses) == 3
    
    # 验证每个响应
    for i, response in enumerate(responses):
        assert response["job_id"] == f"test-job-{i}"
        assert response["ok"] is False
        assert "Unknown tool" in response["errors"][0]
    
    print("✓ Multiple requests test passed")


def test_worker_invalid_json():
    """测试 Worker 处理无效 JSON"""
    
    # 启动 Worker 进程
    worker_path = os.path.join(os.path.dirname(__file__), "static_worker.py")
    process = subprocess.Popen(
        [sys.executable, worker_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # 发送无效 JSON
    invalid_json = "this is not valid json\n"
    stdout, stderr = process.communicate(input=invalid_json, timeout=5)
    
    # 解析响应
    response = json.loads(stdout.strip())
    
    # 验证错误响应
    assert response["ok"] is False
    assert len(response["errors"]) == 1
    assert "JSON decode error" in response["errors"][0]
    
    print("✓ Invalid JSON test passed")


def test_worker_missing_field():
    """测试 Worker 处理缺少必需字段的请求"""
    
    # 准备缺少字段的请求
    request = {
        "job_id": "test-job-123",
        "tool": "pe.fingerprint",
        # 缺少 sample 字段
        "args": {},
        "context": {
            "request_time_utc": "2024-01-01T00:00:00Z",
            "policy": {
                "allow_dynamic": False,
                "allow_network": False
            },
            "versions": {}
        }
    }
    
    # 启动 Worker 进程
    worker_path = os.path.join(os.path.dirname(__file__), "static_worker.py")
    process = subprocess.Popen(
        [sys.executable, worker_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # 发送请求
    request_json = json.dumps(request) + "\n"
    stdout, stderr = process.communicate(input=request_json, timeout=5)
    
    # 解析响应
    response = json.loads(stdout.strip())
    
    # 验证错误响应
    assert response["job_id"] == "test-job-123"
    assert response["ok"] is False
    assert len(response["errors"]) == 1
    assert "Missing required field" in response["errors"][0]
    
    print("✓ Missing field test passed")


if __name__ == "__main__":
    print("Running integration tests...")
    test_worker_communication()
    test_worker_multiple_requests()
    test_worker_invalid_json()
    test_worker_missing_field()
    print("\n✓ All integration tests passed!")
