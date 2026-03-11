"""
Unit tests for Static Worker base framework
"""

import json
import sys
import os
import pytest
from io import StringIO
from datetime import datetime

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import (
    StaticWorker,
    WorkerRequest,
    WorkerResponse,
    SampleInfo,
    PolicyContext,
    WorkerContext,
    ArtifactRef,
    parse_request,
    response_to_dict,
)


class TestDataClasses:
    """测试数据类"""

    def test_sample_info_creation(self):
        """测试 SampleInfo 创建"""
        sample = SampleInfo(
            sample_id="sha256:abc123",
            path="/path/to/sample.exe"
        )
        assert sample.sample_id == "sha256:abc123"
        assert sample.path == "/path/to/sample.exe"

    def test_policy_context_creation(self):
        """测试 PolicyContext 创建"""
        policy = PolicyContext(
            allow_dynamic=False,
            allow_network=False
        )
        assert policy.allow_dynamic is False
        assert policy.allow_network is False

    def test_worker_context_creation(self):
        """测试 WorkerContext 创建"""
        policy = PolicyContext(allow_dynamic=False, allow_network=False)
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7", "lief": "0.14.0"}
        )
        assert context.request_time_utc == "2024-01-01T00:00:00Z"
        assert context.policy.allow_dynamic is False
        assert context.versions["pefile"] == "2023.2.7"

    def test_worker_request_creation(self):
        """测试 WorkerRequest 创建"""
        sample = SampleInfo(sample_id="sha256:abc123", path="/path/to/sample.exe")
        policy = PolicyContext(allow_dynamic=False, allow_network=False)
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-123",
            tool="pe.fingerprint",
            sample=sample,
            args={"fast": True},
            context=context
        )
        
        assert request.job_id == "job-123"
        assert request.tool == "pe.fingerprint"
        assert request.sample.sample_id == "sha256:abc123"
        assert request.args["fast"] is True

    def test_worker_response_creation(self):
        """测试 WorkerResponse 创建"""
        response = WorkerResponse(
            job_id="job-123",
            ok=True,
            warnings=["warning1"],
            errors=[],
            data={"result": "success"},
            artifacts=[],
            metrics={"elapsed_ms": 100}
        )
        
        assert response.job_id == "job-123"
        assert response.ok is True
        assert len(response.warnings) == 1
        assert len(response.errors) == 0
        assert response.data["result"] == "success"
        assert response.metrics["elapsed_ms"] == 100

    def test_artifact_ref_creation(self):
        """测试 ArtifactRef 创建"""
        artifact = ArtifactRef(
            id="artifact-123",
            type="json",
            path="/path/to/artifact.json",
            sha256="def456",
            mime="application/json"
        )
        
        assert artifact.id == "artifact-123"
        assert artifact.type == "json"
        assert artifact.path == "/path/to/artifact.json"
        assert artifact.sha256 == "def456"
        assert artifact.mime == "application/json"


class TestStaticWorker:
    """测试 StaticWorker 类"""

    def test_worker_initialization(self):
        """测试 Worker 初始化"""
        worker = StaticWorker()
        assert worker.tool_handlers is not None
        assert isinstance(worker.tool_handlers, dict)

    def test_execute_unknown_tool(self):
        """测试执行未知工具"""
        worker = StaticWorker()
        
        sample = SampleInfo(sample_id="sha256:abc123", path="/path/to/sample.exe")
        policy = PolicyContext(allow_dynamic=False, allow_network=False)
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-123",
            tool="unknown.tool",
            sample=sample,
            args={},
            context=context
        )
        
        response = worker.execute(request)
        
        assert response.ok is False
        assert len(response.errors) == 1
        assert "Unknown tool" in response.errors[0]
        assert response.job_id == "job-123"

    def test_execute_with_exception(self):
        """测试执行时发生异常"""
        worker = StaticWorker()
        
        # 添加一个会抛出异常的处理器
        def failing_handler(sample_path, args):
            raise ValueError("Test error")
        
        worker.tool_handlers["test.tool"] = failing_handler
        
        sample = SampleInfo(sample_id="sha256:abc123", path="/path/to/sample.exe")
        policy = PolicyContext(allow_dynamic=False, allow_network=False)
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-123",
            tool="test.tool",
            sample=sample,
            args={},
            context=context
        )
        
        response = worker.execute(request)
        
        assert response.ok is False
        assert len(response.errors) == 1
        assert "Test error" in response.errors[0]
        assert response.job_id == "job-123"
        assert "elapsed_ms" in response.metrics

    def test_execute_successful(self):
        """测试成功执行"""
        worker = StaticWorker()
        
        # 添加一个成功的处理器
        def success_handler(sample_path, args):
            return {"result": "success", "path": sample_path}
        
        worker.tool_handlers["test.tool"] = success_handler
        
        sample = SampleInfo(sample_id="sha256:abc123", path="/path/to/sample.exe")
        policy = PolicyContext(allow_dynamic=False, allow_network=False)
        context = WorkerContext(
            request_time_utc="2024-01-01T00:00:00Z",
            policy=policy,
            versions={"pefile": "2023.2.7"}
        )
        
        request = WorkerRequest(
            job_id="job-123",
            tool="test.tool",
            sample=sample,
            args={"param": "value"},
            context=context
        )
        
        response = worker.execute(request)
        
        assert response.ok is True
        assert len(response.errors) == 0
        assert response.data["result"] == "success"
        assert response.data["path"] == "/path/to/sample.exe"
        assert response.job_id == "job-123"
        assert "elapsed_ms" in response.metrics
        assert response.metrics["tool"] == "test.tool"


class TestRequestParsing:
    """测试请求解析"""

    def test_parse_request_valid(self):
        """测试解析有效请求"""
        request_dict = {
            "job_id": "job-123",
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
        
        assert request.job_id == "job-123"
        assert request.tool == "pe.fingerprint"
        assert request.sample.sample_id == "sha256:abc123"
        assert request.sample.path == "/path/to/sample.exe"
        assert request.args["fast"] is True
        assert request.context.request_time_utc == "2024-01-01T00:00:00Z"
        assert request.context.policy.allow_dynamic is False
        assert request.context.policy.allow_network is False
        assert request.context.versions["pefile"] == "2023.2.7"

    def test_parse_request_missing_field(self):
        """测试解析缺少字段的请求"""
        request_dict = {
            "job_id": "job-123",
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
        
        with pytest.raises(KeyError):
            parse_request(request_dict)


class TestResponseSerialization:
    """测试响应序列化"""

    def test_response_to_dict_basic(self):
        """测试基本响应转换为字典"""
        response = WorkerResponse(
            job_id="job-123",
            ok=True,
            warnings=[],
            errors=[],
            data={"result": "success"},
            artifacts=[],
            metrics={"elapsed_ms": 100}
        )
        
        response_dict = response_to_dict(response)
        
        assert response_dict["job_id"] == "job-123"
        assert response_dict["ok"] is True
        assert response_dict["warnings"] == []
        assert response_dict["errors"] == []
        assert response_dict["data"]["result"] == "success"
        assert response_dict["artifacts"] == []
        assert response_dict["metrics"]["elapsed_ms"] == 100

    def test_response_to_dict_with_artifacts(self):
        """测试包含产物的响应转换为字典"""
        artifact = ArtifactRef(
            id="artifact-123",
            type="json",
            path="/path/to/artifact.json",
            sha256="def456",
            mime="application/json"
        )
        
        response = WorkerResponse(
            job_id="job-123",
            ok=True,
            warnings=[],
            errors=[],
            data={"result": "success"},
            artifacts=[artifact],
            metrics={"elapsed_ms": 100}
        )
        
        response_dict = response_to_dict(response)
        
        assert len(response_dict["artifacts"]) == 1
        assert response_dict["artifacts"][0]["id"] == "artifact-123"
        assert response_dict["artifacts"][0]["type"] == "json"
        assert response_dict["artifacts"][0]["path"] == "/path/to/artifact.json"
        assert response_dict["artifacts"][0]["sha256"] == "def456"
        assert response_dict["artifacts"][0]["mime"] == "application/json"

    def test_response_to_dict_with_errors(self):
        """测试包含错误的响应转换为字典"""
        response = WorkerResponse(
            job_id="job-123",
            ok=False,
            warnings=["warning1"],
            errors=["error1", "error2"],
            data=None,
            artifacts=[],
            metrics={"elapsed_ms": 50}
        )
        
        response_dict = response_to_dict(response)
        
        assert response_dict["ok"] is False
        assert len(response_dict["warnings"]) == 1
        assert len(response_dict["errors"]) == 2
        assert response_dict["errors"][0] == "error1"
        assert response_dict["errors"][1] == "error2"
        assert response_dict["data"] is None


class TestJSONSerialization:
    """测试 JSON 序列化"""

    def test_json_round_trip(self):
        """测试 JSON 序列化和反序列化"""
        request_dict = {
            "job_id": "job-123",
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
                    "pefile": "2023.2.7"
                }
            }
        }
        
        # 序列化为 JSON
        json_str = json.dumps(request_dict)
        
        # 反序列化
        parsed_dict = json.loads(json_str)
        
        # 解析为 WorkerRequest
        request = parse_request(parsed_dict)
        
        assert request.job_id == "job-123"
        assert request.tool == "pe.fingerprint"
        assert request.args["fast"] is True

    def test_response_json_serialization(self):
        """测试响应 JSON 序列化"""
        response = WorkerResponse(
            job_id="job-123",
            ok=True,
            warnings=[],
            errors=[],
            data={"result": "success"},
            artifacts=[],
            metrics={"elapsed_ms": 100}
        )
        
        response_dict = response_to_dict(response)
        json_str = json.dumps(response_dict)
        
        # 验证可以反序列化
        parsed = json.loads(json_str)
        assert parsed["job_id"] == "job-123"
        assert parsed["ok"] is True
        assert parsed["data"]["result"] == "success"


class TestPEParsing:
    """测试 PE 解析功能（使用测试样本）"""

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
        pytest.skip("Test PE file (notepad.exe) not found")

    def test_pe_fingerprint_with_real_sample(self, worker, test_pe_path):
        """测试使用真实样本进行 PE 指纹提取"""
        result = worker.pe_fingerprint(test_pe_path, {"fast": True})
        
        # 验证基本字段
        assert "machine" in result
        assert "subsystem" in result
        assert "timestamp" in result
        assert "entry_point" in result
        assert "imphash" in result
        
        # 验证机器类型
        assert result["machine"] in [0x14c, 0x8664]  # x86 or x64
        
        # 验证子系统
        assert result["subsystem"] in [2, 3]  # GUI or CUI
        
        print(f"\nPE Fingerprint Result:")
        print(f"  Machine: {result.get('machine_name', 'Unknown')}")
        print(f"  Subsystem: {result.get('subsystem_name', 'Unknown')}")
        print(f"  Imphash: {result['imphash']}")

    def test_pe_fingerprint_full_mode(self, worker, test_pe_path):
        """测试完整模式 PE 指纹提取（包含节区熵值）"""
        result = worker.pe_fingerprint(test_pe_path, {"fast": False})
        
        # 验证完整模式额外字段
        assert "sections" in result
        assert isinstance(result["sections"], list)
        assert len(result["sections"]) > 0
        
        # 验证节区信息
        for section in result["sections"]:
            assert "name" in section
            assert "entropy" in section
            assert "virtual_size" in section
            assert "raw_size" in section
            
            # 熵值应该在 0-8 之间
            assert 0 <= section["entropy"] <= 8
        
        print(f"\nSection Entropy Analysis:")
        for section in result["sections"]:
            print(f"  {section['name']}: entropy={section['entropy']:.2f}")

    def test_pe_imports_extraction(self, worker, test_pe_path):
        """测试导入表提取"""
        result = worker.pe_imports_extract(test_pe_path, {"group_by_dll": True})
        
        # 验证结果结构
        assert "imports" in result
        assert isinstance(result["imports"], dict)
        assert len(result["imports"]) > 0
        
        # 验证常见系统 DLL
        common_dlls = ["kernel32.dll", "user32.dll", "gdi32.dll"]
        found_dlls = [dll.lower() for dll in result["imports"].keys()]
        
        # 至少应该找到一个常见 DLL
        assert any(dll in found_dlls for dll in common_dlls)
        
        print(f"\nImported DLLs: {len(result['imports'])}")
        for dll in list(result["imports"].keys())[:5]:
            print(f"  {dll}: {len(result['imports'][dll])} functions")

    def test_pe_exports_extraction(self, worker, test_pe_path):
        """测试导出表提取"""
        result = worker.pe_exports_extract(test_pe_path, {})
        
        # 验证结果结构
        assert "exports" in result
        assert isinstance(result["exports"], list)
        
        # notepad.exe 可能没有导出函数，这是正常的
        print(f"\nExported functions: {len(result['exports'])}")
        
        if len(result["exports"]) > 0:
            # 如果有导出，验证结构
            for export in result["exports"][:5]:
                assert "name" in export or "ordinal" in export
                assert "address" in export

    def test_pe_parsing_with_corrupted_file(self, worker):
        """测试损坏的 PE 文件错误处理"""
        import tempfile
        
        # 创建一个损坏的 PE 文件
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            # 写入无效的 PE 头
            f.write(b'MZ\x00\x00' + b'\x00' * 100)
            temp_path = f.name
        
        try:
            # 尝试解析损坏的文件
            with pytest.raises(Exception):
                worker.pe_fingerprint(temp_path, {"fast": True})
            
            print("\nCorrupted PE file correctly rejected")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_pe_parsing_with_nonexistent_file(self, worker):
        """测试不存在的文件错误处理"""
        with pytest.raises(Exception):
            worker.pe_fingerprint("/nonexistent/file.exe", {"fast": True})


class TestStringExtraction:
    """测试字符串提取功能"""

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
        pytest.skip("Test PE file (notepad.exe) not found")

    def test_strings_extract_ascii(self, worker, test_pe_path):
        """测试 ASCII 字符串提取"""
        result = worker.strings_extract(test_pe_path, {
            "min_len": 4,
            "encoding": "ascii"
        })
        
        # 验证结果结构
        assert "strings" in result
        assert "count" in result
        assert "min_len" in result
        assert result["min_len"] == 4
        
        # 应该提取到一些字符串
        assert result["count"] > 0
        assert len(result["strings"]) > 0
        
        # 验证字符串结构
        for s in result["strings"][:5]:
            assert "string" in s
            assert "offset" in s
            assert "encoding" in s
            assert len(s["string"]) >= 4
        
        print(f"\nExtracted {result['count']} ASCII strings")
        print(f"Sample strings: {[s['string'] for s in result['strings'][:5]]}")

    def test_strings_extract_unicode(self, worker, test_pe_path):
        """测试 Unicode 字符串提取"""
        result = worker.strings_extract(test_pe_path, {
            "min_len": 4,
            "encoding": "unicode"
        })
        
        # 验证结果
        assert "strings" in result
        assert result["encoding_filter"] == "unicode"
        
        # 应该提取到一些 Unicode 字符串
        if result["count"] > 0:
            print(f"\nExtracted {result['count']} Unicode strings")
            print(f"Sample strings: {[s['string'] for s in result['strings'][:5]]}")

    def test_strings_extract_all_encodings(self, worker, test_pe_path):
        """测试提取所有编码的字符串"""
        result = worker.strings_extract(test_pe_path, {
            "min_len": 4,
            "encoding": "all"
        })
        
        # 验证结果
        assert "strings" in result
        assert result["encoding_filter"] == "all"
        assert result["count"] > 0
        
        # 应该有多种编码
        encodings = set(s["encoding"] for s in result["strings"])
        print(f"\nFound encodings: {encodings}")
        print(f"Total strings: {result['count']}")

    def test_strings_min_len_parameter(self, worker):
        """测试 min_len 参数"""
        import tempfile
        
        # 创建测试文件
        content = b'Hi\x00Test\x00LongerString\x00'
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(content)
            temp_path = f.name
        
        try:
            result = worker.strings_extract(temp_path, {
                "min_len": 4,
                "encoding": "ascii"
            })
            
            # 'Hi' (长度 2) 不应该被提取
            string_values = [s["string"] for s in result["strings"]]
            assert "Hi" not in string_values
            
            # 'Test' (长度 4) 应该被提取
            assert "Test" in string_values or "LongerString" in string_values
            
            print(f"\nmin_len=4 filter working correctly")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_strings_invalid_parameters(self, worker):
        """测试无效参数处理"""
        import tempfile
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(b'Test')
            temp_path = f.name
        
        try:
            # 测试无效的 min_len
            with pytest.raises(ValueError, match="min_len must be at least 1"):
                worker.strings_extract(temp_path, {"min_len": 0})
            
            # 测试无效的 encoding
            with pytest.raises(ValueError, match="Invalid encoding"):
                worker.strings_extract(temp_path, {"encoding": "invalid"})
            
            print("\nInvalid parameters correctly rejected")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestYARAScan:
    """测试 YARA 扫描功能"""

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
        pytest.skip("Test PE file (notepad.exe) not found")

    def test_yara_scan_with_default_rules(self, worker, test_pe_path):
        """测试使用默认规则集进行 YARA 扫描"""
        try:
            result = worker.yara_scan(test_pe_path, {
                "rule_set": "default",
                "timeout_ms": 30000
            })
            
            # 验证结果结构
            assert "matches" in result
            assert "rule_set" in result
            assert "ruleset_version" in result
            assert isinstance(result["matches"], list)
            
            print(f"\nYARA scan completed")
            print(f"Rule set: {result['rule_set']}")
            print(f"Matches: {len(result['matches'])}")
            
            # 如果有匹配，验证匹配结构
            for match in result["matches"][:3]:
                assert "rule" in match
                assert "tags" in match
                assert "meta" in match
                print(f"  Matched rule: {match['rule']}")
        except RuntimeError as e:
            if "YARA is not available" in str(e):
                pytest.skip("YARA library not available")
            raise

    def test_yara_scan_with_packer_rules(self, worker, test_pe_path):
        """测试使用加壳器规则集进行 YARA 扫描"""
        try:
            result = worker.yara_scan(test_pe_path, {
                "rule_set": "packers",
                "timeout_ms": 30000
            })
            
            # 验证结果
            assert "matches" in result
            assert result["rule_set"] == "packers"
            
            print(f"\nPacker detection scan completed")
            print(f"Matches: {len(result['matches'])}")
            
            # notepad.exe 通常不会匹配加壳器规则
            if len(result["matches"]) == 0:
                print("  No packers detected (expected for notepad.exe)")
        except RuntimeError as e:
            if "YARA is not available" in str(e):
                pytest.skip("YARA library not available")
            raise

    def test_yara_scan_with_nonexistent_ruleset(self, worker, test_pe_path):
        """测试不存在的规则集错误处理"""
        try:
            with pytest.raises(RuntimeError, match="not found|YARA is not available"):
                worker.yara_scan(test_pe_path, {
                    "rule_set": "nonexistent_ruleset_12345",
                    "timeout_ms": 30000
                })
            
            print("\nNonexistent ruleset correctly rejected")
        except RuntimeError as e:
            if "YARA is not available" in str(e):
                pytest.skip("YARA library not available")
            raise

    def test_yara_scan_timeout(self, worker):
        """测试 YARA 扫描超时处理"""
        import tempfile
        
        # 创建一个大文件来测试超时
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            f.write(b'MZ' + b'\x00' * (10 * 1024 * 1024))  # 10MB
            temp_path = f.name
        
        try:
            # 使用很短的超时时间
            result = worker.yara_scan(temp_path, {
                "rule_set": "default",
                "timeout_ms": 1  # 1ms - 应该超时
            })
            
            # 即使超时，也应该返回结果（可能是部分结果）
            assert "matches" in result
            print("\nTimeout handling working correctly")
        except RuntimeError as e:
            if "YARA is not available" in str(e):
                pytest.skip("YARA library not available")
            # 超时也是可接受的结果
            print(f"\nTimeout occurred as expected: {str(e)}")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestErrorHandling:
    """测试错误处理功能"""

    @pytest.fixture
    def worker(self):
        """创建 Worker 实例"""
        return StaticWorker()

    def test_corrupted_pe_file_handling(self, worker):
        """测试损坏的 PE 文件错误处理"""
        import tempfile
        
        # 创建一个损坏的 PE 文件
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            # 只写入 MZ 头，但没有有效的 PE 结构
            f.write(b'MZ\x00\x00' + b'\x00' * 100)
            temp_path = f.name
        
        try:
            # 测试 PE 指纹提取
            with pytest.raises(Exception):
                worker.pe_fingerprint(temp_path, {"fast": True})
            
            # 测试导入表提取
            with pytest.raises(Exception):
                worker.pe_imports_extract(temp_path, {"group_by_dll": True})
            
            # 测试导出表提取
            with pytest.raises(Exception):
                worker.pe_exports_extract(temp_path, {})
            
            print("\nCorrupted PE file errors handled correctly")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_nonexistent_file_handling(self, worker):
        """测试不存在的文件错误处理"""
        nonexistent_path = "/nonexistent/path/to/file.exe"
        
        # 测试各种操作
        with pytest.raises(Exception):
            worker.pe_fingerprint(nonexistent_path, {"fast": True})
        
        with pytest.raises(Exception):
            worker.pe_imports_extract(nonexistent_path, {"group_by_dll": True})
        
        with pytest.raises(Exception):
            worker.strings_extract(nonexistent_path, {"min_len": 4})
        
        print("\nNonexistent file errors handled correctly")

    def test_invalid_file_format(self, worker):
        """测试无效文件格式错误处理"""
        import tempfile
        
        # 创建一个非 PE 文件
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as f:
            f.write(b'This is not a PE file\n')
            temp_path = f.name
        
        try:
            # 尝试解析非 PE 文件
            with pytest.raises(Exception):
                worker.pe_fingerprint(temp_path, {"fast": True})
            
            print("\nInvalid file format errors handled correctly")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_empty_file_handling(self, worker):
        """测试空文件错误处理"""
        import tempfile
        
        # 创建空文件
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            temp_path = f.name
        
        try:
            # 测试字符串提取（应该返回空结果）
            result = worker.strings_extract(temp_path, {"min_len": 4})
            assert result["count"] == 0
            assert len(result["strings"]) == 0
            
            # 测试 PE 解析（应该失败）
            with pytest.raises(Exception):
                worker.pe_fingerprint(temp_path, {"fast": True})
            
            print("\nEmpty file errors handled correctly")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_execute_with_invalid_tool(self, worker):
        """测试执行无效工具"""
        request = WorkerRequest(
            job_id="test-invalid-tool",
            tool="invalid.tool.name",
            sample=SampleInfo(
                sample_id="sha256:test",
                path="/path/to/sample.exe"
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
        
        # 应该返回错误
        assert response.ok is False
        assert len(response.errors) > 0
        assert "Unknown tool" in response.errors[0]
        
        print("\nInvalid tool error handled correctly")

    def test_execute_with_exception(self, worker):
        """测试执行时发生异常"""
        # 添加一个会抛出异常的处理器
        def failing_handler(sample_path, args):
            raise ValueError("Simulated error for testing")
        
        worker.tool_handlers["test.failing"] = failing_handler
        
        request = WorkerRequest(
            job_id="test-exception",
            tool="test.failing",
            sample=SampleInfo(
                sample_id="sha256:test",
                path="/path/to/sample.exe"
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
        
        # 应该捕获异常并返回错误
        assert response.ok is False
        assert len(response.errors) > 0
        assert "Simulated error" in response.errors[0]
        assert "elapsed_ms" in response.metrics
        
        print("\nException during execution handled correctly")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
