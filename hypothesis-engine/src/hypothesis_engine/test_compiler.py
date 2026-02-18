from hypothesis_engine.compiler import (
    CompilationResult,
    TestParameter,
    TestSpecification,
    build_compilation_prompt,
    parse_test_specifications,
)
from hypothesis_engine.generator import Hypothesis


def sample_hypothesis() -> Hypothesis:
    return Hypothesis(
        condition="IF login endpoint uses string concatenation for SQL",
        vulnerability_class="SQL Injection",
        reasoning="BECAUSE no parameterized queries observed",
        test_approach="CAN BE TESTED BY sending SQL payloads in username field",
        confidence=0.8,
    )


class TestBuildCompilationPrompt:
    def test_contains_condition(self) -> None:
        h = sample_hypothesis()
        prompt = build_compilation_prompt(h)
        assert h.condition in prompt

    def test_contains_vulnerability_class(self) -> None:
        h = sample_hypothesis()
        prompt = build_compilation_prompt(h)
        assert "SQL Injection" in prompt

    def test_contains_confidence(self) -> None:
        h = sample_hypothesis()
        prompt = build_compilation_prompt(h)
        assert "0.8" in prompt


class TestParseTestSpecifications:
    def test_parse_valid_spec(self) -> None:
        h = sample_hypothesis()
        response = """[{
            "target_endpoint": "/api/login",
            "http_method": "POST",
            "parameters": [{"name": "username", "value": "admin' OR 1=1--", "location": "body"}],
            "payload_patterns": ["' OR 1=1--", "' UNION SELECT"],
            "expected_anomalies": [{"anomaly_type": "content", "description": "SQL error in response"}],
            "priority": 0.9
        }]"""
        specs = parse_test_specifications(response, h)
        assert len(specs) == 1
        assert specs[0].target_endpoint == "/api/login"
        assert specs[0].http_method == "POST"
        assert len(specs[0].parameters) == 1
        assert specs[0].parameters[0].name == "username"

    def test_parse_empty_response(self) -> None:
        h = sample_hypothesis()
        specs = parse_test_specifications("", h)
        assert specs == []

    def test_parse_invalid_json(self) -> None:
        h = sample_hypothesis()
        specs = parse_test_specifications("not json", h)
        assert specs == []

    def test_parse_single_object_without_array(self) -> None:
        h = sample_hypothesis()
        response = '{"target_endpoint": "/test", "http_method": "GET"}'
        specs = parse_test_specifications(response, h)
        assert len(specs) == 1
        assert specs[0].target_endpoint == "/test"

    def test_default_method_is_get(self) -> None:
        h = sample_hypothesis()
        response = '[{"target_endpoint": "/api"}]'
        specs = parse_test_specifications(response, h)
        assert len(specs) == 1
        assert specs[0].http_method == "GET"

    def test_default_priority_from_hypothesis(self) -> None:
        h = sample_hypothesis()
        response = '[{"target_endpoint": "/api"}]'
        specs = parse_test_specifications(response, h)
        assert specs[0].priority == h.confidence

    def test_parse_with_surrounding_text(self) -> None:
        h = sample_hypothesis()
        response = 'Here is the spec:\n[{"target_endpoint": "/login", "http_method": "POST"}]\nDone.'
        specs = parse_test_specifications(response, h)
        assert len(specs) == 1

    def test_hypothesis_condition_preserved(self) -> None:
        h = sample_hypothesis()
        response = '[{"target_endpoint": "/api"}]'
        specs = parse_test_specifications(response, h)
        assert specs[0].hypothesis_condition == h.condition


class TestTestSpecificationModel:
    def test_default_values(self) -> None:
        spec = TestSpecification(
            hypothesis_condition="IF x",
            target_endpoint="/test",
        )
        assert spec.http_method == "GET"
        assert spec.parameters == []
        assert spec.payload_patterns == []
        assert spec.priority == 0.5

    def test_test_parameter_model(self) -> None:
        param = TestParameter(name="id", value="1", location="query")
        assert param.location == "query"

    def test_default_parameter_location(self) -> None:
        param = TestParameter(name="data", value="test")
        assert param.location == "body"


class TestCompilationResult:
    def test_compilation_result_model(self) -> None:
        result = CompilationResult(
            specifications=[],
            compilation_time_ms=100.0,
            failed_compilations=0,
        )
        assert result.failed_compilations == 0
        assert result.compilation_time_ms == 100.0
