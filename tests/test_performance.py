"""
Tests for Atomic Red Team runner and Load testing framework.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime

from tests.atomic_runner import (
    AtomicRedTeamRunner,
    AtomicTest,
    TestResult,
    TestStatus,
    TechniqueStatus,
    TechniqueCoverage,
    COMMON_ATOMIC_TESTS,
)


class TestAtomicTestModels:
    """Test Atomic Red Team data models."""

    def test_atomic_test_creation(self):
        test = AtomicTest(
            test_id="T1110.001-1",
            name="Password Guessing",
            description="Simulate brute force",
            technique_id="T1110.001",
            executor="command_prompt",
            supported_platforms=["windows"],
            commands=["net use \\\\127.0.0.1 /user:admin wrong"],
        )
        assert test.test_id == "T1110.001-1"
        assert test.technique_id == "T1110.001"
        assert len(test.commands) == 1

    def test_test_result_creation(self):
        result = TestResult(
            test_id="T1110.001-1",
            technique_id="T1110",
            status=TestStatus.PASSED,
            alert_detected=True,
            alert_id="alert-123",
        )
        assert result.status == TestStatus.PASSED
        assert result.alert_detected is True

    def test_test_result_with_times(self):
        result = TestResult(
            test_id="T1110.001-1",
            technique_id="T1110",
            status=TestStatus.PASSED,
            detection_time_ms=500.0,
            response_time_ms=1000.0,
        )
        assert result.detection_time_ms == 500.0
        assert result.response_time_ms == 1000.0

    def test_technique_coverage(self):
        coverage = TechniqueCoverage(
            technique_id="T1110",
            technique_name="Brute Force",
            status=TechniqueStatus.FULLY_COVERED,
            tests_executed=1,
            tests_passed=1,
            alerts_detected=1,
        )
        assert coverage.status == TechniqueStatus.FULLY_COVERED
        assert coverage.alerts_detected == 1

    def test_common_atomic_tests_loaded(self):
        assert len(COMMON_ATOMIC_TESTS) > 0
        assert "T1110" in COMMON_ATOMIC_TESTS
        assert "T1059" in COMMON_ATOMIC_TESTS

    def test_atomic_test_has_required_fields(self):
        for technique_id, tests in COMMON_ATOMIC_TESTS.items():
            for test in tests:
                assert test.test_id
                assert test.name
                assert test.technique_id
                assert test.commands or test.cleanup_commands


class TestAtomicRedTeamRunner:
    """Test Atomic Red Team runner."""

    @pytest.mark.asyncio
    async def test_runner_initialization(self):
        runner = AtomicRedTeamRunner(
            cobalto_api_url="http://localhost:8000",
        )
        assert runner.cobalto_api_url == "http://localhost:8000"
        assert runner._results == []

    @pytest.mark.asyncio
    async def test_generate_synthetic_alert(self):
        runner = AtomicRedTeamRunner()
        test = COMMON_ATOMIC_TESTS["T1110"][0]
        alert = runner._generate_synthetic_alert(test)

        assert "alert_id" in alert
        assert alert["source"] == "wazuh"
        assert "rule" in alert
        assert alert["rule"]["mitre"]["technique"] == test.technique_id

    def test_get_tactic_for_technique(self):
        runner = AtomicRedTeamRunner()
        assert runner._get_tactic_for_technique("T1110") == "credential-access"
        assert runner._get_tactic_for_technique("T1059") == "execution"
        assert runner._get_tactic_for_technique("T1547") == "persistence"

    def test_get_technique_name(self):
        runner = AtomicRedTeamRunner()
        assert runner._get_technique_name("T1110") == "Brute Force"
        assert runner._get_technique_name("T1059") == "Command and Scripting Interpreter"

    @pytest.mark.asyncio
    async def test_run_technique_test_simulate(self):
        runner = AtomicRedTeamRunner(
            cobalto_api_url="http://localhost:8000",
        )
        test = COMMON_ATOMIC_TESTS["T1110"][0]

        # Mock HTTP client
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"alert_id": "test-alert"}
            mock_response.raise_for_status = AsyncMock()
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response

            result = await runner.run_technique_test(
                "T1110",
                test,
                simulate=True,
            )

            assert result.test_id == test.test_id
            assert result.technique_id == "T1110"

    @pytest.mark.asyncio
    async def test_run_technique_suite(self):
        runner = AtomicRedTeamRunner(
            cobalto_api_url="http://localhost:8000",
        )

        with patch.object(runner, "run_technique_test") as mock_run:
            mock_run.return_value = TestResult(
                test_id="test",
                technique_id="T1110",
                status=TestStatus.PASSED,
            )

            results = await runner.run_technique_suite("T1110", simulate=True)
            assert len(results) == len(COMMON_ATOMIC_TESTS["T1110"])

    def test_calculate_coverage(self):
        runner = AtomicRedTeamRunner()
        results = [
            TestResult(
                test_id="T1110-1",
                technique_id="T1110",
                status=TestStatus.PASSED,
                alert_detected=True,
                detection_time_ms=500.0,
                response_time_ms=1000.0,
            ),
            TestResult(
                test_id="T1059-1",
                technique_id="T1059",
                status=TestStatus.FAILED,
                alert_detected=False,
            ),
        ]

        coverage = runner._calculate_coverage(results)
        assert len(coverage) == 2

        t1110_coverage = next(c for c in coverage if c.technique_id == "T1110")
        assert t1110_coverage.status == TechniqueStatus.FULLY_COVERED
        assert t1110_coverage.alerts_detected == 1

        t1059_coverage = next(c for c in coverage if c.technique_id == "T1059")
        assert t1059_coverage.status == TechniqueStatus.NOT_DETECTED

    def test_get_coverage_report(self):
        runner = AtomicRedTeamRunner()
        runner._results = [
            TestResult(
                test_id="T1110-1",
                technique_id="T1110",
                status=TestStatus.PASSED,
                alert_detected=True,
            ),
        ]

        report = runner.get_coverage_report()
        assert "timestamp" in report
        assert "total_techniques" in report
        assert report["total_techniques"] == 1


class TestLoadTestModels:
    """Test load test data models."""

    def test_alert_template_creation(self):
        from tests.load.load_test import AlertTemplate, AlertSeverity

        template = AlertTemplate(
            rule_id=5712,
            rule_level=8,
            rule_description="Test alert",
            rule_groups="test",
            severity=AlertSeverity.HIGH,
        )
        assert template.rule_id == 5712
        assert template.severity == AlertSeverity.HIGH

    def test_load_test_config(self):
        from tests.load.load_test import LoadTestConfig

        config = LoadTestConfig(
            target_rps=10000,
            duration_seconds=300,
            concurrent_users=50,
        )
        assert config.target_rps == 10000
        assert config.duration_seconds == 300

    def test_alert_metrics_creation(self):
        from tests.load.load_test import AlertMetrics

        metrics = AlertMetrics(
            alert_id="test-alert",
            sent_at=1000.0,
            received_at=1000.5,
            triage_completed_at=1001.0,
            response_completed_at=1002.0,
        )
        assert metrics.total_time_ms == 2000.0
        assert metrics.detection_time_ms == 1000.0
        assert metrics.response_time_ms == 1000.0

    def test_load_test_result_metrics(self):
        from tests.load.load_test import LoadTestResult, LoadTestConfig, LoadTestStatus

        result = LoadTestResult(
            test_id="test",
            status=LoadTestStatus.COMPLETED,
            config=LoadTestConfig(),
            started_at=1000.0,
            completed_at=1100.0,
            total_alerts_sent=100,
            total_alerts_received=99,
            total_alerts_processed=98,
        )
        assert result.duration_seconds == 100.0
        assert result.actual_rps == 1.0
        assert result.success_rate == 99.0


class TestLoadTestGenerator:
    """Test load test generator."""

    def test_generator_initialization(self):
        from tests.load.load_test import LoadTestGenerator

        generator = LoadTestGenerator(
            cobalto_api_url="http://localhost:8000",
        )
        assert generator.cobalto_api_url == "http://localhost:8000"

    def test_generate_alert(self):
        from tests.load.load_test import LoadTestGenerator

        generator = LoadTestGenerator()
        alert = generator._generate_alert(1)

        assert "alert_id" in alert
        assert alert["alert_id"] == "load-test-1"
        assert "rule" in alert
        assert "network" in alert
        assert "src_ip" in alert["network"]


class TestPerformanceAnalyzer:
    """Test performance analyzer."""

    def test_analyze_results(self):
        from tests.load.load_test import (
            LoadTestResult,
            LoadTestConfig,
            LoadTestStatus,
            AlertMetrics,
            PerformanceAnalyzer,
        )

        result = LoadTestResult(
            test_id="test",
            status=LoadTestStatus.COMPLETED,
            config=LoadTestConfig(),
            started_at=1000.0,
            completed_at=1100.0,
            total_alerts_sent=100,
            total_alerts_received=100,
            total_alerts_processed=98,
            total_errors=2,
            alert_metrics=[
                AlertMetrics(
                    alert_id=f"alert-{i}",
                    sent_at=1000.0 + i,
                    received_at=1000.5 + i,
                    triage_completed_at=1001.0 + i,
                    response_completed_at=1002.0 + i,
                )
                for i in range(100)
            ],
        )

        analyzer = PerformanceAnalyzer()
        analysis = analyzer.analyze(result)

        assert "summary" in analysis
        assert "latency" in analysis
        assert "sla" in analysis
        assert analysis["summary"]["total_alerts"] == 100
        assert analysis["errors"]["total_errors"] == 2

    def test_generate_recommendations(self):
        from tests.load.load_test import (
            LoadTestResult,
            LoadTestConfig,
            LoadTestStatus,
            PerformanceAnalyzer,
        )

        # Test with high MTTR
        result = LoadTestResult(
            test_id="test",
            status=LoadTestStatus.COMPLETED,
            config=LoadTestConfig(target_rps=10000),
            started_at=1000.0,
            completed_at=1100.0,
            total_alerts_sent=100,
            total_alerts_received=100,
        )
        result._results = []  # Empty metrics will result in 0 MTTR

        analyzer = PerformanceAnalyzer()
        recommendations = analyzer._generate_recommendations(result)
        assert isinstance(recommendations, list)
