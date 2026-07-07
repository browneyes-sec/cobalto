"""
Load Testing Framework for Cobalto Platform.

Simulates high-volume alert ingestion to validate performance
and measure MTTR (Mean Time to Respond).
"""

import asyncio
import json
import random
import time
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import httpx
import structlog
from concurrent.futures import ThreadPoolExecutor

logger = structlog.get_logger(__name__)


class LoadTestStatus(str, Enum):
    """Load test status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AlertTemplate:
    """Template for generating test alerts."""
    rule_id: int
    rule_level: int
    rule_description: str
    rule_groups: str
    severity: AlertSeverity
    technique_id: Optional[str] = None
    tactic: Optional[str] = None


@dataclass
class LoadTestConfig:
    """Load test configuration."""
    target_rps: int = 10000  # Requests per hour (~2.8 RPS)
    duration_seconds: int = 300  # 5 minutes
    concurrent_users: int = 50
    ramp_up_seconds: int = 60
    think_time_ms: int = 100
    alert_templates: List[AlertTemplate] = field(default_factory=list)


@dataclass
class AlertMetrics:
    """Metrics for a single alert."""
    alert_id: str
    sent_at: float
    received_at: Optional[float] = None
    triage_completed_at: Optional[float] = None
    analysis_completed_at: Optional[float] = None
    response_completed_at: Optional[float] = None
    error: Optional[str] = None

    @property
    def total_time_ms(self) -> Optional[float]:
        """Total processing time in milliseconds."""
        if self.received_at and self.response_completed_at:
            return (self.response_completed_at - self.sent_at) * 1000
        return None

    @property
    def detection_time_ms(self) -> Optional[float]:
        """Detection time (sent to triage completed)."""
        if self.triage_completed_at:
            return (self.triage_completed_at - self.sent_at) * 1000
        return None

    @property
    def response_time_ms(self) -> Optional[float]:
        """Response time (triage to response completed)."""
        if self.triage_completed_at and self.response_completed_at:
            return (self.response_completed_at - self.triage_completed_at) * 1000
        return None


@dataclass
class LoadTestResult:
    """Result of a load test run."""
    test_id: str
    status: LoadTestStatus
    config: LoadTestConfig
    started_at: float
    completed_at: Optional[float] = None
    total_alerts_sent: int = 0
    total_alerts_received: int = 0
    total_alerts_processed: int = 0
    total_errors: int = 0
    alert_metrics: List[AlertMetrics] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Test duration in seconds."""
        if self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def actual_rps(self) -> float:
        """Actual requests per second."""
        if self.duration_seconds and self.duration_seconds > 0:
            return self.total_alerts_sent / self.duration_seconds
        return 0.0

    @property
    def success_rate(self) -> float:
        """Success rate as percentage."""
        if self.total_alerts_sent > 0:
            return (self.total_alerts_received / self.total_alerts_sent) * 100
        return 0.0

    @property
    def mttr_ms(self) -> Optional[float]:
        """Mean Time to Respond in milliseconds."""
        response_times = [
            m.total_time_ms for m in self.alert_metrics
            if m.total_time_ms is not None
        ]
        if response_times:
            return sum(response_times) / len(response_times)
        return None

    @property
    def p50_latency_ms(self) -> Optional[float]:
        """50th percentile latency."""
        return self._percentile(50)

    @property
    def p95_latency_ms(self) -> Optional[float]:
        """95th percentile latency."""
        return self._percentile(95)

    @property
    def p99_latency_ms(self) -> Optional[float]:
        """99th percentile latency."""
        return self._percentile(99)

    def _percentile(self, percentile: int) -> Optional[float]:
        """Calculate percentile latency."""
        response_times = sorted([
            m.total_time_ms for m in self.alert_metrics
            if m.total_time_ms is not None
        ])
        if response_times:
            index = int(len(response_times) * percentile / 100)
            return response_times[min(index, len(response_times) - 1)]
        return None


# =============================================================================
# Default Alert Templates
# =============================================================================

DEFAULT_ALERT_TEMPLATES = [
    AlertTemplate(
        rule_id=5712,
        rule_level=8,
        rule_description="Brute force attack detected",
        rule_groups="authentication_failures,brute_force",
        severity=AlertSeverity.HIGH,
        technique_id="T1110",
        tactic="credential-access",
    ),
    AlertTemplate(
        rule_id=5714,
        rule_level=7,
        rule_description="Malware detected by antivirus",
        rule_groups="malware,av_detection",
        severity=AlertSeverity.HIGH,
        technique_id="T1059",
        tactic="execution",
    ),
    AlertTemplate(
        rule_id=5716,
        rule_level=7,
        rule_description="Suspicious scheduled task created",
        rule_groups="windows,scheduled_task",
        severity=AlertSeverity.MEDIUM,
        technique_id="T1053",
        tactic="execution",
    ),
    AlertTemplate(
        rule_id=5718,
        rule_level=8,
        rule_description="Registry persistence mechanism detected",
        rule_groups="windows,persistence",
        severity=AlertSeverity.HIGH,
        technique_id="T1547",
        tactic="persistence",
    ),
    AlertTemplate(
        rule_id=5713,
        rule_level=6,
        rule_description="Suspicious outbound connection",
        rule_groups="network,suspicious_connection",
        severity=AlertSeverity.MEDIUM,
        technique_id="T1071",
        tactic="command-and-control",
    ),
    AlertTemplate(
        rule_id=5719,
        rule_level=9,
        rule_description="Ransomware behavior detected",
        rule_groups="ransomware,file_encryption",
        severity=AlertSeverity.CRITICAL,
        technique_id="T1486",
        tactic="impact",
    ),
    AlertTemplate(
        rule_id=5720,
        rule_level=8,
        rule_description="Lateral movement attempt detected",
        rule_groups="lateral_movement,smb",
        severity=AlertSeverity.HIGH,
        technique_id="T1021",
        tactic="lateral-movement",
    ),
    AlertTemplate(
        rule_id=5721,
        rule_level=5,
        rule_description="New service installed",
        rule_groups="windows,service_install",
        severity=AlertSeverity.LOW,
        technique_id="T1543",
        tactic="persistence",
    ),
]


class LoadTestGenerator:
    """Generates load for testing."""

    def __init__(
        self,
        cobalto_api_url: str = "http://localhost:8000",
        config: Optional[LoadTestConfig] = None,
    ):
        self.cobalto_api_url = cobalto_api_url
        self.config = config or LoadTestConfig(alert_templates=DEFAULT_ALERT_TEMPLATES)
        self._results: List[AlertMetrics] = []
        self._running = False

    def _generate_alert(self, alert_id: int) -> Dict[str, Any]:
        """Generate a test alert."""
        template = random.choice(self.config.alert_templates)
        timestamp = datetime.utcnow()

        # Generate random IP addresses
        src_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        dst_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        return {
            "alert_id": f"load-test-{alert_id}",
            "source": "wazuh",
            "timestamp": timestamp.isoformat(),
            "rule": {
                "id": template.rule_id,
                "level": template.rule_level,
                "description": template.rule_description,
                "groups": template.rule_groups,
                "mitre": {
                    "technique": template.technique_id,
                    "tactic": template.tactic,
                },
            },
            "agent": {
                "id": f"agent-{random.randint(1, 100)}",
                "name": f"host-{random.randint(1, 1000)}",
            },
            "network": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 445, 3389, 22]),
                "protocol": random.choice(["tcp", "udp"]),
            },
            "raw": {
                "log": f"Load test alert {alert_id}",
                "data": {
                    "template": template.rule_description,
                    "severity": template.severity.value,
                },
            },
        }

    async def _send_alert(
        self,
        alert_id: int,
        client: httpx.AsyncClient,
    ) -> AlertMetrics:
        """Send a single alert and measure timing."""
        alert = self._generate_alert(alert_id)
        metrics = AlertMetrics(
            alert_id=alert["alert_id"],
            sent_at=time.time(),
        )

        try:
            response = await client.post(
                f"{self.cobalto_api_url}/webhook/wazuh",
                json={
                    "alert_id": alert["alert_id"],
                    "alert": alert,
                    "source": "load-test",
                    "metadata": {"test_mode": True, "load_test": True},
                },
                timeout=30.0,
            )

            metrics.received_at = time.time()
            response.raise_for_status()

            # Simulate processing time based on severity
            severity = alert["rule"]["level"]
            processing_time = 0.1 + (severity * 0.05)  # 0.1s + 50ms per level
            await asyncio.sleep(processing_time)

            metrics.triage_completed_at = time.time()

            # Simulate analysis time
            analysis_time = 0.2 + (severity * 0.1)
            await asyncio.sleep(analysis_time)

            metrics.analysis_completed_at = time.time()

            # Simulate response time
            response_time = 0.1 + (severity * 0.05)
            await asyncio.sleep(response_time)

            metrics.response_completed_at = time.time()

        except Exception as e:
            metrics.error = str(e)
            metrics.received_at = time.time()

        return metrics

    async def _user_simulation(
        self,
        user_id: int,
        stop_event: asyncio.Event,
    ) -> List[AlertMetrics]:
        """Simulate a single user generating alerts."""
        metrics = []
        alert_counter = 0

        async with httpx.AsyncClient() as client:
            while not stop_event.is_set():
                alert_counter += 1
                metric = await self._send_alert(
                    user_id * 10000 + alert_counter,
                    client,
                )
                metrics.append(metric)

                # Think time
                await asyncio.sleep(self.config.think_time_ms / 1000)

        return metrics

    async def run(self) -> LoadTestResult:
        """Run the load test."""
        logger.info(
            "load_test_starting",
            target_rps=self.config.target_rps,
            duration=self.config.duration_seconds,
            concurrent_users=self.config.concurrent_users,
        )

        result = LoadTestResult(
            test_id=f"load-test-{int(time.time())}",
            status=LoadTestStatus.RUNNING,
            config=self.config,
            started_at=time.time(),
        )

        self._running = True
        stop_event = asyncio.Event()

        # Calculate alerts per user
        total_alerts = self.config.target_rps * (self.config.duration_seconds / 3600)
        alerts_per_user = int(total_alerts / self.config.concurrent_users)

        # Run user simulations
        async def run_user(user_id: int):
            metrics = await self._user_simulation(user_id, stop_event)
            result.alert_metrics.extend(metrics)

        # Create tasks with ramp-up
        tasks = []
        for i in range(self.config.concurrent_users):
            tasks.append(asyncio.create_task(run_user(i)))
            # Ramp up delay
            if i < self.config.concurrent_users:
                await asyncio.sleep(self.config.ramp_up_seconds / self.config.concurrent_users)

        # Wait for duration
        await asyncio.sleep(self.config.duration_seconds)

        # Stop all users
        stop_event.set()

        # Wait for all tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        # Calculate results
        result.total_alerts_sent = len(result.alert_metrics)
        result.total_alerts_received = sum(
            1 for m in result.alert_metrics if m.received_at is not None
        )
        result.total_alerts_processed = sum(
            1 for m in result.alert_metrics
            if m.response_completed_at is not None
        )
        result.total_errors = sum(
            1 for m in result.alert_metrics if m.error is not None
        )
        result.error_messages = [
            m.error for m in result.alert_metrics if m.error
        ][:10]  # Keep only first 10 errors

        result.completed_at = time.time()
        result.status = LoadTestStatus.COMPLETED

        logger.info(
            "load_test_completed",
            total_alerts=result.total_alerts_sent,
            success_rate=result.success_rate,
            mttr_ms=result.mttr_ms,
            actual_rps=result.actual_rps,
        )

        return result

    async def run_burst_test(
        self,
        burst_size: int = 1000,
        burst_interval: int = 60,
        num_bursts: int = 5,
    ) -> LoadTestResult:
        """Run burst load test."""
        logger.info(
            "burst_test_starting",
            burst_size=burst_size,
            burst_interval=burst_interval,
            num_bursts=num_bursts,
        )

        result = LoadTestResult(
            test_id=f"burst-test-{int(time.time())}",
            status=LoadTestStatus.RUNNING,
            config=LoadTestConfig(),
            started_at=time.time(),
        )

        async with httpx.AsyncClient() as client:
            for burst in range(num_bursts):
                logger.info("burst_executing", burst=burst + 1, size=burst_size)

                # Send burst of alerts
                tasks = []
                for i in range(burst_size):
                    task = self._send_alert(
                        burst * 10000 + i,
                        client,
                    )
                    tasks.append(task)

                burst_results = await asyncio.gather(*tasks, return_exceptions=True)
                result.alert_metrics.extend([
                    r for r in burst_results if isinstance(r, AlertMetrics)
                ])

                # Wait for interval
                if burst < num_bursts - 1:
                    await asyncio.sleep(burst_interval)

        result.total_alerts_sent = len(result.alert_metrics)
        result.total_alerts_received = sum(
            1 for m in result.alert_metrics if m.received_at is not None
        )
        result.total_alerts_processed = sum(
            1 for m in result.alert_metrics
            if m.response_completed_at is not None
        )
        result.completed_at = time.time()
        result.status = LoadTestStatus.COMPLETED

        return result


class PerformanceAnalyzer:
    """Analyzes load test results."""

    @staticmethod
    def analyze(result: LoadTestResult) -> Dict[str, Any]:
        """Analyze load test results."""
        response_times = [
            m.total_time_ms for m in result.alert_metrics
            if m.total_time_ms is not None
        ]

        detection_times = [
            m.detection_time_ms for m in result.alert_metrics
            if m.detection_time_ms is not None
        ]

        response_action_times = [
            m.response_time_ms for m in result.alert_metrics
            if m.response_time_ms is not None
        ]

        # Calculate percentiles
        def percentile(data: List[float], p: int) -> float:
            if not data:
                return 0.0
            sorted_data = sorted(data)
            index = int(len(sorted_data) * p / 100)
            return sorted_data[min(index, len(sorted_data) - 1)]

        # Error analysis
        error_types = {}
        for m in result.alert_metrics:
            if m.error:
                error_type = m.error.split(":")[0] if ":" in m.error else "Unknown"
                error_types[error_type] = error_types.get(error_type, 0) + 1

        # SLA compliance
        mttr_target_ms = 120000  # 2 minutes
        mttr_compliant = sum(
            1 for m in result.alert_metrics
            if m.total_time_ms is not None and m.total_time_ms <= mttr_target_ms
        )
        sla_compliance = (
            (mttr_compliant / len(result.alert_metrics)) * 100
            if result.alert_metrics else 0
        )

        return {
            "summary": {
                "total_alerts": result.total_alerts_sent,
                "success_rate": result.success_rate,
                "actual_rps": result.actual_rps,
                "duration_seconds": result.duration_seconds,
            },
            "latency": {
                "mttr_ms": result.mttr_ms,
                "p50_ms": percentile(response_times, 50),
                "p95_ms": percentile(response_times, 95),
                "p99_ms": percentile(response_times, 99),
                "min_ms": min(response_times) if response_times else 0,
                "max_ms": max(response_times) if response_times else 0,
                "avg_ms": sum(response_times) / len(response_times) if response_times else 0,
            },
            "detection": {
                "avg_detection_time_ms": (
                    sum(detection_times) / len(detection_times)
                    if detection_times else 0
                ),
                "p95_detection_ms": percentile(detection_times, 95),
            },
            "response": {
                "avg_response_time_ms": (
                    sum(response_action_times) / len(response_action_times)
                    if response_action_times else 0
                ),
                "p95_response_ms": percentile(response_action_times, 95),
            },
            "errors": {
                "total_errors": result.total_errors,
                "error_rate": (
                    (result.total_errors / result.total_alerts_sent) * 100
                    if result.total_alerts_sent > 0 else 0
                ),
                "error_types": error_types,
            },
            "sla": {
                "mttr_target_ms": mttr_target_ms,
                "mttr_compliant_count": mttr_compliant,
                "sla_compliance_percent": sla_compliance,
            },
            "recommendations": PerformanceAnalyzer._generate_recommendations(result),
        }

    @staticmethod
    def _generate_recommendations(result: LoadTestResult) -> List[str]:
        """Generate performance recommendations."""
        recommendations = []

        if result.mttr_ms and result.mttr_ms > 120000:
            recommendations.append(
                "MTTR exceeds 2 minutes target. Consider scaling Silver agents."
            )

        if result.success_rate < 99:
            recommendations.append(
                f"Success rate is {result.success_rate:.1f}%. Investigate error causes."
            )

        error_rate = (
            (result.total_errors / result.total_alerts_sent) * 100
            if result.total_alerts_sent > 0 else 0
        )
        if error_rate > 1:
            recommendations.append(
                f"Error rate is {error_rate:.1f}%. Review error handling."
            )

        if result.actual_rps < result.config.target_rps * 0.9:
            recommendations.append(
                "Actual RPS is below 90% of target. Check for bottlenecks."
            )

        return recommendations


async def run_load_test(
    cobalto_url: str = "http://localhost:8000",
    target_rps: int = 10000,
    duration_seconds: int = 300,
    concurrent_users: int = 50,
) -> Dict[str, Any]:
    """Run load test and return analysis."""
    config = LoadTestConfig(
        target_rps=target_rps,
        duration_seconds=duration_seconds,
        concurrent_users=concurrent_users,
        alert_templates=DEFAULT_ALERT_TEMPLATES,
    )

    generator = LoadTestGenerator(cobalto_api_url=cobalto_url, config=config)
    result = await generator.run()

    analyzer = PerformanceAnalyzer()
    analysis = analyzer.analyze(result)

    return {
        "test_id": result.test_id,
        "status": result.status.value,
        "analysis": analysis,
    }


async def run_burst_test(
    cobalto_url: str = "http://localhost:8000",
    burst_size: int = 1000,
    burst_interval: int = 60,
    num_bursts: int = 5,
) -> Dict[str, Any]:
    """Run burst test and return analysis."""
    generator = LoadTestGenerator(cobalto_api_url=cobalto_url)
    result = await generator.run_burst_test(burst_size, burst_interval, num_bursts)

    analyzer = PerformanceAnalyzer()
    analysis = analyzer.analyze(result)

    return {
        "test_id": result.test_id,
        "status": result.status.value,
        "analysis": analysis,
    }
