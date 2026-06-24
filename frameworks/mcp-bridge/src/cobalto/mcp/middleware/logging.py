"""
MCP Logging Middleware - Request/response logging and metrics.
"""

import time
import logging
from typing import Any, Callable, Dict, Optional
from datetime import datetime

from cobalto.mcp.protocol import JSONRPCRequest, JSONRPCResponse, JSONRPCError

logger = logging.getLogger(__name__)


class MCPLoggingMiddleware:
    """Logging middleware for MCP server."""

    def __init__(
        self,
        log_requests: bool = True,
        log_responses: bool = False,
        log_errors: bool = True,
        mask_sensitive_fields: Optional[list] = None,
    ):
        self.log_requests = log_requests
        self.log_responses = log_responses
        self.log_errors = log_errors
        self.mask_sensitive_fields = mask_sensitive_fields or [
            "password", "token", "api_key", "secret", "auth"
        ]

        # Metrics
        self._request_count = 0
        self._error_count = 0
        self._total_duration = 0.0
        self._method_counts: Dict[str, int] = {}
        self._method_durations: Dict[str, float] = {}

    def _mask_data(self, data: Any) -> Any:
        """Mask sensitive fields in data."""
        if isinstance(data, dict):
            masked = {}
            for key, value in data.items():
                if key.lower() in [f.lower() for f in self.mask_sensitive_fields]:
                    masked[key] = "***MASKED***"
                else:
                    masked[key] = self._mask_data(value)
            return masked
        elif isinstance(data, list):
            return [self._mask_data(item) for item in data]
        return data

    def _log_request(self, request: JSONRPCRequest) -> None:
        """Log incoming request."""
        if not self.log_requests:
            return

        masked_params = self._mask_data(request.params) if request.params else None

        logger.info(
            "MCP Request",
            extra={
                "request_id": request.id,
                "method": request.method,
                "params": masked_params,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def _log_response(
        self,
        request: JSONRPCRequest,
        response: JSONRPCResponse,
        duration_ms: float,
    ) -> None:
        """Log response."""
        if not self.log_responses and not response.error:
            return

        log_data = {
            "request_id": request.id,
            "method": request.method,
            "duration_ms": round(duration_ms, 2),
            "timestamp": datetime.utcnow().isoformat(),
        }

        if response.error:
            log_data["error"] = {
                "code": response.error.code,
                "message": response.error.message,
            }

        if self.log_responses:
            log_data["result"] = response.result

        if response.error:
            logger.warning("MCP Response (error)", extra=log_data)
        else:
            logger.info("MCP Response", extra=log_data)

    def _update_metrics(self, method: str, duration_ms: float, is_error: bool) -> None:
        """Update request metrics."""
        self._request_count += 1
        self._total_duration += duration_ms

        if is_error:
            self._error_count += 1

        self._method_counts[method] = self._method_counts.get(method, 0) + 1
        self._method_durations[method] = (
            self._method_durations.get(method, 0) + duration_ms
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Get request metrics."""
        avg_duration = (
            self._total_duration / self._request_count
            if self._request_count > 0
            else 0
        )

        method_metrics = {}
        for method, count in self._method_counts.items():
            total_duration = self._method_durations.get(method, 0)
            method_metrics[method] = {
                "count": count,
                "avg_duration_ms": round(total_duration / count, 2) if count > 0 else 0,
            }

        return {
            "total_requests": self._request_count,
            "total_errors": self._error_count,
            "error_rate": (
                self._error_count / self._request_count
                if self._request_count > 0
                else 0
            ),
            "avg_duration_ms": round(avg_duration, 2),
            "methods": method_metrics,
        }

    def reset_metrics(self) -> None:
        """Reset all metrics."""
        self._request_count = 0
        self._error_count = 0
        self._total_duration = 0.0
        self._method_counts.clear()
        self._method_durations.clear()

    async def __call__(
        self,
        request: JSONRPCRequest,
        handler: Callable,
    ) -> JSONRPCResponse:
        """Process request with logging."""
        self._log_request(request)

        start_time = time.time()

        try:
            response = await handler(request)
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            self._update_metrics(request.method, duration_ms, True)

            logger.exception(
                "MCP Request failed",
                extra={
                    "request_id": request.id,
                    "method": request.method,
                    "error": str(e),
                    "duration_ms": round(duration_ms, 2),
                },
            )
            raise

        duration_ms = (time.time() - start_time) * 1000
        is_error = response.error is not None

        self._update_metrics(request.method, duration_ms, is_error)
        self._log_response(request, response, duration_ms)

        return response
