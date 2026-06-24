"""
Structured logging configuration using structlog and python-json-logger.
Provides consistent JSON logging across all services.
"""

import sys
import logging
import structlog
from typing import Any, Dict, Optional
from structlog.typing import EventDict, Processor
from .config import get_settings


def add_service_info(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add service identification to log entries."""
    settings = get_settings()
    event_dict["service"] = settings.app_name
    event_dict["environment"] = settings.app_env
    return event_dict


def add_timestamp(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add ISO format timestamp."""
    from datetime import datetime, timezone
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def add_log_level(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Add log level."""
    event_dict["level"] = method_name.upper()
    return event_dict


def drop_color_message_key(logger: Any, method_name: str, event_dict: EventDict) -> EventDict:
    """Remove color_message key from output."""
    event_dict.pop("color_message", None)
    return event_dict


def setup_logging(
    log_level: Optional[str] = None,
    log_format: Optional[str] = None,
    service_name: Optional[str] = None,
) -> None:
    """Configure structured logging for the application."""
    settings = get_settings()

    level = log_level or settings.log_level
    fmt = log_format or settings.log_format

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level),
    )

    # Configure structlog processors
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        add_service_info,
        drop_color_message_key,
    ]

    if fmt == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Set log levels for noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)


def get_logger(name: str, **bind_kwargs: Any) -> structlog.BoundLogger:
    """Get a structured logger instance with optional bound context."""
    logger = structlog.get_logger(name)
    if bind_kwargs:
        logger = logger.bind(**bind_kwargs)
    return logger


class LogContext:
    """Context manager for adding temporary context to logs."""

    def __init__(self, **kwargs: Any):
        self.kwargs = kwargs
        self.tokens = []

    def __enter__(self) -> "LogContext":
        for key, value in self.kwargs.items():
            token = structlog.contextvars.bind_contextvars(**{key: value})
            self.tokens.append((key, token))
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for key, token in self.tokens:
            structlog.contextvars.unbind_contextvars(key)


def log_function_call(logger: structlog.BoundLogger):
    """Decorator to log function entry/exit with timing."""
    import functools
    import time

    def decorator(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.perf_counter()
            logger.debug(
                "function_called",
                function=func.__name__,
                args_count=len(args),
                kwargs_keys=list(kwargs.keys()),
            )
            try:
                result = await func(*args, **kwargs)
                duration = time.perf_counter() - start
                logger.debug(
                    "function_completed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                )
                return result
            except Exception as e:
                duration = time.perf_counter() - start
                logger.exception(
                    "function_failed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                    error=str(e),
                )
                raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.perf_counter()
            logger.debug(
                "function_called",
                function=func.__name__,
                args_count=len(args),
                kwargs_keys=list(kwargs.keys()),
            )
            try:
                result = func(*args, **kwargs)
                duration = time.perf_counter() - start
                logger.debug(
                    "function_completed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                )
                return result
            except Exception as e:
                duration = time.perf_counter() - start
                logger.exception(
                    "function_failed",
                    function=func.__name__,
                    duration_ms=round(duration * 1000, 2),
                    error=str(e),
                )
                raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator