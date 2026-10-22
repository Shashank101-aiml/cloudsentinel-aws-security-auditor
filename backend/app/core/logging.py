import logging
import re
import sys

# Patterns to mask in logs
SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(aws_secret_access_key|secret_key|secretkey|password|token|session_token)[\s:=]+([^\s,;]+)'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)'), r'\1***REDACTED***'),
]


class SanitizingFormatter(logging.Formatter):
    """Custom logging formatter that strips potential AWS credentials or secret tokens."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern, replacement in SENSITIVE_PATTERNS:
            msg = pattern.sub(replacement, msg)
        return msg


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configures application-wide structured and sanitized logging."""
    logger = logging.getLogger("cloudsentinel")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            SanitizingFormatter(
                fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)

    return logger


logger = setup_logging()
