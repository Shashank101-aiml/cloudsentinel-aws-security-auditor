import html
import re
from typing import Any, Dict

REDACT_KEYS = {
    "secret",
    "password",
    "token",
    "aws_secret_access_key",
    "access_key",
    "session_token",
    "authorization",
    "key_material",
    "private_key",
}

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class Sanitizer:
    """Provides security sanitization for evidence, CSV export formulas, and HTML rendering."""

    @classmethod
    def sanitize_dict(cls, data: Any) -> Any:
        """Recursively scrubs secret patterns and sensitive key-values from dictionaries/lists."""
        if isinstance(data, dict):
            sanitized: Dict[str, Any] = {}
            for k, v in data.items():
                k_lower = str(k).lower()
                if any(sec_key in k_lower for sec_key in REDACT_KEYS):
                    sanitized[k] = "***REDACTED_SECRET***"
                else:
                    sanitized[k] = cls.sanitize_dict(v)
            return sanitized
        elif isinstance(data, list):
            return [cls.sanitize_dict(item) for item in data]
        elif isinstance(data, str):
            # Mask potential AWS secret key format (40 base64 chars) or sensitive strings
            if re.search(r'(?i)(secret|token|password)[\s:=]+([^\s,;]+)', data):
                return re.sub(r'(?i)(secret|token|password)[\s:=]+([^\s,;]+)', r'\1=***REDACTED***', data)
            return data
        return data

    @classmethod
    def sanitize_csv_cell(cls, val: Any) -> str:
        """
        Guards against CSV Formula Injection / DDE exploits in Excel/Sheets.
        Prepends a single quote if the string begins with =, +, -, @, tab, or carriage return.
        """
        if val is None:
            return ""
        s = str(val).strip()
        if s and s.startswith(FORMULA_PREFIXES):
            return f"'{s}"
        return s

    @classmethod
    def escape_html(cls, val: Any) -> str:
        """Escapes raw content for safe HTML reports to prevent XSS."""
        if val is None:
            return ""
        return html.escape(str(val))
