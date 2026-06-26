import re


class PromptInjectionGuard:
    INJECTION_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        r"(?i)disregard\s+(all\s+)?previous",
        r"(?i)you\s+are\s+now\s+(?:a|an)\s+",
        r"(?i)system\s*:\s*",
        r"(?i)new\s+instructions?\s*:",
        r"(?i)forget\s+(?:everything|all|previous)",
        r"(?i)override\s+(?:system|instructions?|rules?)",
        r"(?i)act\s+as\s+if\s+you\s+(?:are|have|can)",
        r"(?i)pretend\s+(?:you\s+are|to\s+be|you(?:'re|re))",
        r"(?i)\bDAN\b.*\bjailbreak\b",
        r"(?i)developer\s+mode\s+(?:enabled|on|activate)",
    ]

    CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")

    def __init__(self, custom_patterns: list[str] | None = None):
        self._patterns = [re.compile(p) for p in self.INJECTION_PATTERNS]
        if custom_patterns:
            self._patterns.extend(re.compile(p) for p in custom_patterns)

    def sanitize(self, user_input: str) -> str:
        cleaned = self.CONTROL_CHAR_PATTERN.sub("", user_input)
        cleaned = cleaned.strip()
        return cleaned

    def detect_injection(self, text: str) -> tuple[bool, str | None]:
        for pattern in self._patterns:
            match = pattern.search(text)
            if match:
                return True, f"Potential injection detected: '{match.group()}'"
        return False, None

    def validate_and_sanitize(self, user_input: str) -> tuple[str, bool, str | None]:
        sanitized = self.sanitize(user_input)
        has_injection, reason = self.detect_injection(sanitized)
        return sanitized, has_injection, reason

    def wrap_for_prompt(self, user_input: str, context_label: str = "user_input") -> str:
        sanitized = self.sanitize(user_input)
        has_injection, reason = self.detect_injection(sanitized)
        if has_injection:
            raise ValueError(f"Blocked prompt injection attempt: {reason}")
        return f"<{context_label}>\n{sanitized}\n</{context_label}>"
