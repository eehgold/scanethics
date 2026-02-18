"""
BaseScanner — abstract class every scanner must inherit from.

Each scanner must implement:
    - name: str           human-readable name shown in the UI
    - description: str    one-line description of what it does
    - run() -> dict       execute the scan; return a result dict

The result dict must follow this schema:
    {
        "success": bool,
        "findings": list[dict],   # scanner-specific items
        "errors":   list[str],    # non-fatal errors encountered
        "count":    int,          # total findings (auto-computed if omitted)
    }
"""

from abc import ABC, abstractmethod
from core.target import Target


class BaseScanner(ABC):
    name: str = "UnnamedScanner"
    description: str = ""

    def __init__(self, target: Target, **options):
        self.target = target
        self.options = options

    @abstractmethod
    def run(self) -> dict:
        """Execute the scan and return a structured result dict."""
        ...

    def _result(
        self,
        findings: list[dict],
        errors: list[str] | None = None,
        success: bool = True,
    ) -> dict:
        """Helper to build a standardised result dict."""
        errors = errors or []
        return {
            "scanner": self.name,
            "success": success,
            "findings": findings,
            "errors": errors,
            "count": len(findings),
        }
