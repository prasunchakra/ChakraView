"""Base scanner class — all scanners inherit from this."""

from abc import ABC, abstractmethod
from typing import Optional


class BaseScanner(ABC):
    """Abstract base for every vulnerability scanner module."""

    name: str = "Unnamed Scanner"
    description: str = ""
    owasp_category: str = ""

    @abstractmethod
    def scan(self, target: str) -> dict:
        """Run the scan against `target` and return a results dict.

        Returns:
            dict with keys: scanner, target, status, findings
        """

    def _result(self, target: str, findings: Optional[list] = None) -> dict:
        return {
            "scanner": self.name,
            "target": target,
            "status": "complete",
            "findings": findings or [],
        }
