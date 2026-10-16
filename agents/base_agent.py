"""
Base Agent Module
Defines standard contracts, data classes, and shared utility methods for all PhishGuard agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List


@dataclass
class AgentResult:
    """Represents the standardized output of a specialized security agent."""
    agent_name: str
    score: float  # 0.0 (Clean/Safe) to 100.0 (Critical Threat)
    verdict: str  # SAFE, LOW_RISK, SUSPICIOUS, HIGH_RISK, CRITICAL
    confidence: float  # 0.0 to 1.0
    flags: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert agent result to a serializable dictionary."""
        return asdict(self)


class BaseAgent(ABC):
    """Abstract base class for all detection agents."""

    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight

    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> AgentResult:
        """
        Analyze provided payload and return an AgentResult.
        
        Args:
            data: Dictionary containing target payload (e.g., 'url', 'body', 'headers', 'raw_email')
            
        Returns:
            AgentResult containing score, verdict, flags, and diagnostic details.
        """
        pass

    @staticmethod
    def score_to_verdict(score: float) -> str:
        """Map numerical score to standard threat category."""
        if score < 20.0:
            return "SAFE"
        elif score < 45.0:
            return "LOW_RISK"
        elif score < 70.0:
            return "SUSPICIOUS"
        elif score < 85.0:
            return "HIGH_RISK"
        else:
            return "CRITICAL"
