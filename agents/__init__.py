"""
PhishGuard Agents Package
Multi-Agent Phishing Detection & Security Analysis Architecture
Features 5 Autonomous Security Agents coordinated by the PhishGuard Orchestrator.
"""

from .base_agent import BaseAgent, AgentResult
from .url_agent import UrlAgent
from .content_agent import ContentAgent
from .header_agent import HeaderAgent
from .threat_intel_agent import ThreatIntelAgent
from .ml_agent import MLAgent
from .orchestrator import PhishGuardOrchestrator

__all__ = [
    "BaseAgent",
    "AgentResult",
    "UrlAgent",
    "ContentAgent",
    "HeaderAgent",
    "ThreatIntelAgent",
    "MLAgent",
    "PhishGuardOrchestrator",
]
