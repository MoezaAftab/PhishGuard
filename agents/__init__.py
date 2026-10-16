"""
PhishGuard Agents Package
Multi-Agent Phishing Detection & Security Analysis Architecture
"""

from .base_agent import BaseAgent, AgentResult
from .url_agent import UrlAgent
from .content_agent import ContentAgent
from .header_agent import HeaderAgent
from .ml_agent import MLAgent
from .orchestrator import PhishGuardOrchestrator

__all__ = [
    "BaseAgent",
    "AgentResult",
    "UrlAgent",
    "ContentAgent",
    "HeaderAgent",
    "MLAgent",
    "PhishGuardOrchestrator",
]
