"""Core interface contracts (ports).

The architectural source of truth for shared contracts. Outer layers provide
implementations (adapters); the domain depends only on these abstractions.
"""

from core.interfaces.ai_service import IAIService
from core.interfaces.audit import IAuditTrail
from core.interfaces.auth_repository import IAuthSessionRepository, IUserRepository
from core.interfaces.configuration import IConfigurationProvider
from core.interfaces.copilot_skill import ICopilotSkill, SkillSpec
from core.interfaces.domain_intelligence import IDomainIntelligenceProvider
from core.interfaces.email_analyzer import IEmailAnalyzer, IEmailEvidenceProvider
from core.interfaces.event_bus import EventHandler, IEventBus
from core.interfaces.file_analyzer import (
    AnalyzedArtifact,
    IArchiveInspector,
    IArtifactEvidenceProvider,
    IFileAnalyzer,
)
from core.interfaces.gmail import (
    IGmailAuthFlow,
    IGmailGateway,
    IGmailTokenStore,
)
from core.interfaces.gmail_sync_state import IGmailSyncStateRepository
from core.interfaces.graph_repository import IGraphRepository
from core.interfaces.llm_provider import (
    ILLMProvider,
    LLMRequest,
    LLMResult,
    LLMStreamChunk,
)
from core.interfaces.logger import ILogger
from core.interfaces.password_hasher import IPasswordHasher
from core.interfaces.pe_parser import IPeParser
from core.interfaces.repository import IRepository
from core.interfaces.reputation import IReputationProvider
from core.interfaces.threat_intelligence import IThreatIntelligenceRepository
from core.interfaces.threat_protection import IThreatProtectionService
from core.interfaces.unit_of_work import IUnitOfWork
from core.interfaces.url_analyzer import IUrlAnalyzer

__all__ = [
    "AnalyzedArtifact",
    "EventHandler",
    "IAIService",
    "IArchiveInspector",
    "IArtifactEvidenceProvider",
    "IAuditTrail",
    "IAuthSessionRepository",
    "IConfigurationProvider",
    "ICopilotSkill",
    "IDomainIntelligenceProvider",
    "IEmailAnalyzer",
    "IEmailEvidenceProvider",
    "IEventBus",
    "IFileAnalyzer",
    "IGmailAuthFlow",
    "IGmailGateway",
    "IGmailSyncStateRepository",
    "IGmailTokenStore",
    "IGraphRepository",
    "ILLMProvider",
    "ILogger",
    "IPasswordHasher",
    "IPeParser",
    "IRepository",
    "IReputationProvider",
    "IThreatIntelligenceRepository",
    "IThreatProtectionService",
    "IUnitOfWork",
    "IUrlAnalyzer",
    "IUserRepository",
    "LLMRequest",
    "LLMResult",
    "LLMStreamChunk",
    "SkillSpec",
]
