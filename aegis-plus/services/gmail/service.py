"""Gmail ingestion service (M14).

Orchestrates the read-only Gmail *input connector*. It does not analyze anything
itself: it obtains valid credentials (refreshing when needed), lists recent
messages, fetches each as raw RFC-822, and hands the raw text to the **existing**
:class:`~services.email_analysis.service.EmailAnalysisService`. Every downstream
capability — IOC extraction, threat intelligence, incident/campaign correlation,
the event bus, the knowledge graph, analytics, SOC, and the Copilot — is reached
through that single reused seam. No Gmail-specific intelligence exists.

Beyond synchronization the service exposes a **workspace read-model**: the
analyst message list and per-message detail. These project the *existing*
intelligence (persisted scan, investigation, incident/campaign correlation) into
display DTOs and derive a safe, on-demand preview from the raw message. They
recompute nothing.

Deduplication and the read-model use the Gmail message id as the external
identity, scoped by the connected ``account_email`` so messages from different
demonstration accounts stay isolated. Ingestion outcomes are classified with the
four-state :class:`~core.domain.gmail.GmailMessageStatus` taxonomy so an
unsupported message never fails the whole synchronization and the analyst can
tell it apart from a transient Gmail failure.

Connect (the interactive OAuth loopback flow) is exposed as a distinct method so
the API/UI can run it off the request path. Disconnect clears tokens and sync
state but never touches previously generated AEGIS+ intelligence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from core.domain.analysis import Verdict
from core.domain.email import EmailMessage
from core.domain.gmail import (
    GmailAccount,
    GmailCredentials,
    GmailMessageRef,
    GmailMessageStatus,
    GmailProcessedMessage,
)
from core.exceptions import ValidationError
from core.interfaces import ILogger
from core.interfaces.gmail import (
    GmailAuthError,
    GmailConnectorError,
    IGmailAuthFlow,
    IGmailGateway,
    IGmailTokenStore,
)
from core.interfaces.gmail_sync_state import IGmailSyncStateRepository
from services.email_analysis.service import EmailAnalysisService
from services.gmail.dtos import (
    GmailEvidenceItem,
    GmailMessageDetail,
    GmailMessageView,
    GmailPreview,
    GmailSourceItem,
    GmailUrlItem,
)
from services.incident import IncidentCorrelationService

_ACTOR = "gmail.connector"
_PREVIEW_BODY_CAP = 20_000


@dataclass(frozen=True, slots=True)
class GmailConnectionStatus:
    """Connection state surfaced to the API/UI (never carries a token)."""

    connected: bool
    email_address: str = ""
    scope: str = ""
    read_only: bool = True
    processed_messages: int = 0
    last_synced_at: str = ""


@dataclass(frozen=True, slots=True)
class GmailMessageOutcome:
    """The per-message result of an ingestion pass."""

    message_id: str
    subject: str
    sender: str
    verdict: str
    analyzed: bool
    status: str = GmailMessageStatus.ANALYZED.value
    duplicate: bool = False
    error: str = ""


@dataclass(slots=True)
class GmailSyncResult:
    """Aggregate statistics for a synchronization pass.

    ``errors`` is the total that could not be analyzed (``unsupported`` +
    ``transient`` + ``failed``), retained for backward compatibility; the
    individual four-state counts are exposed alongside it.
    """

    retrieved: int = 0
    analyzed: int = 0
    duplicates: int = 0
    malicious: int = 0
    suspicious: int = 0
    benign: int = 0
    errors: int = 0
    unsupported: int = 0
    transient: int = 0
    failed: int = 0
    synced_at: str = ""
    outcomes: list[GmailMessageOutcome] = field(default_factory=list)


class GmailIngestionService:
    """Read-only Gmail connector feeding the existing Email Analysis pipeline."""

    def __init__(
        self,
        *,
        auth_flow: IGmailAuthFlow,
        token_store: IGmailTokenStore,
        gateway: IGmailGateway,
        email_analysis: EmailAnalysisService,
        sync_state_factory: Callable[[], GmailSyncStateContext],
        logger: ILogger,
        incidents: IncidentCorrelationService | None = None,
        default_query: str = "in:inbox",
        max_messages: int = 50,
    ) -> None:
        """Initialize the service.

        Args:
            auth_flow: The OAuth loopback flow (authorize/refresh).
            token_store: Protected local credential store.
            gateway: Read-only Gmail REST gateway.
            email_analysis: The existing Email Analysis service (reused verbatim).
            sync_state_factory: Produces a context yielding a sync-state
                repository bound to a short-lived unit of work.
            logger: Injected logger (never receives tokens).
            incidents: The existing incident/campaign correlation service, used
                read-only to surface a message's incident/campaign association.
            default_query: Default Gmail search query for message selection.
            max_messages: Default cap on messages fetched per sync.
        """
        self._auth = auth_flow
        self._tokens = token_store
        self._gateway = gateway
        self._email = email_analysis
        self._sync_state = sync_state_factory
        self._logger = logger
        self._incidents = incidents
        self._default_query = default_query
        self._max_messages = max_messages
        self._last_synced_at = ""

    # --- connection ------------------------------------------------------

    def connect(self) -> GmailConnectionStatus:
        """Run the interactive OAuth loopback flow and persist credentials.

        Raises:
            GmailAuthError: If authorization fails, is denied, or times out.
        """
        credentials = self._auth.authorize()
        self._tokens.save(credentials)
        email = self._safe_profile_email(credentials)
        self._logger.info("Gmail connected for account ending with {}", _mask(email))
        return self.status()

    def disconnect(self) -> GmailConnectionStatus:
        """Clear stored credentials and dedup state (keeps prior intelligence)."""
        self._tokens.clear()
        with self._sync_state() as state:
            state.repository.clear()
            state.commit()
        self._last_synced_at = ""
        self._logger.info("Gmail disconnected; local tokens and sync state cleared")
        return GmailConnectionStatus(connected=False)

    def status(self) -> GmailConnectionStatus:
        """Return the current connection status (no token material)."""
        credentials = self._tokens.load()
        if credentials is None:
            return GmailConnectionStatus(connected=False)
        account = self._account_from(credentials)
        with self._sync_state() as state:
            processed = state.repository.processed_count(account.email_address)
        return GmailConnectionStatus(
            connected=True,
            email_address=account.email_address,
            scope=account.scope,
            read_only=account.is_read_only,
            processed_messages=processed,
            last_synced_at=self._last_synced_at,
        )

    def is_connected(self) -> bool:
        """Whether a Gmail account is currently connected."""
        return self._tokens.load() is not None

    # --- synchronization -------------------------------------------------

    def sync(self, *, query: str | None = None, max_messages: int | None = None) -> GmailSyncResult:
        """Fetch recent messages and analyze new ones via the existing pipeline.

        Raises:
            GmailConnectorError: If no account is connected or Gmail is
                unreachable.
        """
        credentials = self._require_credentials()
        credentials = self._ensure_fresh(credentials)
        account_email = self._safe_profile_email(credentials)
        effective_query = query or self._default_query
        cap = max_messages or self._max_messages

        refs = self._gateway.list_messages(credentials, query=effective_query, max_results=cap)
        result = GmailSyncResult(retrieved=len(refs))
        for ref in refs:
            self._ingest_one(credentials, account_email, ref, result)
        result.errors = result.unsupported + result.transient + result.failed
        result.synced_at = _now_iso()
        self._last_synced_at = result.synced_at
        self._logger.info(
            "Gmail sync: {} retrieved, {} analyzed, {} duplicate, "
            "{} unsupported, {} transient, {} failed",
            result.retrieved,
            result.analyzed,
            result.duplicates,
            result.unsupported,
            result.transient,
            result.failed,
        )
        return result

    # --- workspace read-model -------------------------------------------

    def list_messages(
        self, *, risk_filter: str = "all", search: str = ""
    ) -> tuple[GmailMessageView, ...]:
        """Return the analyst message list for the active account.

        Projects the persisted read-model rows into display views, joining the
        *existing* scan for analyzed messages to surface verdict/risk/confidence.
        Filtering and search are presentation concerns applied over existing
        values; no intelligence is computed here.
        """
        account_email = self._active_account_email()
        if not account_email:
            return ()
        with self._sync_state() as state:
            records = state.repository.list_for_account(account_email)
        views = [self._view_from_record(record) for record in records]
        return tuple(_apply_filters(views, risk_filter=risk_filter, search=search))

    def message_detail(self, message_id: str) -> GmailMessageDetail | None:
        """Return the full analyst detail for one message, or ``None`` if absent.

        Combines the existing scan's evidence/sources with the incident/campaign
        association and a safe, on-demand preview of the raw message. Recomputes
        no intelligence: risk/verdict/evidence come verbatim from the stored scan.
        """
        credentials = self._tokens.load()
        if credentials is None:
            return None
        account_email = self._safe_profile_email(credentials)
        with self._sync_state() as state:
            record = state.repository.get(account_email, message_id)
        if record is None:
            return None

        view = self._view_from_record(record)
        preview = self._safe_preview(credentials, message_id)
        detail = self._detail_from_scan(view, record, preview)
        return detail

    # --- internals: ingestion -------------------------------------------

    def _ingest_one(
        self,
        credentials: GmailCredentials,
        account_email: str,
        ref: GmailMessageRef,
        result: GmailSyncResult,
    ) -> None:
        with self._sync_state() as state:
            already = state.repository.is_processed(account_email, ref.message_id)
        if already:
            result.duplicates += 1
            result.outcomes.append(
                GmailMessageOutcome(
                    message_id=ref.message_id,
                    subject=ref.subject,
                    sender=ref.sender,
                    verdict="",
                    analyzed=False,
                    duplicate=True,
                )
            )
            return

        try:
            raw = self._gateway.fetch_raw(credentials, ref.message_id)
        except GmailConnectorError as exc:
            # Transient Gmail/API failure: do NOT record, so it retries next sync.
            result.transient += 1
            result.outcomes.append(
                self._outcome(ref, GmailMessageStatus.TRANSIENT, error=_safe_message(exc))
            )
            return

        try:
            outcome = self._email.analyze(raw.raw, actor=_ACTOR)
        except ValidationError:
            # Malformed/unsupported RFC-822: terminal, recorded, does not fail sync.
            result.unsupported += 1
            self._record(account_email, ref, scan_id="", status=GmailMessageStatus.UNSUPPORTED)
            result.outcomes.append(
                self._outcome(
                    ref,
                    GmailMessageStatus.UNSUPPORTED,
                    error="This message could not be parsed (unsupported email format).",
                )
            )
            return
        except Exception:
            # Unexpected failure: terminal, recorded to avoid a poison re-loop.
            result.failed += 1
            self._record(account_email, ref, scan_id="", status=GmailMessageStatus.FAILED)
            result.outcomes.append(
                self._outcome(
                    ref,
                    GmailMessageStatus.FAILED,
                    error="This message could not be analyzed.",
                )
            )
            return

        verdict = outcome.scan.verdict
        self._tally(result, verdict)
        self._record(
            account_email,
            ref,
            scan_id=str(outcome.scan.id),
            status=GmailMessageStatus.ANALYZED,
        )
        result.analyzed += 1
        result.outcomes.append(
            GmailMessageOutcome(
                message_id=ref.message_id,
                subject=ref.subject or outcome.scan.subject,
                sender=ref.sender or outcome.scan.sender,
                verdict=verdict.name,
                analyzed=True,
                status=GmailMessageStatus.ANALYZED.value,
            )
        )

    def _record(
        self,
        account_email: str,
        ref: GmailMessageRef,
        *,
        scan_id: str,
        status: GmailMessageStatus,
    ) -> None:
        with self._sync_state() as state:
            state.repository.record(
                GmailProcessedMessage(
                    account_email=account_email,
                    message_id=ref.message_id,
                    thread_id=ref.thread_id,
                    scan_id=scan_id,
                    sender=ref.sender,
                    subject=ref.subject,
                    received_at=ref.received_at,
                    snippet=ref.snippet,
                    status=status,
                    processed_at=datetime.now(UTC),
                )
            )
            state.commit()

    @staticmethod
    def _outcome(
        ref: GmailMessageRef, status: GmailMessageStatus, *, error: str = ""
    ) -> GmailMessageOutcome:
        return GmailMessageOutcome(
            message_id=ref.message_id,
            subject=ref.subject,
            sender=ref.sender,
            verdict="",
            analyzed=False,
            status=status.value,
            error=error,
        )

    @staticmethod
    def _tally(result: GmailSyncResult, verdict: Verdict) -> None:
        if verdict is Verdict.PHISHING:
            result.malicious += 1
        elif verdict is Verdict.SUSPICIOUS:
            result.suspicious += 1
        else:
            result.benign += 1

    # --- internals: read-model projection -------------------------------

    def _view_from_record(self, record: GmailProcessedMessage) -> GmailMessageView:
        verdict = ""
        risk_percent = 0
        confidence = 0.0
        if record.status is GmailMessageStatus.ANALYZED and record.scan_id:
            scan = self._email.get_scan(record.scan_id)
            if scan is not None:
                verdict = scan.verdict.value
                risk_percent = round(scan.threat_score * 100)
                confidence = scan.confidence
        return GmailMessageView(
            message_id=record.message_id,
            thread_id=record.thread_id,
            sender=record.sender,
            subject=record.subject,
            received_at=record.received_at,
            snippet=record.snippet,
            status=record.status,
            verdict=verdict,
            risk_percent=risk_percent,
            confidence=confidence,
            scan_id=record.scan_id,
        )

    def _detail_from_scan(
        self,
        view: GmailMessageView,
        record: GmailProcessedMessage,
        preview: GmailPreview,
    ) -> GmailMessageDetail:
        analysis_error = _status_explanation(record.status)
        if record.status is not GmailMessageStatus.ANALYZED or not record.scan_id:
            return GmailMessageDetail(view=view, preview=preview, analysis_error=analysis_error)

        scan = self._email.get_scan(record.scan_id)
        if scan is None:
            return GmailMessageDetail(
                view=view,
                preview=preview,
                analysis_error="The analysis for this message is no longer available.",
            )

        evidence = tuple(
            GmailEvidenceItem(feature=c.feature, detail=c.detail, weight=c.weight)
            for c in sorted(
                (c for c in scan.contributions if c.triggered),
                key=lambda c: c.weight,
                reverse=True,
            )
        )
        sources = tuple(
            GmailSourceItem(
                source=s.source.value,
                risk_percent=round(s.risk * 100),
                confidence=s.confidence,
                available=s.available,
                rationale=s.rationale,
            )
            for s in scan.sources
        )
        incident_id, incident_title, campaign_name = self._correlation_for(record.scan_id)
        return GmailMessageDetail(
            view=view,
            category=scan.category.value,
            evidence_strength=scan.evidence_strength,
            url_count=scan.url_count,
            malicious_url_count=scan.malicious_url_count,
            evidence=evidence,
            sources=sources,
            urls=preview.urls,
            iocs=_iocs_from_preview(preview),
            recommendations=_handling_guidance(scan.verdict.value),
            incident_id=incident_id,
            incident_title=incident_title,
            campaign_name=campaign_name,
            artifact_id=_artifact_id(preview),
            preview=preview,
            analysis_error="",
        )

    def _correlation_for(self, scan_id: str) -> tuple[str, str, str]:
        """Resolve a message's incident/campaign association (read-only reuse)."""
        if self._incidents is None or not scan_id:
            return "", "", ""
        try:
            incidents = self._incidents.list_incidents()
        except Exception:  # pragma: no cover - defensive: never fail the detail view
            return "", "", ""
        incident = next((i for i in incidents if scan_id in i.scan_ids), None)
        if incident is None:
            return "", "", ""
        campaign_name = ""
        if incident.campaign_id:
            campaign = next(
                (c for c in self._incidents.list_campaigns() if str(c.id) == incident.campaign_id),
                None,
            )
            campaign_name = campaign.name if campaign is not None else ""
        return str(incident.id), incident.title, campaign_name

    def _safe_preview(self, credentials: GmailCredentials, message_id: str) -> GmailPreview:
        """Build a safe, non-executable preview from the raw message on demand."""
        try:
            fresh = self._ensure_fresh(credentials)
            raw = self._gateway.fetch_raw(fresh, message_id)
        except GmailConnectorError:
            return GmailPreview(
                from_display="",
                from_address="",
                error="The message could not be retrieved from Gmail for preview.",
            )
        try:
            email = EmailMessage.parse(raw.raw)
        except ValidationError:
            return GmailPreview(
                from_display="",
                from_address="",
                error="This message could not be safely parsed for preview.",
            )
        urls = tuple(
            GmailUrlItem(url=url, verdict="untrusted", risk_percent=0, blacklisted=False)
            for url in email.urls
        )
        attachments = tuple(f"{a.filename} ({a.content_type})" for a in email.attachments)
        return GmailPreview(
            from_display=email.sender.display_name,
            from_address=email.sender.address,
            to=tuple(a.address for a in email.recipients),
            cc=tuple(a.address for a in email.cc),
            subject=email.subject,
            date=email.date,
            reply_to=email.reply_to.address if email.reply_to else "",
            plain_body=email.body[:_PREVIEW_BODY_CAP],
            urls=urls,
            attachments=attachments,
        )

    # --- internals: credentials -----------------------------------------

    def _active_account_email(self) -> str:
        credentials = self._tokens.load()
        if credentials is None:
            return ""
        return self._safe_profile_email(credentials)

    def _require_credentials(self) -> GmailCredentials:
        credentials = self._tokens.load()
        if credentials is None:
            raise GmailConnectorError("No Gmail account is connected.")
        return credentials

    def _ensure_fresh(self, credentials: GmailCredentials) -> GmailCredentials:
        if not credentials.is_expired():
            return credentials
        refreshed = self._auth.refresh(credentials)
        self._tokens.save(refreshed)
        return refreshed

    def _account_from(self, credentials: GmailCredentials) -> GmailAccount:
        email = self._safe_profile_email(credentials)
        return GmailAccount(
            email_address=email,
            connected_at=datetime.now(UTC),
            scope=credentials.scope,
        )

    def _safe_profile_email(self, credentials: GmailCredentials) -> str:
        try:
            return self._gateway.profile_email(credentials)
        except GmailAuthError:
            try:
                refreshed = self._auth.refresh(credentials)
                self._tokens.save(refreshed)
                return self._gateway.profile_email(refreshed)
            except GmailConnectorError:
                return ""
        except GmailConnectorError:
            return ""


@dataclass(slots=True)
class GmailSyncStateContext:
    """A unit-of-work-scoped sync-state repository handle.

    Yielded by the ``sync_state_factory``; ``commit`` persists changes. The
    context manager protocol lets the service scope each state access to a
    short-lived session, mirroring the auth service's pattern.
    """

    repository: IGmailSyncStateRepository
    _commit: Callable[[], None]
    _close: Callable[[], None]

    def commit(self) -> None:
        """Commit the underlying session."""
        self._commit()

    def __enter__(self) -> GmailSyncStateContext:
        """Enter the context, returning self."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the underlying session."""
        self._close()


def _apply_filters(
    views: list[GmailMessageView], *, risk_filter: str, search: str
) -> list[GmailMessageView]:
    selected = views
    band = risk_filter.strip().lower()
    if band and band != "all":
        selected = [v for v in selected if v.risk_band == band]
    needle = search.strip().lower()
    if needle:
        selected = [
            v
            for v in selected
            if needle in v.sender.lower()
            or needle in v.subject.lower()
            or needle in v.snippet.lower()
        ]
    return selected


def _iocs_from_preview(preview: GmailPreview) -> tuple[str, ...]:
    """Derive IOC strings from parsed message content (no recomputation)."""
    iocs: list[str] = []
    if preview.from_address and "@" in preview.from_address:
        iocs.append(preview.from_address.rsplit("@", 1)[-1])
    iocs.extend(u.url for u in preview.urls)
    seen: set[str] = set()
    unique: list[str] = []
    for ioc in iocs:
        if ioc not in seen:
            seen.add(ioc)
            unique.append(ioc)
    return tuple(unique)


def _artifact_id(preview: GmailPreview) -> str:
    """The knowledge-graph focus id for the message (matches email.identity)."""
    if not preview.from_address:
        return ""
    subject = preview.subject or "(no subject)"
    return f"{preview.from_address} — {subject}"


def _handling_guidance(verdict: str) -> tuple[str, ...]:
    """Deterministic analyst handling guidance keyed to the existing verdict.

    Presentation-level next steps (not new detection): what to do given the
    verdict AEGIS+ already produced.
    """
    v = verdict.lower()
    if v == "phishing":
        return (
            "Do not click links or open attachments in this message.",
            "Open the investigation to review evidence and IOCs.",
            "Check the associated incident/campaign for related activity.",
        )
    if v == "suspicious":
        return (
            "Treat links and attachments as untrusted until verified.",
            "Open the investigation to review the contributing evidence.",
        )
    return ("No malicious indicators were found. Remain cautious with unexpected requests.",)


def _status_explanation(status: GmailMessageStatus) -> str:
    if status is GmailMessageStatus.UNSUPPORTED:
        return "This message could not be parsed (unsupported email format)."
    if status is GmailMessageStatus.FAILED:
        return "This message could not be analyzed."
    if status is GmailMessageStatus.TRANSIENT:
        return "This message was not analyzed due to a temporary Gmail error."
    return ""


def _mask(email: str) -> str:
    """Return a privacy-preserving fragment of an email for logs."""
    if "@" not in email:
        return "***"
    _, _, domain = email.partition("@")
    return f"***@{domain}"


def _safe_message(error: Exception) -> str:
    """A user-safe message for a connector error (never leaks internals)."""
    text = str(error)
    return text if text else "Gmail synchronization could not complete."


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()
