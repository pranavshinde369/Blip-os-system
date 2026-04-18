# ============================================================
# BLIP ENDPOINT SENTINEL — core/risk_scorer.py
# Weighted Multi-Signal Risk Scorer (0–100)
# Combines: Regex hits + RAG matches + Vision flags +
#           Behavioral anomalies + Time-of-day + Process context
#
# Score ranges:
#   0–30   → ALLOW   (green)
#   31–60  → WARN    (yellow)
#   61–85  → SANITIZE (orange)
#   86–100 → HARD BLOCK + Admin Alert (red)
# ============================================================

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from core.scanner import ScanResult, Severity, ThreatType
from core.classifier import ClassificationResult, ContentType


# ── Decision Enum ─────────────────────────────────────────────

class Decision(Enum):
    ALLOW    = "ALLOW"
    WARN     = "WARN"
    SANITIZE = "SANITIZE"
    BLOCK    = "BLOCK"


# ── Score band config ─────────────────────────────────────────

DECISION_BANDS = [
    (0,  30,  Decision.ALLOW),
    (31, 60,  Decision.WARN),
    (61, 85,  Decision.SANITIZE),
    (86, 100, Decision.BLOCK),
]

# Severity → base score contribution for each regex hit
SEVERITY_SCORE: dict[Severity, int] = {
    Severity.LOW:      8,
    Severity.MEDIUM:  20,
    Severity.HIGH:    32,
    Severity.CRITICAL: 45,
}

# ContentType → risk multiplier
# Credentials copied from an IDE are scarier than an email
CONTENT_MULTIPLIER: dict[ContentType, float] = {
    ContentType.CREDENTIALS:      1.4,
    ContentType.SOURCE_CODE:      1.1,
    ContentType.FINANCIAL_DATA:   1.2,
    ContentType.PII_BLOCK:        1.2,
    ContentType.MEDICAL_DATA:     1.15,
    ContentType.DATABASE_QUERY:   1.1,
    ContentType.NETWORK_CONFIG:   1.05,
    ContentType.SPREADSHEET_DATA: 1.1,
    ContentType.EMAIL_CONTENT:    1.0,
    ContentType.NATURAL_LANGUAGE: 0.9,
    ContentType.DOCUMENT_TEXT:    0.95,
    ContentType.UNKNOWN:          1.0,
}

# Sensitive process names (lowercase) → bonus score
SENSITIVE_PROCESSES = {
    "excel.exe":     15,
    "winword.exe":   12,
    "outlook.exe":   18,
    "chrome.exe":    10,
    "firefox.exe":   10,
    "code.exe":      12,
    "dbeaver.exe":   20,
    "datagrip.exe":  20,
    "postman.exe":   15,
    "ssms.exe":      20,
    "pgadmin4.exe":  20,
    "winscp.exe":    18,
    "putty.exe":     18,
}

# After-hours window (10 PM – 6 AM) → bonus score
AFTER_HOURS_SCORE   = 10
AFTER_HOURS_START   = 22   # 10 PM
AFTER_HOURS_END     = 6    #  6 AM

# RAG match bonus
RAG_CLOSE_SCORE     = 50   # distance < 0.25
RAG_MEDIUM_SCORE    = 25   # distance 0.25–0.45

# Vision AI flag bonus
VISION_FLAG_SCORE   = 35

# Behavioral anomaly bonus
ANOMALY_SCORE       = 15

# Multiple-threat-type bonus (data aggregation risk)
MULTI_THREAT_BONUS  = 10


# ── Score breakdown ───────────────────────────────────────────

@dataclass
class ScoreBreakdown:
    """Detailed breakdown of how the final score was computed."""
    regex_score:      int = 0
    rag_score:        int = 0
    vision_score:     int = 0
    anomaly_score:    int = 0
    after_hours:      int = 0
    process_score:    int = 0
    multi_threat:     int = 0
    multiplier:       float = 1.0
    raw_score:        int = 0     # before multiplier
    final_score:      int = 0     # clamped 0–100
    contributing_signals: list[str] = field(default_factory=list)


# ── Risk score result ─────────────────────────────────────────

@dataclass
class RiskScore:
    score:          int              # 0–100
    decision:       Decision
    breakdown:      ScoreBreakdown
    content_type:   ContentType
    threat_types:   list[str]        # human-readable threat names
    top_severity:   Optional[Severity]
    active_process: str              # process name that was active
    timestamp:      datetime = field(default_factory=datetime.now)
    score_time_ms:  float = 0.0

    @property
    def color(self) -> str:
        """UI accent color for the decision."""
        return {
            Decision.ALLOW:    "#2ECC71",   # green
            Decision.WARN:     "#F39C12",   # yellow
            Decision.SANITIZE: "#E67E22",   # orange
            Decision.BLOCK:    "#E74C3C",   # red
        }[self.decision]

    @property
    def emoji(self) -> str:
        return {
            Decision.ALLOW:    "✅",
            Decision.WARN:     "⚠️",
            Decision.SANITIZE: "🔧",
            Decision.BLOCK:    "🚫",
        }[self.decision]

    def to_dict(self) -> dict:
        """Serialise for audit logger."""
        return {
            "score":          self.score,
            "decision":       self.decision.value,
            "content_type":   self.content_type.value,
            "threat_types":   self.threat_types,
            "top_severity":   self.top_severity.value if self.top_severity else None,
            "active_process": self.active_process,
            "timestamp":      self.timestamp.isoformat(),
            "breakdown": {
                "regex":       self.breakdown.regex_score,
                "rag":         self.breakdown.rag_score,
                "vision":      self.breakdown.vision_score,
                "anomaly":     self.breakdown.anomaly_score,
                "after_hours": self.breakdown.after_hours,
                "process":     self.breakdown.process_score,
                "multi":       self.breakdown.multi_threat,
                "multiplier":  self.breakdown.multiplier,
                "final":       self.breakdown.final_score,
            },
            "signals": self.breakdown.contributing_signals,
        }


# ── Risk Scorer ───────────────────────────────────────────────

class RiskScorer:
    """
    Aggregates signals from all detection layers into
    a single 0–100 risk score and an actionable Decision.

    Usage:
        scorer  = RiskScorer()
        result  = scorer.score(
                      scan_result       = scanner.scan(text),
                      classification    = classifier.classify(text),
                      active_process    = "excel.exe",
                      rag_distance      = 0.31,     # optional
                      vision_flagged    = False,     # optional
                      anomaly_flagged   = False,     # optional
                  )
    """

    def __init__(self, config: Optional[dict] = None):
        """
        config: dict from settings.json["risk_weights"] (optional).
        Falls back to module-level constants if not provided.
        """
        self._cfg = config or {}

    # ── Main scoring method ───────────────────────────────────

    def score(
        self,
        scan_result:     ScanResult,
        classification:  ClassificationResult,
        active_process:  str = "",
        rag_distance:    Optional[float] = None,
        vision_flagged:  bool = False,
        anomaly_flagged: bool = False,
    ) -> RiskScore:

        t_start  = time.perf_counter()
        bd       = ScoreBreakdown()
        process  = active_process.lower().strip()

        # ── 1. Regex signal ───────────────────────────────────
        if scan_result.is_threat:
            seen_types: set[ThreatType] = set()
            for match in scan_result.matches:
                # Only score each ThreatType once (avoid double-counting)
                if match.threat_type not in seen_types:
                    contribution = SEVERITY_SCORE[match.severity]
                    bd.regex_score += contribution
                    bd.contributing_signals.append(
                        f"regex:{match.threat_type.value}(+{contribution})"
                    )
                    seen_types.add(match.threat_type)

            # Multiple distinct threat types in one payload → aggregation risk
            if len(seen_types) > 1:
                bd.multi_threat = MULTI_THREAT_BONUS
                bd.contributing_signals.append(
                    f"multi_threat:{len(seen_types)}_types(+{MULTI_THREAT_BONUS})"
                )

        # ── 2. RAG semantic match ─────────────────────────────
        if rag_distance is not None:
            if rag_distance < 0.25:
                bd.rag_score = RAG_CLOSE_SCORE
                bd.contributing_signals.append(
                    f"rag:close_match(dist={rag_distance:.3f},+{RAG_CLOSE_SCORE})"
                )
            elif rag_distance < 0.45:
                bd.rag_score = RAG_MEDIUM_SCORE
                bd.contributing_signals.append(
                    f"rag:medium_match(dist={rag_distance:.3f},+{RAG_MEDIUM_SCORE})"
                )

        # ── 3. Vision AI flag ─────────────────────────────────
        if vision_flagged:
            bd.vision_score = VISION_FLAG_SCORE
            bd.contributing_signals.append(
                f"vision:flagged(+{VISION_FLAG_SCORE})"
            )

        # ── 4. Behavioral anomaly ─────────────────────────────
        if anomaly_flagged:
            bd.anomaly_score = ANOMALY_SCORE
            bd.contributing_signals.append(
                f"anomaly:deviation(+{ANOMALY_SCORE})"
            )

        # ── 5. After-hours bonus ──────────────────────────────
        hour = datetime.now().hour
        if hour >= AFTER_HOURS_START or hour < AFTER_HOURS_END:
            bd.after_hours = AFTER_HOURS_SCORE
            bd.contributing_signals.append(
                f"after_hours:{hour:02d}:xx(+{AFTER_HOURS_SCORE})"
            )

        # ── 6. Sensitive process bonus ────────────────────────
        for proc, bonus in SENSITIVE_PROCESSES.items():
            if proc in process:
                bd.process_score = bonus
                bd.contributing_signals.append(
                    f"process:{proc}(+{bonus})"
                )
                break

        # ── 7. Content-type multiplier ────────────────────────
        bd.multiplier = CONTENT_MULTIPLIER.get(
            classification.content_type, 1.0
        )

        # ── 8. Final score calculation ────────────────────────
        bd.raw_score = (
            bd.regex_score
            + bd.rag_score
            + bd.vision_score
            + bd.anomaly_score
            + bd.after_hours
            + bd.process_score
            + bd.multi_threat
        )
        bd.final_score = min(
            int(bd.raw_score * bd.multiplier), 100
        )
        bd.final_score = max(bd.final_score, 0)

        # ── 9. Map score → Decision ───────────────────────────
        decision = Decision.ALLOW
        for low, high, dec in DECISION_BANDS:
            if low <= bd.final_score <= high:
                decision = dec
                break

        # ── Collect threat type names ─────────────────────────
        threat_types = list({
            m.threat_type.value for m in scan_result.matches
        }) if scan_result.is_threat else []

        elapsed = (time.perf_counter() - t_start) * 1000

        return RiskScore(
            score          = bd.final_score,
            decision       = decision,
            breakdown      = bd,
            content_type   = classification.content_type,
            threat_types   = threat_types,
            top_severity   = scan_result.highest_severity,
            active_process = active_process,
            score_time_ms  = round(elapsed, 3),
        )

    # ── Convenience: score raw text directly ─────────────────

    def score_text(
        self,
        text:           str,
        active_process: str = "",
        rag_distance:   Optional[float] = None,
        vision_flagged: bool = False,
        anomaly_flagged: bool = False,
    ) -> RiskScore:
        """
        One-shot helper that runs scanner + classifier internally.
        Use this when you don't need the intermediate results.
        """
        from core.scanner    import get_scanner
        from core.classifier import get_classifier

        scan   = get_scanner().scan(text)
        cls    = get_classifier().classify(text)

        return self.score(
            scan_result     = scan,
            classification  = cls,
            active_process  = active_process,
            rag_distance    = rag_distance,
            vision_flagged  = vision_flagged,
            anomaly_flagged = anomaly_flagged,
        )


# ── Module-level singleton ────────────────────────────────────

_scorer_instance: Optional[RiskScorer] = None

def get_scorer(config: Optional[dict] = None) -> RiskScorer:
    global _scorer_instance
    if _scorer_instance is None:
        _scorer_instance = RiskScorer(config)
    return _scorer_instance


# ── Self-test ─────────────────────────────────────────────────

if __name__ == "__main__":
    scorer = RiskScorer()

    test_cases = [
        {
            "label":   "Clean text (daytime)",
            "text":    "Hello team, please review the attached document.",
            "process": "winword.exe",
            "rag":     None,
            "vision":  False,
            "anomaly": False,
        },
        {
            "label":   "PAN card only",
            "text":    "My PAN is ABCDE1234F please update records",
            "process": "chrome.exe",
            "rag":     None,
            "vision":  False,
            "anomaly": False,
        },
        {
            "label":   "AWS key in IDE",
            "text":    "access_key = AKIAIOSFODNN7EXAMPLE",
            "process": "code.exe",
            "rag":     0.31,
            "vision":  False,
            "anomaly": False,
        },
        {
            "label":   "DB creds + anomaly",
            "text":    "postgresql://admin:secret123@db.internal:5432/prod",
            "process": "dbeaver.exe",
            "rag":     0.22,
            "vision":  False,
            "anomaly": True,
        },
        {
            "label":   "Screenshot with source code",
            "text":    "",
            "process": "chrome.exe",
            "rag":     None,
            "vision":  True,
            "anomaly": False,
        },
        {
            "label":   "Aadhaar + PAN + GSTIN combo",
            "text":    "Aadhaar: 2345 6789 0123  PAN: ABCDE1234F  GSTIN: 27ABCDE1234F1Z5",
            "process": "excel.exe",
            "rag":     0.18,
            "vision":  False,
            "anomaly": True,
        },
    ]

    print(f"\n{'='*70}")
    print(f"  Blip Sentinel — RiskScorer Self-Test")
    print(f"{'='*70}\n")

    for tc in test_cases:
        result = scorer.score_text(
            text            = tc["text"],
            active_process  = tc["process"],
            rag_distance    = tc["rag"],
            vision_flagged  = tc["vision"],
            anomaly_flagged = tc["anomaly"],
        )

        bar_filled = int(result.score / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)

        print(f"  {tc['label']}")
        print(f"  Score : {result.score:>3}/100  [{bar}]  "
              f"{result.emoji} {result.decision.value}")
        print(f"  Type  : {result.content_type.value}")
        print(f"  Signals: {result.breakdown.contributing_signals}")
        print(f"  Time  : {result.score_time_ms:.2f}ms")
        print()

    print(f"{'='*70}\n")