import math
from typing import Dict, List, Any
from app.core.config import settings


class RiskScorer:
    """
    Calculates overall scan risk score (0.0 to 100.0).
    Considers severity weights, total findings count, and distinct affected resources.
    """

    def __init__(
        self,
        weight_critical: float = None,
        weight_high: float = None,
        weight_medium: float = None,
        weight_low: float = None,
        weight_info: float = None,
    ):
        self.weights = {
            "CRITICAL": weight_critical if weight_critical is not None else settings.WEIGHT_CRITICAL,
            "HIGH": weight_high if weight_high is not None else settings.WEIGHT_HIGH,
            "MEDIUM": weight_medium if weight_medium is not None else settings.WEIGHT_MEDIUM,
            "LOW": weight_low if weight_low is not None else settings.WEIGHT_LOW,
            "INFO": weight_info if weight_info is not None else settings.WEIGHT_INFO,
        }

    def calculate(self, findings: List[Dict[str, Any]], total_resources: int = 1) -> Dict[str, Any]:
        """
        Calculates:
        1. Severity counts
        2. Deduplicated affected resource count
        3. Overall risk score normalized between 0.0 and 100.0
        """
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        affected_resources = set()
        raw_weighted_sum = 0.0

        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
                raw_weighted_sum += self.weights.get(sev, 0.0)
            res_id = f.get("resource_id")
            if res_id:
                affected_resources.add(res_id)

        # Non-linear asymptotic saturation curve: Score = 100 * (1 - e^(-weighted_sum / 35))
        # 0 weighted sum => 0.0
        # 1 Critical (weight 10) => ~25.0
        # 2 Critical + 2 High (weight 34) => ~62.0
        # Large volume of critical/high asymptotically approaches 100.0 without overflow
        if raw_weighted_sum <= 0.0:
            risk_score = 0.0
        else:
            scaled = 100.0 * (1.0 - math.exp(-raw_weighted_sum / 35.0))
            risk_score = min(100.0, max(0.0, round(scaled, 1)))

        return {
            "risk_score": risk_score,
            "counts": counts,
            "distinct_resources_affected": len(affected_resources),
            "raw_weighted_sum": round(raw_weighted_sum, 2),
            "weights_used": self.weights,
        }
