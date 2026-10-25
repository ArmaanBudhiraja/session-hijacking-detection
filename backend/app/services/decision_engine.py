from typing import Dict, Any, List, Tuple
from app.core.config import settings
from app.schemas.fingerprint import (
    FingerprintComparisonResult,
    MismatchedAttributeDetail
)

def compare_screen(expected: Dict[str, Any], actual: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Compares screen attributes with practical tolerances.
    Screen size can change on external monitor connection or window tiling,
    so we check resolution delta and aspect ratio.
    """
    exp_w, exp_h = expected.get("width", 0), expected.get("height", 0)
    act_w, act_h = actual.get("width", 0), actual.get("height", 0)

    if exp_w <= 0 or exp_h <= 0 or act_w <= 0 or act_h <= 0:
        return False, "Invalid screen dimensions"

    # Color depth mismatch is unusual for same device
    if expected.get("color_depth") != actual.get("color_depth"):
        return False, f"Color depth mismatch (expected {expected.get('color_depth')}bpp, got {actual.get('color_depth')}bpp)"

    # Resolution delta tolerance: allow +/- 15% for DPI scaling or taskbar changes
    w_delta = abs(exp_w - act_w) / max(exp_w, 1)
    h_delta = abs(exp_h - act_h) / max(exp_h, 1)

    if w_delta > 0.20 or h_delta > 0.20:
        return False, f"Screen resolution shifted significantly: {exp_w}x{exp_h} vs {act_w}x{act_h}"

    return True, "Screen dimensions within normal operational tolerance"

def compare_fingerprints(
    trusted_fp: Dict[str, Any],
    current_fp: Dict[str, Any]
) -> FingerprintComparisonResult:
    """
    Interpretable weighted browser fingerprint comparison engine.
    
    Formula:
      Mismatch Score = 100 * (Sum of weights for mismatched attributes / Sum of weights for comparable attributes)
      Similarity Score = 100 - Mismatch Score
    """
    weights = settings.ATTRIBUTE_WEIGHTS
    mismatched_attrs: List[MismatchedAttributeDetail] = []
    comparable_count = 0
    total_comparable_weight = 0.0
    total_mismatched_weight = 0.0

    # 1. Platform Comparison (Critical weight: 25.0)
    if trusted_fp.get("platform") and current_fp.get("platform"):
        comparable_count += 1
        w = weights.get("platform", 25.0)
        total_comparable_weight += w
        if trusted_fp["platform"] != current_fp["platform"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="platform",
                category="Operating System",
                weight=w,
                expected=trusted_fp["platform"],
                actual=current_fp["platform"],
                reason=f"OS Platform changed from {trusted_fp['platform']} to {current_fp['platform']}"
            ))

    # 2. Canvas Hash Comparison (Critical weight: 25.0)
    if trusted_fp.get("canvas_hash") and current_fp.get("canvas_hash"):
        comparable_count += 1
        w = weights.get("canvas_hash", 25.0)
        total_comparable_weight += w
        if trusted_fp["canvas_hash"] != current_fp["canvas_hash"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="canvas_hash",
                category="Hardware/Rendering",
                weight=w,
                expected=trusted_fp["canvas_hash"][:16] + "...",
                actual=current_fp["canvas_hash"][:16] + "...",
                reason="Deterministic 2D canvas drawing signature mismatch"
            ))

    # 3. User Agent Family (Weight: 20.0)
    if trusted_fp.get("user_agent_family") and current_fp.get("user_agent_family"):
        comparable_count += 1
        w = weights.get("user_agent_family", 20.0)
        total_comparable_weight += w
        if trusted_fp["user_agent_family"] != current_fp["user_agent_family"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="user_agent_family",
                category="Browser",
                weight=w,
                expected=trusted_fp["user_agent_family"],
                actual=current_fp["user_agent_family"],
                reason=f"Browser family mismatch ({trusted_fp['user_agent_family']} vs {current_fp['user_agent_family']})"
            ))

    # 4. WebGL Renderer (Weight: 15.0)
    if trusted_fp.get("webgl_renderer") and current_fp.get("webgl_renderer"):
        comparable_count += 1
        w = weights.get("webgl_renderer", 15.0)
        total_comparable_weight += w
        if trusted_fp["webgl_renderer"] != current_fp["webgl_renderer"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="webgl_renderer",
                category="Graphics Hardware",
                weight=w,
                expected=trusted_fp["webgl_renderer"],
                actual=current_fp["webgl_renderer"],
                reason="GPU / WebGL unmasked renderer hardware changed"
            ))

    # 5. Timezone (Weight: 15.0)
    if trusted_fp.get("timezone") and current_fp.get("timezone"):
        comparable_count += 1
        w = weights.get("timezone", 15.0)
        total_comparable_weight += w
        if trusted_fp["timezone"] != current_fp["timezone"]:
            # Also check timezone offset: if offset is identical, maybe DST or alias
            if trusted_fp.get("timezone_offset") != current_fp.get("timezone_offset"):
                total_mismatched_weight += w
                mismatched_attrs.append(MismatchedAttributeDetail(
                    attribute="timezone",
                    category="Localization",
                    weight=w,
                    expected=trusted_fp["timezone"],
                    actual=current_fp["timezone"],
                    reason=f"Timezone shifted from {trusted_fp['timezone']} to {current_fp['timezone']}"
                ))

    # 6. Hardware Concurrency (Weight: 10.0)
    if trusted_fp.get("hardware_concurrency") is not None and current_fp.get("hardware_concurrency") is not None:
        comparable_count += 1
        w = weights.get("hardware_concurrency", 10.0)
        total_comparable_weight += w
        if trusted_fp["hardware_concurrency"] != current_fp["hardware_concurrency"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="hardware_concurrency",
                category="Hardware",
                weight=w,
                expected=f"{trusted_fp['hardware_concurrency']} cores",
                actual=f"{current_fp['hardware_concurrency']} cores",
                reason=f"CPU core count discrepancy"
            ))

    # 7. Language (Weight: 10.0)
    if trusted_fp.get("language") and current_fp.get("language"):
        comparable_count += 1
        w = weights.get("language", 10.0)
        total_comparable_weight += w
        if trusted_fp["language"] != current_fp["language"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="language",
                category="Localization",
                weight=w,
                expected=trusted_fp["language"],
                actual=current_fp["language"],
                reason=f"Primary language changed from {trusted_fp['language']} to {current_fp['language']}"
            ))

    # 8. Screen Resolution & Color Depth (Weight: 10.0)
    if trusted_fp.get("screen") and current_fp.get("screen"):
        comparable_count += 1
        w = weights.get("screen", 10.0)
        total_comparable_weight += w
        screen_ok, screen_msg = compare_screen(trusted_fp["screen"], current_fp["screen"])
        if not screen_ok:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="screen",
                category="Display",
                weight=w,
                expected=f"{trusted_fp['screen'].get('width')}x{trusted_fp['screen'].get('height')}",
                actual=f"{current_fp['screen'].get('width')}x{current_fp['screen'].get('height')}",
                reason=screen_msg
            ))

    # 9. Device Memory (Weight: 8.0)
    if trusted_fp.get("device_memory") is not None and current_fp.get("device_memory") is not None:
        comparable_count += 1
        w = weights.get("device_memory", 8.0)
        total_comparable_weight += w
        if trusted_fp["device_memory"] != current_fp["device_memory"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="device_memory",
                category="Hardware",
                weight=w,
                expected=f"{trusted_fp['device_memory']} GB",
                actual=f"{current_fp['device_memory']} GB",
                reason="RAM device memory class mismatch"
            ))

    # 10. WebGL Vendor (Weight: 8.0)
    if trusted_fp.get("webgl_vendor") and current_fp.get("webgl_vendor"):
        comparable_count += 1
        w = weights.get("webgl_vendor", 8.0)
        total_comparable_weight += w
        if trusted_fp["webgl_vendor"] != current_fp["webgl_vendor"]:
            total_mismatched_weight += w
            mismatched_attrs.append(MismatchedAttributeDetail(
                attribute="webgl_vendor",
                category="Graphics Hardware",
                weight=w,
                expected=trusted_fp["webgl_vendor"],
                actual=current_fp["webgl_vendor"],
                reason="WebGL GPU vendor changed"
            ))

    # Minimum Evidence Policy Check
    if comparable_count < settings.MIN_EVIDENCE_COUNT:
        return FingerprintComparisonResult(
            similarity_score=0.0,
            mismatch_score=100.0,
            risk_level="HIGH",
            decision="CHALLENGE",
            mismatched_attributes=[MismatchedAttributeDetail(
                attribute="evidence_count",
                category="Integrity",
                weight=100.0,
                expected=f">= {settings.MIN_EVIDENCE_COUNT} attributes",
                actual=f"{comparable_count} attributes provided",
                reason="Insufficient browser characteristics provided to establish device context"
            )],
            comparable_attributes_count=comparable_count,
            total_weights_evaluated=total_comparable_weight,
            diagnostic_details={
                "policy": "fail_safe_insufficient_evidence",
                "comparable_count": comparable_count,
                "required_count": settings.MIN_EVIDENCE_COUNT
            }
        )

    # Calculate Mismatch and Similarity Scores
    if total_comparable_weight > 0:
        mismatch_score = round(100.0 * (total_mismatched_weight / total_comparable_weight), 2)
    else:
        mismatch_score = 0.0

    similarity_score = round(100.0 - mismatch_score, 2)

    # Determine Decision and Risk Level
    if mismatch_score >= settings.MISMATCH_REVOKE_THRESHOLD:
        decision = "BLOCK_REVOKE"
        risk_level = "CRITICAL"
    elif mismatch_score >= settings.MISMATCH_FLAG_THRESHOLD:
        decision = "CHALLENGE"
        risk_level = "HIGH"
    elif similarity_score >= 85.0:
        decision = "ALLOW"
        risk_level = "LOW"
    else:
        decision = "ALLOW"
        risk_level = "MEDIUM"

    diagnostic_details = {
        "mismatched_count": len(mismatched_attrs),
        "comparable_count": comparable_count,
        "total_comparable_weight": round(total_comparable_weight, 2),
        "total_mismatched_weight": round(total_mismatched_weight, 2),
        "threshold_revoke": settings.MISMATCH_REVOKE_THRESHOLD,
        "threshold_flag": settings.MISMATCH_FLAG_THRESHOLD
    }

    return FingerprintComparisonResult(
        similarity_score=similarity_score,
        mismatch_score=mismatch_score,
        risk_level=risk_level,
        decision=decision,
        mismatched_attributes=mismatched_attrs,
        comparable_attributes_count=comparable_count,
        total_weights_evaluated=total_comparable_weight,
        diagnostic_details=diagnostic_details
    )
