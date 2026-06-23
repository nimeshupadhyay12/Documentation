"""
integrations/notifiers.py  -  Anomaly Hunter Pro
==================================================
Alert notification integrations.

Supported:
  - Slack webhook
  - Microsoft Teams webhook
  - Generic HTTP webhook (JSON POST)
  - Console (always on)

Configure via environment variables:
  AH_SLACK_WEBHOOK    = https://hooks.slack.com/services/...
  AH_TEAMS_WEBHOOK    = https://your-org.webhook.office.com/...
  AH_WEBHOOK_URL      = https://your-siem.example.com/alerts
  AH_NOTIFY_MIN_SEV   = CRITICAL  (minimum severity to notify, default HIGH)
"""

import os
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime

import pandas as pd

log = logging.getLogger("AnomalyHunter.Notifiers")

SLACK_WEBHOOK  = os.getenv("AH_SLACK_WEBHOOK", "")
TEAMS_WEBHOOK  = os.getenv("AH_TEAMS_WEBHOOK", "")
GENERIC_WEBHOOK= os.getenv("AH_WEBHOOK_URL", "")
MIN_SEVERITY   = os.getenv("AH_NOTIFY_MIN_SEV", "HIGH")

SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _should_notify(severity: str) -> bool:
    return SEV_ORDER.get(severity, 0) >= SEV_ORDER.get(MIN_SEVERITY, 3)


def _post_json(url: str, payload: dict, timeout: int = 8) -> bool:
    try:
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json",
                     "User-Agent": "AnomalyHunterPro/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status in (200, 204)
    except Exception as e:
        log.warning("Webhook POST failed: %s", e)
        return False


# ── Slack ─────────────────────────────────────────────────────────────────────

def _build_slack_payload(alerts_df: pd.DataFrame, run_id: str = "") -> dict:
    """Build Slack Block Kit message for top alerts."""
    top = alerts_df.sort_values("Risk Score", ascending=False).head(5)

    sev_counts = alerts_df["Severity"].value_counts().to_dict()
    summary    = " | ".join(f"{s}: {c}" for s, c in sev_counts.items()
                            if SEV_ORDER.get(s, 0) >= 2)
    overall_sev= top.iloc[0]["Severity"] if not top.empty else "UNKNOWN"
    emoji      = SEV_EMOJI.get(overall_sev, "⚪")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Anomaly Hunter Alert — {overall_sev}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Alerts:*\n{len(alerts_df)}"},
                {"type": "mrkdwn", "text": f"*Summary:*\n{summary}"},
                {"type": "mrkdwn", "text": f"*Run ID:*\n{run_id or 'N/A'}"},
                {"type": "mrkdwn",
                 "text": f"*Time:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"},
            ],
        },
        {"type": "divider"},
    ]

    for _, row in top.iterrows():
        proc  = str(row.get("Process","")).split("\\")[-1]
        det   = str(row.get("Detection Type",""))[:60]
        score = row.get("Risk Score", 0)
        sev   = row.get("Severity", "")
        e     = SEV_EMOJI.get(sev, "•")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{e} *{sev}* | `{proc}` | {det} | score={score}",
            },
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": "Anomaly Hunter Pro — For analyst use only"}],
    })

    return {"text": f"{emoji} Anomaly Hunter: {len(alerts_df)} alerts detected",
            "blocks": blocks}


def notify_slack(alerts_df: pd.DataFrame, run_id: str = "") -> bool:
    if not SLACK_WEBHOOK:
        return False

    # Filter to notifiable severity
    filtered = alerts_df[alerts_df["Severity"].apply(_should_notify)]
    if filtered.empty:
        return False

    payload = _build_slack_payload(filtered, run_id)
    ok = _post_json(SLACK_WEBHOOK, payload)
    if ok:
        log.info("Slack notification sent (%d alerts)", len(filtered))
    return ok


# ── Microsoft Teams ──────────────────────────────────────────────────────────

def _build_teams_payload(alerts_df: pd.DataFrame) -> dict:
    """Build Adaptive Card payload for Teams."""
    top = alerts_df.sort_values("Risk Score", ascending=False).head(5)
    overall_sev = top.iloc[0]["Severity"] if not top.empty else "UNKNOWN"
    emoji = SEV_EMOJI.get(overall_sev, "⚪")

    facts = []
    for _, row in top.iterrows():
        proc  = str(row.get("Process","")).split("\\")[-1]
        det   = str(row.get("Detection Type",""))[:50]
        score = row.get("Risk Score", 0)
        facts.append({
            "name":  f"[{row.get('Severity','')}] {proc}",
            "value": f"{det} (score={score})"
        })

    return {
        "@type":      "MessageCard",
        "@context":   "http://schema.org/extensions",
        "themeColor": "cc0000" if overall_sev == "CRITICAL" else "e67e22",
        "summary":    f"Anomaly Hunter: {len(alerts_df)} alerts",
        "sections": [{
            "activityTitle":    f"{emoji} Anomaly Hunter Alert — {overall_sev}",
            "activitySubtitle": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "activityText":     f"{len(alerts_df)} alerts detected",
            "facts":            facts,
        }],
    }


def notify_teams(alerts_df: pd.DataFrame) -> bool:
    if not TEAMS_WEBHOOK:
        return False

    filtered = alerts_df[alerts_df["Severity"].apply(_should_notify)]
    if filtered.empty:
        return False

    payload = _build_teams_payload(filtered)
    ok = _post_json(TEAMS_WEBHOOK, payload)
    if ok:
        log.info("Teams notification sent (%d alerts)", len(filtered))
    return ok


# ── Generic webhook ───────────────────────────────────────────────────────────

def notify_webhook(alerts_df: pd.DataFrame, run_id: str = "") -> bool:
    """POST alerts as JSON to a generic webhook URL."""
    if not GENERIC_WEBHOOK:
        return False

    filtered = alerts_df[alerts_df["Severity"].apply(_should_notify)]
    if filtered.empty:
        return False

    payload = {
        "source":      "AnomalyHunterPro",
        "run_id":      run_id,
        "generated":   datetime.now().isoformat(),
        "alert_count": len(filtered),
        "alerts": filtered.head(20).fillna("").to_dict("records"),
    }

    ok = _post_json(GENERIC_WEBHOOK, payload)
    if ok:
        log.info("Generic webhook notification sent (%d alerts)", len(filtered))
    return ok


# ── Master notifier ───────────────────────────────────────────────────────────

def send_all_notifications(alerts_df: pd.DataFrame,
                            incidents_df: pd.DataFrame = None,
                            run_id: str = "") -> dict:
    """
    Send notifications to all configured channels.
    Returns dict of {channel: success_bool}.
    """
    if alerts_df is None or alerts_df.empty:
        return {}

    results = {}

    if SLACK_WEBHOOK:
        results["slack"] = notify_slack(alerts_df, run_id)

    if TEAMS_WEBHOOK:
        results["teams"] = notify_teams(alerts_df)

    if GENERIC_WEBHOOK:
        results["webhook"] = notify_webhook(alerts_df, run_id)

    if results:
        log.info("Notifications: %s", results)
    else:
        log.debug("No notification channels configured")

    return results


def get_configured_channels() -> list:
    """Return list of configured notification channels."""
    channels = []
    if SLACK_WEBHOOK:  channels.append("Slack")
    if TEAMS_WEBHOOK:  channels.append("Microsoft Teams")
    if GENERIC_WEBHOOK:channels.append("Generic Webhook")
    return channels
