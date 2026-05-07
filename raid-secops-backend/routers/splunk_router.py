"""
RAID-SecOps — Splunk Integration Router
=========================================
Three endpoints:

  GET  /splunk/status          — health check, used by Pipeline Status page
  POST /splunk/alert-webhook   — Splunk pushes alerts to us
  POST /splunk/pull            — we pull recent events from Splunk REST API
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional
from config import settings

import requests
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db
from alert_models import Alert
from routers.ml_router import _models, _run_rf, _run_if, _hybrid_decision, _build_role_recs, models_ready, MITRE_MAP

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/splunk", tags=["splunk"])

# ── Role assignment map ───────────────────────────────────────
ROLE_MAP = {
    "Fuzzers":        "analyst",
    "Analysis":       "analyst",
    "Backdoor":       "engineer",
    "DoS":            "engineer",
    "Exploits":       "analyst",
    "Generic":        "analyst",
    "Reconnaissance": "analyst",
    "Shellcode":      "engineer",
    "Worms":          "engineer",
    "Normal":         "analyst",
    "Unknown":        "analyst",
}

# ── User assignment map ───────────────────────────────────────
USER_MAP = {
    "analyst":  ["r.reddy", "b.bindu"],
    "engineer": ["k.magora", "a.kasala"],
    "grc":      ["f.sagayaraj", "r.mashinge"],
}

# ── Feature columns the ML models expect ─────────────────────
FEATURE_COLS = [
    "dur", "proto", "service", "state",
    "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
    "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]

DEFAULTS = {
    "dur": 0.0, "spkts": 0, "dpkts": 0, "sbytes": 0, "dbytes": 0,
    "rate": 0.0, "sttl": 63, "dttl": 63, "sload": 0.0, "dload": 0.0,
    "sloss": 0, "dloss": 0, "sinpkt": 0.0, "dinpkt": 0.0,
    "sjit": 0.0, "djit": 0.0, "swin": 0, "stcpb": 0, "dtcpb": 0,
    "dwin": 0, "tcprtt": 0.0, "synack": 0.0, "ackdat": 0.0,
    "smean": 0.0, "dmean": 0.0, "trans_depth": 0, "response_body_len": 0,
    "ct_srv_src": 1, "ct_state_ttl": 1, "ct_dst_ltm": 1,
    "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "ct_dst_src_ltm": 1,
    "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0,
    "ct_src_ltm": 1, "ct_srv_dst": 1, "is_sm_ips_ports": 0,
    "proto": "tcp", "service": "-", "state": "FIN",
}

INT_COLS = {
    "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "swin", "stcpb", "dtcpb", "dwin",
    "trans_depth", "response_body_len", "ct_srv_src", "ct_state_ttl",
    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm",
    "ct_srv_dst", "is_sm_ips_ports",
}

_event_counter = 0


def flatten_splunk_event(body: dict) -> list:
    """
    Parse Splunk webhook payload.
    The most reliable source is _raw which contains the original
    JSON string we sent to HEC. Parse that directly to avoid
    Splunk multi-value list issues caused by spath field extraction.

    Priority order:
    1. result._raw  -> parse JSON string -> clean event dict
    2. results[]._raw -> parse each JSON string
    3. result fields directly (may be lists, handled downstream)
    4. body directly
    """
    events = []

    result = body.get("result")
    if result and isinstance(result, dict):
        # Priority 1: parse _raw JSON string directly
        raw = result.get("_raw", "")
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and parsed.get("event_id"):
                    events.append(parsed)
                    return events
            except Exception:
                pass
        # Fallback: use result fields as-is
        events.append(result)
        return events

    # results array
    results_list = body.get("results")
    if results_list and isinstance(results_list, list):
        for r in results_list:
            if not isinstance(r, dict):
                continue
            raw = r.get("_raw", "")
            if raw:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        events.append(parsed)
                        continue
                except Exception:
                    pass
            events.append(r)
        return events

    # Direct body
    if body.get("event_id") or body.get("attack_cat"):
        events.append(body)
        return events

    events.append(body)
    return events


def get_attack_cat(event_data: dict) -> str:
    """Extract attack category — tries all known field name variants."""
    cat = (
        event_data.get("attack_cat")
        or event_data.get("_attack_cat")
        or event_data.get("attack_category")
        or "Unknown"
    )
    # Splunk multi-value fields arrive as Python lists — take first element
    if isinstance(cat, list):
        cat = cat[0] if cat else "Unknown"
    cat = str(cat).strip() if cat else "Unknown"
    if cat.lower() in ("", "none", "null", "unknown"):
        return "Unknown"
    return cat


def get_assigned_role(attack_cat: str) -> str:
    return ROLE_MAP.get(attack_cat, "analyst")


def get_assigned_user(role: str, counter: int) -> str:
    users = USER_MAP.get(role, ["r.reddy"])
    return users[counter % len(users)]


def extract_features(event_data: dict) -> dict:
    features = {}
    for col in FEATURE_COLS:
        val = event_data.get(col, DEFAULTS.get(col, 0))
        # Splunk multi-value fields arrive as Python lists — take first element
        if isinstance(val, list):
            val = val[0] if val else DEFAULTS.get(col, 0)
        if col not in ("proto", "service", "state"):
            try:
                val = int(float(val)) if col in INT_COLS else float(val)
            except (ValueError, TypeError):
                val = DEFAULTS.get(col, 0)
        features[col] = val
    return features


async def score_and_save(
    sample_id:     str,
    features:      dict,
    attack_cat:    str,
    source_siem:   str,
    raw_log:       str,
    assigned_role: str,
    assigned_to:   str,
    db:            AsyncSession,
) -> Optional[dict]:
    existing = await db.execute(select(Alert).where(Alert.sample_id == sample_id))
    if existing.scalar_one_or_none():
        return None

    features_df = pd.DataFrame([features])
    rf_pred, rf_proba = _run_rf(features_df)
    if_threshold      = _models.get("if_threshold", 0.008)
    if_score          = _run_if(features_df)

    hybrid_pred, confidence, defer, models_agree = _hybrid_decision(
        rf_proba, if_score, if_threshold
    )

    status = "ATTACK" if hybrid_pred == 1 else "NORMAL"

    # Only assign attack type and MITRE if ML classified as ATTACK
    # AND the attack category is a real attack (not Normal or Unknown)
    effective_attack_cat = (
        attack_cat
        if status == "ATTACK" and attack_cat not in ("Normal", "Unknown", "—")
        else "—"
    )
    mitre = (
        MITRE_MAP.get(attack_cat, "—")
        if status == "ATTACK" and attack_cat not in ("Normal", "Unknown", "—")
        else "—"
    )

    rec_analyst, rec_engineer, rec_grc = _build_role_recs(
        sample_id    = sample_id,
        status       = status,
        confidence   = confidence,
        attack_cat   = effective_attack_cat,
        if_score     = if_score,
        rf_proba     = rf_proba,
        defer        = defer,
        models_agree = models_agree,
    )

    alert = Alert(
        sample_id                = sample_id,
        siem_event_id            = sample_id,
        timestamp                = datetime.now(timezone.utc),
        source_siem              = source_siem,
        status                   = status,
        confidence               = round(confidence, 4),
        attack_type              = effective_attack_cat,
        mitre_technique          = mitre,
        isolation_forest_score   = round(if_score, 4),
        random_forest_confidence = round(rf_proba, 4),
        final_prediction         = status,
        models_agree             = models_agree,
        defer_to_human           = defer,
        investigation_status     = "open",
        assigned_role            = assigned_role,
        assigned_to              = assigned_to,
        rec_analyst              = rec_analyst,
        rec_engineer             = rec_engineer,
        rec_grc                  = rec_grc,
        raw_log                  = raw_log,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    return {
        "sample_id":     sample_id,
        "status":        status,
        "confidence":    round(confidence, 4),
        "attack_type":   attack_cat,
        "assigned_role": assigned_role,
        "assigned_to":   assigned_to,
        "defer":         defer,
    }


# ── ENDPOINT 1: Health check ──────────────────────────────────

@router.get("/status")
async def splunk_status():
    hec_url   = settings.SPLUNK_HEC_URL
    hec_token = settings.SPLUNK_HEC_TOKEN
    hec_ok    = False
    hec_msg   = "HEC token not configured"
    if hec_token:
        try:
            r = requests.get(
                f"{hec_url}/services/collector/health",
                headers={"Authorization": f"Splunk {hec_token}"},
                timeout=3,
            )
            hec_ok  = r.status_code in (200, 204)
            hec_msg = "Connected" if hec_ok else f"HTTP {r.status_code}"
        except Exception as e:
            hec_msg = f"Unreachable: {str(e)[:80]}"
    return {
        "splunk_hec_url":    hec_url,
        "splunk_hec_ok":     hec_ok,
        "splunk_hec_status": hec_msg,
        "ml_models_ready":   models_ready(),
    }


# ── ENDPOINT 2: Receive Splunk webhook ────────────────────────

@router.post("/alert-webhook", status_code=201)
async def receive_splunk_webhook(
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    global _event_counter

    if not models_ready():
        raise HTTPException(503, "ML models not loaded")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON payload from Splunk")

    # DEBUG — print raw payload structure to FastAPI terminal
    print(f"[SPLUNK] Raw keys: {list(body.keys()) if isinstance(body, dict) else type(body)}")
    result_raw = body.get("result", {})
    if isinstance(result_raw, dict):
        print(f"[SPLUNK] Result keys: {list(result_raw.keys())[:20]}")
        print(f"[SPLUNK] attack_cat='{result_raw.get('attack_cat', 'MISSING')}' event_id='{result_raw.get('event_id', 'MISSING')}'")

    # Flatten whatever Splunk sends into a clean list of event dicts
    events = flatten_splunk_event(body)

    saved   = []
    skipped = 0

    for i, event_data in enumerate(events):
        attack_cat    = get_attack_cat(event_data)
        assigned_role = get_assigned_role(attack_cat)
        assigned_to   = get_assigned_user(assigned_role, _event_counter)
        _event_counter += 1

        event_id  = event_data.get("event_id") or f"SPL-{int(time.time())}-{i}"
        # Splunk multi-value fields arrive as lists — take first element
        if isinstance(event_id, list):
            event_id = event_id[0] if event_id else f"SPL-{int(time.time())}-{i}"
        sample_id = f"SPL-{event_id}"
        raw_log   = json.dumps(event_data)[:1000]
        features  = extract_features(event_data)

        print(f"[SPLUNK] Processing: {sample_id} | cat={attack_cat} | role={assigned_role}")

        result = await score_and_save(
            sample_id     = sample_id,
            features      = features,
            attack_cat    = attack_cat,
            source_siem   = "Splunk",
            raw_log       = raw_log,
            assigned_role = assigned_role,
            assigned_to   = assigned_to,
            db            = db,
        )

        if result:
            saved.append(result)
            print(f"[SPLUNK] SAVED {sample_id}: {result['status']} ({result['confidence']:.0%}) cat={attack_cat} role={assigned_role}")
        else:
            skipped += 1
            print(f"[SPLUNK] SKIPPED {sample_id}: duplicate")

    return {
        "message": f"Processed {len(events)} events",
        "saved":   len(saved),
        "skipped": skipped,
        "results": saved,
    }


# ── ENDPOINT 3: Pull from Splunk REST API ─────────────────────

@router.post("/pull")
async def pull_from_splunk(
    minutes_back: int = 5,
    db:           AsyncSession = Depends(get_db),
):
    global _event_counter

    if not models_ready():
        raise HTTPException(503, "ML models not loaded")

    splunk_host = settings.SPLUNK_HOST
    username    = settings.SPLUNK_USERNAME
    password    = settings.SPLUNK_PASSWORD

    if not password:
        raise HTTPException(400, "SPLUNK_PASSWORD not set in .env")

    search_query = f'search index=main source=raid-secops earliest=-{minutes_back}m | head 50'

    try:
        auth = (username, password)
        r = requests.post(
            f"{splunk_host}/services/search/jobs",
            auth=auth,
            data={"search": search_query, "output_mode": "json"},
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        job_id = r.json()["sid"]

        for _ in range(30):
            time.sleep(1)
            sr = requests.get(
                f"{splunk_host}/services/search/jobs/{job_id}",
                auth=auth,
                params={"output_mode": "json"},
                verify=False,
                timeout=10,
            )
            if sr.json()["entry"][0]["content"]["dispatchState"] == "DONE":
                break

        rr = requests.get(
            f"{splunk_host}/services/search/jobs/{job_id}/results",
            auth=auth,
            params={"output_mode": "json", "count": 50},
            verify=False,
            timeout=15,
        )
        events_raw = rr.json().get("results", [])

    except Exception as e:
        raise HTTPException(500, f"Splunk REST API error: {str(e)}")

    saved   = []
    skipped = 0

    for i, event_data in enumerate(events_raw):
        attack_cat    = get_attack_cat(event_data)
        assigned_role = get_assigned_role(attack_cat)
        assigned_to   = get_assigned_user(assigned_role, _event_counter)
        _event_counter += 1

        event_id  = event_data.get("event_id") or f"PULL-{int(time.time())}-{i}"
        sample_id = f"SPL-{event_id}"
        features  = extract_features(event_data)

        result = await score_and_save(
            sample_id     = sample_id,
            features      = features,
            attack_cat    = attack_cat,
            source_siem   = "Splunk",
            raw_log       = json.dumps(event_data)[:1000],
            assigned_role = assigned_role,
            assigned_to   = assigned_to,
            db            = db,
        )
        if result:
            saved.append(result)
        else:
            skipped += 1

    return {
        "message": f"Pulled {len(events_raw)} events from Splunk",
        "saved":   len(saved),
        "skipped": skipped,
        "results": saved,
    }
