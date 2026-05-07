"""
RAID-SecOps — Splunk Connection Test
======================================
Run this to verify the full Splunk connection is working.

    python test_splunk_connection.py

Place this file in your raid-secops-backend folder and run with venv active.
"""

import os
import time
import requests
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent / ".env")

BASE       = "http://localhost:8000"
HEC_URL    = os.getenv("SPLUNK_HEC_URL", "http://localhost:8088")
HEC_TOKEN  = os.getenv("SPLUNK_HEC_TOKEN", "")

print("=" * 55)
print("  RAID-SecOps — Splunk Connection Test")
print("=" * 55)
print(f"  HEC URL   : {HEC_URL}")
print(f"  HEC Token : {HEC_TOKEN[:8]}...{HEC_TOKEN[-4:] if len(HEC_TOKEN) > 12 else '?'}")
print()

# Test 1: FastAPI health
print("[1] Checking FastAPI is running...")
try:
    r = requests.get(f"{BASE}/health", timeout=5)
    d = r.json()
    print(f"  Status  : {r.status_code}")
    print(f"  Response: {d}")
    print("  OK FastAPI is up\n")
except Exception as e:
    print(f"  FAILED: {e}")
    print("  Make sure FastAPI is running: python -m uvicorn main:app --reload --port 8000\n")

# Test 2: ML models loaded
print("[2] Checking ML models are loaded...")
try:
    r = requests.get(f"{BASE}/ml/status", timeout=5)
    d = r.json()
    print(f"  Models ready : {d.get('models_ready')}")
    print(f"  Models loaded: {d.get('models_loaded')}")
    print(f"  Feature count: {d.get('feature_count')}")
    if d.get("models_ready"):
        print("  OK ML models ready\n")
    else:
        print("  WARNING: ML models not loaded - check ML_MODEL_DIR in .env\n")
except Exception as e:
    print(f"  FAILED: {e}\n")

# Test 3: Splunk HEC health via FastAPI
print("[3] Checking Splunk HEC status via FastAPI...")
try:
    r = requests.get(f"{BASE}/splunk/status", timeout=5)
    d = r.json()
    print(f"  HEC OK    : {d.get('splunk_hec_ok')}")
    print(f"  HEC status: {d.get('splunk_hec_status')}")
    if d.get("splunk_hec_ok"):
        print("  OK Splunk HEC is reachable\n")
    else:
        print("  WARNING: Splunk HEC not reachable")
        print("  Check: HEC enabled in Splunk? Token correct in .env?\n")
except Exception as e:
    print(f"  FAILED: {e}\n")

# Test 4: Send one event directly to Splunk HEC
print("[4] Sending test event directly to Splunk HEC...")
if not HEC_TOKEN:
    print("  SKIPPED: SPLUNK_HEC_TOKEN not set in .env\n")
else:
    payload = {
        "time":       time.time(),
        "host":       "raid-secops-test",
        "source":     "raid-secops",
        "sourcetype": "_json",
        "index":      "main",
        "event": {
            "event_id":    "TEST-HEC-001",
            "_attack_cat": "DoS",
            "test":        True,
            "message":     "RAID-SecOps HEC connection test"
        }
    }
    try:
        r = requests.post(
            f"{HEC_URL}/services/collector/event",
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            json=payload,
            timeout=5,
        )
        print(f"  HTTP Status : {r.status_code}")
        print(f"  Response    : {r.text}")
        if r.status_code == 200:
            print("  OK Event sent to Splunk successfully\n")
        else:
            print("  FAILED: Check HEC is enabled and token is correct\n")
    except Exception as e:
        print(f"  FAILED: {e}")
        print("  Is Splunk running? Is port 8088 open?\n")

# Test 5: Simulate Splunk webhook to FastAPI
print("[5] Simulating Splunk webhook to FastAPI /splunk/alert-webhook...")
webhook_payload = {
    "result": {
        "event_id":    "TEST-WEBHOOK-001",
        "_attack_cat": "Reconnaissance",
        "dur": 0.1, "proto": "tcp", "service": "-", "state": "REQ",
        "spkts": 3, "dpkts": 1, "sbytes": 120, "dbytes": 40,
        "rate": 30.0, "sttl": 63, "dttl": 63,
        "sload": 9600.0, "dload": 3200.0,
        "sloss": 0, "dloss": 0, "sinpkt": 0.03, "dinpkt": 0.1,
        "sjit": 0.001, "djit": 0.001,
        "swin": 0, "stcpb": 0, "dtcpb": 0, "dwin": 0,
        "tcprtt": 0.0, "synack": 0.0, "ackdat": 0.0,
        "smean": 40.0, "dmean": 40.0,
        "trans_depth": 0, "response_body_len": 0,
        "ct_srv_src": 1, "ct_state_ttl": 2, "ct_dst_ltm": 1,
        "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "ct_dst_src_ltm": 1,
        "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0,
        "ct_src_ltm": 1, "ct_srv_dst": 1, "is_sm_ips_ports": 0,
    }
}
try:
    r = requests.post(
        f"{BASE}/splunk/alert-webhook",
        json=webhook_payload,
        timeout=30,
    )
    print(f"  HTTP Status : {r.status_code}")
    if r.status_code == 201:
        d = r.json()
        print(f"  Saved   : {d.get('saved')}")
        print(f"  Skipped : {d.get('skipped')} (0=new, 1=already exists)")
        if d.get("results"):
            res = d["results"][0]
            print(f"  Alert   : {res['sample_id']} -> {res['status']} ({res['confidence']:.0%})")
        print("  OK Webhook working — check Alerts Queue in UI")
    elif r.status_code == 409:
        print("  Already exists — duplicate prevention working OK")
    else:
        print(f"  Response: {r.text[:300]}")
except Exception as e:
    print(f"  FAILED: {e}")

print()
print("=" * 55)
print("  Done.")
print("  If Test 4 OK: Splunk is receiving events")
print("  If Test 5 OK: Full pipeline is connected")
print("  Open http://localhost:5173/alerts to see scored alerts")
print("=" * 55)
