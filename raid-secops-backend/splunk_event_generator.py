"""
RAID-SecOps — Splunk Event Generator
======================================
Generates fake network events and sends them to Splunk via HEC.
Splunk then fires the alert webhook to FastAPI which scores each event.

Usage:
    python splunk_event_generator.py

Auto-detects the highest existing event number from the database
on startup to avoid duplicate sample IDs every time it restarts.
"""

import os
import time
import random
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent / ".env")

HEC_URL   = os.getenv("SPLUNK_HEC_URL",   "http://localhost:8088")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
INTERVAL  = 10   # seconds between events

if not HEC_TOKEN:
    print("ERROR: SPLUNK_HEC_TOKEN not set in .env")
    exit(1)

# Attack profiles — (weight, feature ranges)
PROFILES = {
    "Normal":         {"w": 70, "spkts": (2,20),     "sbytes": (60,600),     "rate": (10,200),       "proto": ["tcp","udp"], "state": ["FIN","CON"],       "dur": (0.01,2.0)},
    "DoS":            {"w": 6,  "spkts": (1000,8000), "sbytes": (50000,500000),"rate": (500000,5000000),"proto": ["udp","tcp"],"state": ["CON","INT"],       "dur": (0.000001,0.01)},
    "Exploits":       {"w": 8,  "spkts": (10,80),     "sbytes": (500,8000),   "rate": (5,100),        "proto": ["tcp"],       "state": ["FIN","CON"],        "dur": (0.5,30.0)},
    "Reconnaissance": {"w": 7,  "spkts": (1,5),       "sbytes": (40,200),     "rate": (1,500),        "proto": ["tcp","udp"], "state": ["REQ","INT","CON"],  "dur": (0.001,0.5)},
    "Generic":        {"w": 5,  "spkts": (3,30),      "sbytes": (100,2000),   "rate": (10,300),       "proto": ["tcp","udp"], "state": ["FIN","CON"],        "dur": (0.1,5.0)},
    "Backdoor":       {"w": 2,  "spkts": (5,50),      "sbytes": (200,3000),   "rate": (1,20),         "proto": ["tcp"],       "state": ["CON"],              "dur": (10.0,300.0)},
    "Fuzzers":        {"w": 2,  "spkts": (20,200),    "sbytes": (1000,20000), "rate": (100,5000),     "proto": ["tcp"],       "state": ["FIN","CON"],        "dur": (0.01,0.5)},
}

cats    = list(PROFILES.keys())
weights = [PROFILES[c]["w"] for c in cats]


def rnd(lo, hi):
    return round(random.uniform(lo, hi), 4)


def make_event(cat, n):
    p      = PROFILES[cat]
    dur    = rnd(*p["dur"])
    spkts  = random.randint(*[int(x) for x in p["spkts"]])
    dpkts  = random.randint(0, max(1, spkts // 2))
    sbytes = random.randint(*[int(x) for x in p["sbytes"]])
    dbytes = random.randint(0, sbytes)
    rate   = rnd(*p["rate"])
    proto  = random.choice(p["proto"])
    state  = random.choice(p["state"])
    svc    = random.choice(["-", "http", "ftp"]) if cat == "Normal" else "-"

    return {
        "event_id":          f"GEN2-{n:05d}",
        "attack_cat":         cat,
        "_generator":         "raid-secops",
        "_timestamp":         datetime.now(timezone.utc).isoformat(),
        "dur":                dur,
        "proto":              proto,
        "service":            svc,
        "state":              state,
        "spkts":              spkts,
        "dpkts":              dpkts,
        "sbytes":             sbytes,
        "dbytes":             dbytes,
        "rate":               rate,
        "sttl":               random.choice([63, 127, 255]),
        "dttl":               random.choice([63, 127, 252]),
        "sload":              round(sbytes * 8 / max(dur, 0.001), 2),
        "dload":              round(dbytes * 8 / max(dur, 0.001), 2),
        "sloss":              random.randint(0, 2),
        "dloss":              random.randint(0, 2),
        "sinpkt":             round(dur / max(spkts, 1), 4),
        "dinpkt":             round(dur / max(dpkts, 1), 4),
        "sjit":               round(random.uniform(0, 0.05), 4),
        "djit":               round(random.uniform(0, 0.05), 4),
        "swin":               random.choice([0, 255, 512, 1024]),
        "stcpb":              random.randint(0, 9999999),
        "dtcpb":              random.randint(0, 9999999),
        "dwin":               random.choice([0, 255, 512, 1024]),
        "tcprtt":             round(random.uniform(0, 0.1), 4),
        "synack":             round(random.uniform(0, 0.05), 4),
        "ackdat":             round(random.uniform(0, 0.05), 4),
        "smean":              round(sbytes / max(spkts, 1), 1),
        "dmean":              round(dbytes / max(dpkts, 1), 1),
        "trans_depth":        random.randint(0, 3),
        "response_body_len":  random.randint(0, 5000),
        "ct_srv_src":         random.randint(1, 20),
        "ct_state_ttl":       random.randint(1, 6),
        "ct_dst_ltm":         random.randint(1, 10),
        "ct_src_dport_ltm":   random.randint(1, 10),
        "ct_dst_sport_ltm":   random.randint(1, 10),
        "ct_dst_src_ltm":     random.randint(1, 20),
        "is_ftp_login":       1 if svc == "ftp" and cat != "Normal" else 0,
        "ct_ftp_cmd":         random.randint(0, 5) if svc == "ftp" else 0,
        "ct_flw_http_mthd":   random.randint(0, 3) if svc == "http" else 0,
        "ct_src_ltm":         random.randint(1, 10),
        "ct_srv_dst":         random.randint(1, 20),
        "is_sm_ips_ports":    0,
    }


def send(event, cat):
    payload = {
        "time":       time.time(),
        "host":       "raid-secops-generator",
        "source":     "raid-secops",
        "sourcetype": "_json",
        "index":      "main",
        "event":      event,
    }
    r = requests.post(
        f"{HEC_URL}/services/collector/event",
        headers={"Authorization": f"Splunk {HEC_TOKEN}"},
        json=payload,
        timeout=5,
    )
    return r.status_code == 200


def get_start_number():
    """
    Auto-detect the highest GEN2 event number already in the database.
    This prevents duplicate sample IDs every time the generator restarts.
    """
    try:
        import psycopg2
        from dotenv import dotenv_values
        env = dotenv_values(Path(__file__).parent / ".env")
        # Parse password from DATABASE_URL
        db_url = env.get("DATABASE_URL", "")
        # Extract password between : and @ after postgres:
        import re
        match = re.search(r'postgres:([^@]+)@', db_url)
        password = match.group(1) if match else "raid"

        conn = psycopg2.connect(
            host="localhost", port=5432,
            database="RAID-SecOps",
            user="postgres",
            password=password
        )
        cur = conn.cursor()
        cur.execute(
            "SELECT sample_id FROM alerts "
            "WHERE sample_id LIKE 'SPL-GEN2%' "
            "ORDER BY sample_id DESC LIMIT 1"
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            num = int(row[0].replace("SPL-GEN2-", ""))
            print(f"  Auto-detected last event: {row[0]} — starting from #{num + 1}")
            return num
        else:
            print(f"  No existing GEN2 events found — starting from #1")
            return 0
    except Exception as e:
        print(f"  Could not read DB ({e}) — starting from #1")
        return 0


# ── Main ──────────────────────────────────────────────────────
print("=" * 55)
print("  RAID-SecOps — Splunk Event Generator")
print("=" * 55)
print(f"  HEC URL  : {HEC_URL}")
print(f"  Interval : {INTERVAL}s between events")
print(f"  Checking database for last event number...")

n      = get_start_number()
sent   = 0
fails  = 0
counts = {c: 0 for c in cats}

print(f"  Press Ctrl+C to stop\n")

while True:
    n += 1
    cat   = random.choices(cats, weights=weights, k=1)[0]
    event = make_event(cat, n)

    try:
        ok = send(event, cat)
        if ok:
            sent += 1
            counts[cat] += 1
            label = "ATTACK" if cat != "Normal" else "normal"
            print(f"  [{n:>4}] {cat:<16} {label:<8} "
                  f"spkts={event['spkts']:<6} "
                  f"sbytes={event['sbytes']:<8} "
                  f"-> Splunk OK")
        else:
            fails += 1
            print(f"  [{n:>4}] FAILED to send")
    except Exception as e:
        fails += 1
        print(f"  [{n:>4}] ERROR: {e}")

    if n % 10 == 0:
        print(f"\n  --- After {n} events: sent={sent} failed={fails} ---")
        for c, cnt in counts.items():
            if cnt > 0:
                print(f"    {c:<18}: {cnt}")
        print()

    time.sleep(INTERVAL)
