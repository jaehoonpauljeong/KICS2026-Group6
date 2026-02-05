#!/usr/bin/env python3
import os
import time
import uuid
import json
import math
import ipaddress
import sqlite3
import requests
from datetime import datetime
from flask import Flask, request, jsonify

# ================== CONFIG ==================
ODL = "http://192.168.2.4:8181"   # controller URL (used only for allow flows)
AUTH = ("admin", "admin")
NODE = "openflow:1"
TABLE = 0

# tuned weights and thresholds
WEIGHTS = {"mac": 40, "history": 10, "location": 20, "time_profile": 20, "geo": 10}
THRESHOLDS = {"low": 20, "high": 60}

DB_PATH = "enforcer_state.db"
GEOIP_API = "http://ip-api.com/json/"  # set None to disable geo

# adaptive params
MAC_LEARN_THRESHOLD = 5
COUNTRY_LEARN_THRESHOLD = 3
SUBNET_LEARN_THRESHOLD = 4
TIME_WINDOW_MIN_COUNT = 3
MAX_ALLOWED_COUNTRIES = 2

# test-mode toggles
WIPE_DB_ON_START = True
SIMULATED_VPN = True

def build_identity(src_mac, src_ip):
    mac = (src_mac or "nomac").lower()
    ip = src_ip or "noip"
    return f"{mac}|{ip}"

# ================== DB HELPERS ==================
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    # history now stores identity and username
    c.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identity TEXT,
        username TEXT,
        src_ip TEXT,
        src_mac TEXT,
        timestamp INTEGER
    )""")
    # user_profiles keyed by identity (mac|ip)
    c.execute("""
    CREATE TABLE IF NOT EXISTS user_profiles (
        identity TEXT PRIMARY KEY,
        username TEXT,
        profile_json TEXT,
        last_updated INTEGER
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS location_subnets (
        category TEXT PRIMARY KEY,
        subnets_json TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS mac_whitelist (
        mac TEXT PRIMARY KEY,
        label TEXT,
        added_at INTEGER
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS installed_flows (
      flow_id TEXT PRIMARY KEY,
      identity TEXT,
      username TEXT,
      src_ip TEXT,
      src_mac TEXT,
      created_ts INTEGER
    )""")
    conn.commit()
    conn.close()

def wipe_db_if_requested():
    if WIPE_DB_ON_START and os.path.exists(DB_PATH):
        print("[TEST MODE] wiping DB:", DB_PATH)
        os.remove(DB_PATH)

def load_default_seed(): # some example case for testing
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM location_subnets")
    if c.fetchone()[0] == 0:
        defaults = {
            "internal": ["10.0.0.0/8", "192.168.0.0/16", "192.0.2.0/24"],
            "vpn": ["172.16.0.0/12"],
            "public": []
        }
        for k, v in defaults.items():
            c.execute("INSERT INTO location_subnets (category, subnets_json) VALUES (?, ?)", (k, json.dumps(v)))
    c.execute("SELECT COUNT(*) FROM mac_whitelist")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO mac_whitelist (mac, label, added_at) VALUES (?, ?, ?)",
                  ("00:00:00:00:00:03", "alice-device", int(time.time())))
    conn.commit()
    conn.close()

# ================== DB READ/WRITE ==================
def record_history(identity, username, src_ip, src_mac):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO history (identity, username, src_ip, src_mac, timestamp) VALUES (?, ?, ?, ?, ?)",
              (identity, username, src_ip, src_mac, int(time.time())))
    conn.commit()
    conn.close()

def recent_history(identity, lookback_seconds=30*24*3600):
    cutoff = int(time.time()) - lookback_seconds
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT src_ip, src_mac, timestamp FROM history WHERE identity=? AND timestamp>=? ORDER BY timestamp DESC",
              (identity, cutoff))
    rows = c.fetchall()
    conn.close()
    return rows

def get_user_profile(identity):
    """
    Retrieve the profile for a specific identity (mac|ip).
    Returns a profile dict. If none exists, return default profile template.
    """
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT profile_json, username FROM user_profiles WHERE identity=?", (identity,))
    r = c.fetchone()
    conn.close()
    if not r:
        return {
            "identity": identity,
            "username": None,
            "login_count": 0,
            "mac_counts": {},
            "country_counts": {},
            "subnet_counts": {},
            "time_counts": {},
            "time_windows": [],
            "allowed_countries": []
        }
    try:
        profile = json.loads(r["profile_json"])
        profile["identity"] = identity
        profile["username"] = r["username"]
        return profile
    except Exception:
        return {
            "identity": identity,
            "username": r["username"] if r and "username" in r.keys() else None,
            "login_count": 0,
            "mac_counts": {},
            "country_counts": {},
            "subnet_counts": {},
            "time_counts": {},
            "time_windows": [],
            "allowed_countries": []
        }

def upsert_user_profile(identity, username, profile):
    conn = get_conn()
    c = conn.cursor()
    c.execute("REPLACE INTO user_profiles (identity, username, profile_json, last_updated) VALUES (?, ?, ?, ?)",
              (identity, username, json.dumps(profile), int(time.time())))
    conn.commit()
    conn.close()

def get_location_subnets():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT category, subnets_json FROM location_subnets")
    rows = c.fetchall()
    conn.close()
    out = {}
    for r in rows:
        out[r["category"]] = json.loads(r["subnets_json"])
    return out

def is_mac_whitelisted(mac):
    if not mac:
        return False
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT mac FROM mac_whitelist WHERE mac=?", (mac.lower(),))
    f = c.fetchone()
    conn.close()
    return f is not None

def add_whitelist_mac(mac, label="auto"):
    if not mac:
        return
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO mac_whitelist (mac,label,added_at) VALUES (?, ?, ?)",
              (mac.lower(), label, int(time.time())))
    conn.commit()
    conn.close()

def add_installed_flow(flow_id, identity, username, src_ip, src_mac):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO installed_flows (flow_id, identity, username, src_ip, src_mac, created_ts) VALUES (?, ?, ?, ?, ?, ?)",
              (flow_id, identity, username, src_ip, src_mac, int(time.time())))
    conn.commit()
    conn.close()

def remove_installed_flow(flow_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM installed_flows WHERE flow_id=?", (flow_id,))
    conn.commit()
    conn.close()

# ================== NETWORK / GEO utilities ==================

def geoip_lookup(ip):

    if not GEOIP_API:
        return None
    try:
        r = requests.get(GEOIP_API + ip, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def ip_in_subnet_list(ip, subnet_list):
    try:
        ipobj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for s in subnet_list:
        try:
            if ipobj in ipaddress.ip_network(s):
                return True
        except Exception:
            pass
    return False

# ================== ADAPTIVE PROFILE UPDATES ==================
def compute_time_windows_from_counts(time_counts):
    # time_counts: {"0": n0, ...}
    if not time_counts:
        return []
    counts = [int(time_counts.get(str(h), 0)) for h in range(24)]
    total = sum(counts)
    if total < TIME_WINDOW_MIN_COUNT:
        return []
    maxv = max(counts)
    threshold = max(1, int(maxv * 0.5))
    active = [1 if counts[h] >= threshold else 0 for h in range(24)]
    windows = []
    i = 0
    visited = [False]*24
    while i < 24:
        if active[i] and not visited[i]:
            start = i
            j = i
            while active[j] and not visited[j]:
                visited[j] = True
                j = (j+1) % 24
                if j == start:
                    break
            end = (j-1) % 24
            s = f"{start:02d}:00"
            e = f"{(end+1)%24:02d}:00"
            windows.append([s, e])
            i = j
            if i <= start:
                break
        else:
            i += 1
    return windows

def update_profile_on_success(identity, username, src_ip, src_mac, country=None):
    profile = get_user_profile(identity)
    profile["username"] = username
    profile["login_count"] = profile.get("login_count", 0) + 1
    if src_mac:
        mc = profile.get("mac_counts", {})
        mc[src_mac.lower()] = mc.get(src_mac.lower(), 0) + 1
        profile["mac_counts"] = mc
    if country:
        cc = profile.get("country_counts", {})
        cc[country] = cc.get(country, 0) + 1
        profile["country_counts"] = cc
        top = sorted(cc.items(), key=lambda x: x[1], reverse=True)[:MAX_ALLOWED_COUNTRIES]
        profile["allowed_countries"] = [c for c,_ in top]
    subs = get_location_subnets()
    cat_hit = None
    for cat, nets in subs.items():
        if ip_in_subnet_list(src_ip, nets):
            cat_hit = cat
            break
    if cat_hit:
        sc = profile.get("subnet_counts", {})
        sc[cat_hit] = sc.get(cat_hit, 0) + 1
        profile["subnet_counts"] = sc
    try:
        hr = datetime.now().hour
        tc = profile.get("time_counts", {})
        tc[str(hr)] = tc.get(str(hr), 0) + 1
        profile["time_counts"] = tc
    except Exception:
        pass
    profile["time_windows"] = compute_time_windows_from_counts(profile.get("time_counts", {}))
    upsert_user_profile(identity, username, profile)
    return profile

# ================== SCORING FUNCTIONS (tuned) ==================
def score_mac(identity, src_mac):
    profile = get_user_profile(identity)
    mc = profile.get("mac_counts", {})
    count = mc.get(src_mac.lower(), 0) if src_mac else 0
    trust = min(count / MAC_LEARN_THRESHOLD, 1.0)
    trust_curve = trust ** 0.6
    score = int(WEIGHTS["mac"] * (1 - 0.8 * trust_curve))
    if is_mac_whitelisted(src_mac):
        score = int(score * 0.25)
    return score

def score_history(identity, src_ip, src_mac):
    rows = recent_history(identity)
    if not rows:
        return int(WEIGHTS["history"] * 1.0)
    for r in rows[:20]:
        if src_ip == r[0] or (src_mac and src_mac.lower() == (r[1] or "").lower()):
            return int(WEIGHTS["history"] * 0.2)
    return int(WEIGHTS["history"] * 0.8)

def score_location(identity, src_ip):
    subs = get_location_subnets()
    if ip_in_subnet_list(src_ip, subs.get("internal", [])):
        base = int(WEIGHTS["location"] * 0.35)
    elif ip_in_subnet_list(src_ip, subs.get("vpn", [])):
        base = int(WEIGHTS["location"] * 0.6)
    else:
        base = WEIGHTS["location"]
    profile = get_user_profile(identity)
    sc = profile.get("subnet_counts", {})
    cat = None
    for k, nets in subs.items():
        if ip_in_subnet_list(src_ip, nets):
            cat = k
            break
    count = sc.get(cat, 0) if cat else 0
    trust = min(count / SUBNET_LEARN_THRESHOLD, 1.0)
    reduction = 0.6 * trust
    score = int(base * (1 - reduction))
    return score

def score_time_profile(identity):
    profile = get_user_profile(identity)
    time_counts = profile.get("time_counts", {})
    total_samples = sum(int(v) for v in time_counts.values()) if time_counts else 0
    if total_samples < TIME_WINDOW_MIN_COUNT:
        return int(WEIGHTS["time_profile"] * 0.5)
    hours = []
    for h, c in time_counts.items():
        hours += [int(h)] * int(c)
    if not hours:
        return int(WEIGHTS["time_profile"] * 0.5)
    angles = [2 * math.pi * (h / 24.0) for h in hours]
    mean_angle = math.atan2(sum(math.sin(a) for a in angles), sum(math.cos(a) for a in angles))
    mean_hour = (mean_angle / (2 * math.pi)) * 24.0
    mean_hour %= 24.0
    now_h = datetime.now().hour + datetime.now().minute / 60.0
    diff = min(abs(now_h - mean_hour), 24 - abs(now_h - mean_hour))
    ratio = min(diff / 6.0, 1.0)
    return int(WEIGHTS["time_profile"] * ratio)

def score_geo(identity, src_ip):
    if not GEOIP_API:
        return int(WEIGHTS["geo"] * 0.5)
    geo = geoip_lookup(src_ip)
    if not geo or geo.get("status") != "success":
        return int(WEIGHTS["geo"] * 0.7)
    country = geo.get("countryCode")
    if not country:
        return int(WEIGHTS["geo"] * 0.7)
    profile = get_user_profile(identity)
    allowed = profile.get("allowed_countries", [])
    counts = profile.get("country_counts", {})
    if country in allowed:
        return 0
    cnt = counts.get(country, 0)
    trust = min(cnt / COUNTRY_LEARN_THRESHOLD, 1.0)
    trust_curve = trust ** 0.7
    return int(WEIGHTS["geo"] * (1 - 0.9 * trust_curve))

# ================== AGGREGATION ==================
def compute_risk_score(identity, src_ip, src_mac):
    parts = {}
    parts["mac"] = score_mac(identity, src_mac)
    parts["history"] = score_history(identity, src_ip, src_mac)
    parts["location"] = score_location(identity, src_ip)
    parts["time_profile"] = score_time_profile(identity)
    parts["geo"] = score_geo(identity, src_ip)
    total = sum(parts.values())
    max_possible = sum(WEIGHTS.values())
    score = int((total / max_possible) * 100)
    return score, parts

def risk_decision(score):
    if score <= THRESHOLDS["low"]:
        return "LOW"
    if score >= THRESHOLDS["high"]:
        return "HIGH"
    return "HIGH"  # conservative for medium

# ================== SIMULATED VPN AUTH (TEST) ==================
def simulate_vpn_auth(username, src_ip, src_mac):
    print(f"[SIM] Simulating VPN auth for user={username} ip={src_ip} mac={src_mac}")
    time.sleep(0.4)
    return True

# ================== FLOW PUSH (minimal) ==================
def push_allow_flow(flow_id, src_ip, src_mac, dst_ip):
    flow = {
        "flow": [{
            "id": flow_id,
            "table_id": TABLE,
            "priority": 400,
            "match": {
                **({"ethernet-match": {"ethernet-source": {"address": src_mac}}} if src_mac else {}),
                **({"ipv4-source": f"{src_ip}/32"} if src_ip else {}),
                **({"ipv4-destination": f"{dst_ip}/32"} if dst_ip else {}),
                "ip-match": {"ip-protocol": 6}
            },
            "instructions": {
                "instruction": [{
                    "order": 0,
                    "apply-actions": {
                        "action": [{
                            "order": 0,
                            "output-action": {"output-node-connector": "NORMAL"}
                        }]
                    }
                }]
            },
            "idle-timeout": 300,
            "hard-timeout": 600
        }]
    }
    try:
        url = f"{ODL}/restconf/config/opendaylight-inventory:nodes/node/{NODE}/table/{TABLE}/flow/{flow_id}"
        r = requests.put(url, json=flow, auth=AUTH, timeout=5)
        print("push_allow_flow", r.status_code)
    except Exception as e:
        print("push_allow_flow error", e)

# ================== FLASK API ==================
app = Flask(__name__)

@app.route("/login_attempt", methods=["POST"])
def login_attempt():
    payload = request.json or {}
    src_ip = payload.get("src_ip")
    src_mac = payload.get("src_mac")
    username = payload.get("username")
    dst_ip = payload.get("dst_ip")
    if not (src_ip and username):
        return jsonify({"error": "src_ip and username required"}), 400

    identity = build_identity(src_mac, src_ip)

    print("\n[EVENT] login_attempt", payload, "identity=", identity)

    # Always perform geo-lookup early (so learning uses country immediately)
    geo = geoip_lookup(src_ip) if GEOIP_API else None
    country = geo.get("countryCode") if geo and geo.get("status") == "success" else None

    # compute risk BEFORE updating profile/history (we want to decide based on prior state)
    score, parts = compute_risk_score(identity, src_ip, src_mac)
    decision = risk_decision(score)
    print("[RISK] score", score, "parts", parts, "decision", decision)

    flow_id = str(uuid.uuid4())[:8]

    if decision == "LOW":
        push_allow_flow(flow_id, src_ip, src_mac, dst_ip)
        record_history(identity, username, src_ip, src_mac)
        profile = update_profile_on_success(identity, username, src_ip, src_mac, country)
        add_installed_flow(flow_id, identity, username, src_ip, src_mac)
        return jsonify({"decision": "BYPASS", "flow_id": flow_id, "score": score, "parts": parts, "profile": profile})

    # HIGH risk
    if SIMULATED_VPN:
        ok = simulate_vpn_auth(username, src_ip, src_mac)
        if ok:
            # record success and update profile (so geo/subnet/mac/time counts grow immediately)
            record_history(identity, username, src_ip, src_mac)
            profile = update_profile_on_success(identity, username, src_ip, src_mac, country)
            # auto-whitelist if mac_count >= threshold
            mac_count = profile.get("mac_counts", {}).get(src_mac.lower(), 0) if src_mac else 0
            if mac_count >= MAC_LEARN_THRESHOLD:
                add_whitelist_mac(src_mac, label=f"auto:{username}")
            add_installed_flow(flow_id, identity, username, src_ip, src_mac)
            return jsonify({"decision": "SIMULATED_VPN_AUTH", "flow_id": flow_id, "score": score, "parts": parts, "profile": profile})
        else:
            return jsonify({"decision": "SIMULATED_VPN_FAILED"}), 500

    # fallback (non-simulated)
    record_history(identity, username, src_ip, src_mac)
    profile = update_profile_on_success(identity, username, src_ip, src_mac, country)
    add_installed_flow(flow_id, identity, username, src_ip, src_mac)
    return jsonify({"decision": "ENFORCE_TOTP", "flow_id": flow_id, "score": score, "parts": parts, "profile": profile})

@app.route("/admin/profile", methods=["GET"])
def admin_profile():
    """
    Fetch profile by mac/ip (preferred) or by identity param.
    Example: /admin/profile?mac=00:00:00:00:00:03&ip=10.0.0.3
    """
    mac = (request.args.get("mac") or "").lower()
    ip = request.args.get("ip")
    identity = None
    if mac and ip:
        identity = build_identity(mac, ip)
    else:
        # fallback: allow identity query param directly
        identity = request.args.get("identity")
    if not identity:
        return jsonify({"error": "provide mac+ip or identity"}), 400
    prof = get_user_profile(identity)
    return jsonify(prof)

@app.route("/admin/list_flows", methods=["GET"])
def admin_list_flows():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT flow_id, identity, username, src_ip, src_mac, created_ts FROM installed_flows")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/remove_flow/<flow_id>", methods=["DELETE"])
def remove_flow(flow_id):
    remove_installed_flow(flow_id)
    try:
        url = f"{ODL}/restconf/config/opendaylight-inventory:nodes/node/{NODE}/table/{TABLE}/flow/{flow_id}"
        r = requests.delete(url, auth=AUTH, timeout=3)
        return jsonify({"status": r.status_code, "text": r.text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================== BOOT ==================
if __name__ == "__main__":
    wipe_db_if_requested()
    init_db()
    load_default_seed()
    print("Adaptive enforcer (fixed, identity-isolated) starting. DB:", DB_PATH)
    app.run(host="0.0.0.0", port=5000)

