import os, tempfile, pytest
os.environ["DB_PATH"] = tempfile.mktemp(suffix=".db")
from fastapi.testclient import TestClient
import app as A
A.create_user("admin", "pw-Admin-1", "admin"); A.create_user("op", "pw-Op-1", "operator")
c = TestClient(A.app)
def tok(u, p): return {"Authorization": "Bearer " + c.post("/api/auth/login", json={"username": u, "password": p}).json()["token"]}
H = tok("admin", "pw-Admin-1"); O = tok("op", "pw-Op-1")
c.post("/api/meters", json={"meter_id": "M-001", "name": "Block A", "location": "Lab"}, headers=H)
def sess(): return c.post("/api/protocol/authenticate", json={"meter_id": "M-001", "cm": "00"}, headers=H).json()
def test_login():
    assert c.post("/api/auth/login", json={"username": "admin", "password": "bad"}).status_code == 401
    assert c.get("/api/meters").status_code == 401
def test_authz(): assert c.post("/api/meters", json={"meter_id": "M-002", "name": "x"}, headers=O).status_code == 403
def test_no_key_exposed(): assert "k" not in c.get("/api/meters", headers=H).json()[0]
def test_mutual_auth(): assert sess()["authenticated"] is True
def test_encrypt_decrypt():
    s = sess(); r = c.post("/api/readings/transmit", json={"meter_id": "M-001", "session_id": s["session_id"], "kwh": 12.5, "voltage": 230, "current": 5}, headers=H).json()
    assert r["result"]["reading"]["kwh"] == 12.5
def test_sims():
    for p, b in [("tamper", {"meter_id": "M-001"}), ("replay", {"meter_id": "M-001"}), ("unknown-meter", None), ("invalid-response", {"meter_id": "M-001"}), ("expired-challenge", {"meter_id": "M-001"})]:
        r = c.post("/api/simulation/" + p, json=b, headers=H).json(); assert r["result"] == "PASS", r
def test_events_logged():
    types = {e["type"] for e in c.get("/api/logs", headers=H).json()}
    assert {"auth_success", "tampered", "replay", "unknown_meter", "auth_failed"} <= types
