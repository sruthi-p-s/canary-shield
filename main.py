from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
from pydantic import BaseModel
import uuid
import datetime

app = FastAPI(
    title="CanaryShield - Deception Forensics API",
    version="1.0.0",
    description="Live Threat Deception & Incident Response Telemetry Pipeline"
)

# Enable CORS for cross-origin frontend dashboard requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cloud Database Connection
SUPABASE_URL = "https://rndsbynqjdbtsxxplsqi.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJuZHNieW5xamRidHN4eHBsc3FpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTExNzc4MTcsImV4cCI6MjEwNjc1MzgxN30.QkRcWfiVp1fPR8sBDMmQO5JFpvDIPRlCbKuSaaAkNJY"  
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

class TokenCreateRequest(BaseModel):
    name: str
    bait_type: str

# 1. CREATE CANARY TOKEN (BAIT GENERATOR)
@app.post("/api/v1/tokens/create")
def create_canary_token(data: TokenCreateRequest):
    token_id = str(uuid.uuid4())[:8]
    record = {
        "token_id": token_id,
        "name": data.name,
        "bait_type": data.bait_type
    }
    supabase.table("canary_tokens").insert(record).execute()
    return {
        "status": "created",
        "token_id": token_id,
        "bait_name": data.name,
        "canary_url": f"/api/v1/beacon/{token_id}"
    }

# 2. THE HONEYPOT TRAP: TRIGGERED BY ATTACKER / EXTERNAL DEVICE
@app.get("/api/v1/beacon/{token_id}")
async def trigger_canary_trap(token_id: str, request: Request):
    # Verify token exists in database
    token_query = supabase.table("canary_tokens").select("*").eq("token_id", token_id).execute()
    if not token_query.data:
        raise HTTPException(status_code=404, detail="Invalid token")

    # Forensic triage telemetry extraction
    client_ip = request.client.host
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    user_agent = request.headers.get("user-agent", "Unknown Device")
    accept_lang = request.headers.get("accept-language", "Unknown")
    fingerprint = f"UA: {user_agent[:45]} | Lang: {accept_lang[:15]}"

    # Commit forensic incident into PostgreSQL
    incident = {
        "token_id": token_id,
        "attacker_ip": client_ip,
        "user_agent": user_agent,
        "device_fingerprint": fingerprint,
        "severity": "CRITICAL"
    }
    supabase.table("breach_incidents").insert(incident).execute()

    return {
        "alert": "SECURITY DECEPTION BEACON TRIPPED",
        "status": "INCIDENT_LOGGED",
        "forensic_signature": {
            "source_ip": client_ip,
            "captured_user_agent": user_agent,
            "tripped_at": datetime.datetime.utcnow().isoformat()
        }
    }

# 3. REAL-TIME INCIDENT FEED FOR DASHBOARD
@app.get("/api/v1/incidents")
def get_incidents():
    res = supabase.table("breach_incidents").select("*, canary_tokens(name, bait_type)").order("tripped_at", desc=True).limit(50).execute()
    return res.data

# 4. SUMMARY TELEMETRY METRICS
@app.get("/api/v1/stats")
def get_stats():
    tokens = supabase.table("canary_tokens").select("token_id", count="exact").execute()
    incidents = supabase.table("breach_incidents").select("id", count="exact").execute()
    return {
        "active_tokens": tokens.count if tokens.count is not None else 0,
        "total_breaches_detected": incidents.count if incidents.count is not None else 0
    }