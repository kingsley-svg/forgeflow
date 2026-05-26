from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import datetime, uuid, sqlite3, json
from typing import Optional

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def db():
    c = sqlite3.connect("/tmp/ff.db")
    c.row_factory = sqlite3.Row
    return c

def init():
    c = db()
    c.execute("CREATE TABLE IF NOT EXISTS disputes(id TEXT PRIMARY KEY, bank TEXT, amount REAL, tx_type TEXT, tx_ref TEXT, customer TEXT, status TEXT, logged TEXT, deadline TEXT, hours INTEGER)")
    c.commit()
    c.close()

init()

class D(BaseModel):
    bank: str
    amount: float
    tx_type: str = "PoS"
    customer_name: str
    consent_given: bool = False

@app.get("/")
def root():
    return {"product": "ForgeFlow", "founder": "Ogunremi Ayodele Kingsley", "status": "live"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/disputes/intake")
def intake(data: D):
    hours = 72 if data.tx_type in ["PoS","Web"] else 48
    now = datetime.datetime.now()
    did = str(uuid.uuid4())[:8].upper()
    deadline = now + datetime.timedelta(hours=hours)
    c = db()
    c.execute("INSERT INTO disputes VALUES(?,?,?,?,?,?,?,?,?,?)",
        (did, data.bank, data.amount, data.tx_type, f"FF-{did}",
         data.customer_name, "MONITORING", now.isoformat(), deadline.isoformat(), hours))
    c.commit()
    c.close()
    return {"dispute_id": did, "status": "MONITORING", "deadline": deadline.isoformat(), "hours": hours}

@app.get("/disputes")
def list_d():
    c = db()
    rows = [dict(r) for r in c.execute("SELECT * FROM disputes").fetchall()]
    c.close()
    return {"disputes": rows, "total": len(rows)}

@app.get("/stats")
def stats():
    c = db()
    rows = [dict(r) for r in c.execute("SELECT * FROM disputes").fetchall()]
    c.close()
    return {"total": len(rows)}
