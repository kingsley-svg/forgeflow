from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import datetime, uuid, sqlite3, json

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

CBN = {"Web": 72, "PoS": 72, "ATM": 48, "USSD": 48}

def db():
    c = sqlite3.connect("/tmp/ff.db")
    c.row_factory = sqlite3.Row
    return c

db().execute("CREATE TABLE IF NOT EXISTS disputes(id TEXT PRIMARY KEY, bank TEXT, amount REAL, tx_type TEXT, customer TEXT, status TEXT, logged TEXT, deadline TEXT, hours INTEGER)").connection.commit()

class Dispute(BaseModel):
    bank: str
    amount: float
    tx_type: str
    customer: str

@app.get("/")
def root():
    return {"status": "live", "product": "ForgeFlow"}

@app.post("/disputes")
def create(d: Dispute):
    hours = CBN.get(d.tx_type, 72)
    now = datetime.datetime.now()
    did = str(uuid.uuid4())[:8].upper()
    deadline = now + datetime.timedelta(hours=hours)
    c = db()
    c.execute("INSERT INTO disputes VALUES(?,?,?,?,?,?,?,?,?)",
        (did, d.bank, d.amount, d.tx_type, d.customer, "MONITORING", now.isoformat(), deadline.isoformat(), hours))
    c.commit()
    return {"id": did, "status": "MONITORING", "deadline": deadline.isoformat(), "hours": hours}

@app.get("/disputes")
def list_d():
    c = db()
    rows = [dict(r) for r in c.execute("SELECT * FROM disputes").fetchall()]
    return {"disputes": rows, "total": len(rows)}
