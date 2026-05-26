from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class Dispute(BaseModel):
    bank: str
    amount: float
    customer: str

@app.get("/")
def root():
    return {"status": "live", "product": "ForgeFlow"}

@app.post("/disputes")
def create(d: Dispute):
    return {"bank": d.bank, "amount": d.amount, "status": "MONITORING"}
