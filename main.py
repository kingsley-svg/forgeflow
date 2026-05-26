"""
ForgeFlow v2.0 — Cloud Backend API
FastAPI + SQLite + AES-256-GCM
Founder: Ogunremi Ayodele Kingsley
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import datetime
import uuid
import os
import json
import hashlib
import base64
import re
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)

# ── Database setup ─────────────────────────────────────────────
DB_PATH = "/tmp/forgeflow.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS disputes (
            id TEXT PRIMARY KEY,
            bank TEXT,
            amount REAL,
            tx_type TEXT,
            tx_ref TEXT,
            customer_name TEXT,
            account_number TEXT,
            status TEXT DEFAULT 'MONITORING',
            logged_at TEXT,
            deadline TEXT,
            warning_at TEXT,
            timeline_hours INTEGER,
            audit_trail TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS consent_log (
            id TEXT PRIMARY KEY,
            subject_id TEXT,
            purpose TEXT,
            lawful_basis TEXT,
            timestamp TEXT,
            integrity_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

# ── Security Vault ─────────────────────────────────────────────
class SecurityVault:
    _MASTER_PASSWORD = os.environ.get("FORGEFLOW_SECRET", "ForgeFlow-Dev-2026!")
    _SALT = b"ForgeFlowNDPA2026"

    def __init__(self):
        self._key = self._derive_key()

    def _derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._SALT,
            iterations=100_000,
        )
        return kdf.derive(self._MASTER_PASSWORD.encode())

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._key)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return "ENC::" + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, token: str) -> str:
        if not token or not token.startswith("ENC::"):
            return token or ""
        raw = base64.urlsafe_b64decode(token[5:])
        nonce = raw[:12]
        ct = raw[12:]
        aesgcm = AESGCM(self._key)
        return aesgcm.decrypt(nonce, ct, None).decode()

vault = SecurityVault()

# ── CBN Config ─────────────────────────────────────────────────
CBN_TIMELINES = {"Web": 72, "PoS": 72, "ATM": 48, "USSD": 48}
CBN_REF = {
    "Web":  "CBN Circular FPR/DIR/GEN/CIR/06/010",
    "PoS":  "CBN Circular FPR/DIR/GEN/CIR/06/010",
    "ATM":  "CBN Consumer Protection Framework 2022",
    "USSD": "CBN Consumer Protection Framework 2022",
}

# ── OCR ────────────────────────────────────────────────────────
BANK_ALIASES = {
    r"guaranty|gtbank":  "Guaranty Trust Bank (GTBank)",
    r"access bank":      "Access Bank",
    r"united bank|uba":  "United Bank for Africa (UBA)",
    r"zenith":           "Zenith Bank",
    r"first bank":       "First Bank of Nigeria",
    r"kuda":             "Kuda Microfinance Bank",
    r"opay":             "OPay Digital Services",
    r"moniepoint":       "Moniepoint MFB",
    r"palmpay":          "PalmPay",
    r"wema|alat":        "Wema Bank / ALAT",
    r"sterling":         "Sterling Bank",
    r"fidelity":         "Fidelity Bank",
    r"fcmb":             "First City Monument Bank",
    r"stanbic":          "Stanbic IBTC Bank",
}

def parse_receipt(text: str) -> dict:
    bank = None
    for pattern, canonical in BANK_ALIASES.items():
        if re.search(pattern, text, re.IGNORECASE):
            bank = canonical
            break
    ref_match = re.search(r"(?:Ref|Trans)[:\s#]+([A-Z0-9\-]{8,25})", text, re.IGNORECASE)
    amt_match = re.search(r"(?:₦|NGN|Amount)[:\s]*([\d,]+(?:\.\d{2})?)", text, re.IGNORECASE)
    date_match = re.search(r"(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})", text)
    found = sum(1 for v in [bank, ref_match, amt_match, date_match] if v)
    return {
        "bank_name":  bank,
        "tx_ref":     ref_match.group(1) if ref_match else None,
        "amount":     float(amt_match.group(1).replace(",", "")) if amt_match else None,
        "date":       date_match.group(1) if date_match else None,
        "confidence": {4: "HIGH", 3: "HIGH", 2: "MEDIUM"}.get(found, "LOW"),
    }

# ── PDF Generator ───────────────────────────────────────────────
def generate_pdf(dispute: dict, customer_name: str) -> str:
    path = f"/tmp/escalation_{dispute['id']}.pdf"
    GREEN = colors.HexColor("#006B3F")
    NAVY  = colors.HexColor("#0A1628")
    RED   = colors.HexColor("#C0392B")
    GREY  = colors.HexColor("#7F8C9A")

    doc = SimpleDocTemplate(path, pagesize=A4,
        leftMargin=2.5*cm, rightMargin=2.5*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm)

    def sty(n, **kw): return ParagraphStyle(n, **kw)
    h  = sty("H", fontSize=22, textColor=NAVY, fontName="Helvetica-Bold", spaceAfter=4)
    s  = sty("S", fontSize=10, textColor=GREEN, fontName="Helvetica-Bold", spaceAfter=10)
    b  = sty("B", fontSize=10, leading=16, fontName="Helvetica", spaceAfter=8)
    bo = sty("Bo", fontSize=10, fontName="Helvetica-Bold", spaceAfter=6)
    r  = sty("R", fontSize=10, fontName="Helvetica-Bold", textColor=RED, spaceAfter=8)
    sm = sty("Sm", fontSize=8, textColor=GREY, fontName="Helvetica")

    now      = datetime.datetime.now()
    deadline = datetime.datetime.fromisoformat(dispute["deadline"])
    logged   = datetime.datetime.fromisoformat(dispute["logged_at"])
    overdue  = max(0, int((now - deadline).total_seconds() / 3600))

    story = [
        Paragraph("ForgeFlow", h),
        Paragraph("AI-Powered Consumer Dispute Resolution · Nigeria", s),
        HRFlowable(width="100%", thickness=2, color=GREEN, spaceAfter=10),
        Paragraph(f"Date: <b>{now.strftime('%d %B %Y')}</b>", b),
        Paragraph(f"Ref: <b>FF-ESC-{dispute['id']}</b>", b),
        Spacer(1, 0.3*cm),
        Paragraph("<b>TO: Director, Consumer Protection Dept, CBN, Abuja</b>", bo),
        Paragraph(f"<b>CC: MD/CEO, {dispute['bank']}</b>", b),
        Spacer(1, 0.3*cm),
        Paragraph(f"<b>RE: FORMAL ESCALATION — UNRESOLVED {dispute['tx_type']} TRANSACTION | {dispute['bank']} | REF: {dispute['tx_ref']}</b>", r),
        HRFlowable(width="100%", thickness=0.5, color=GREY, spaceAfter=10),
        Paragraph("Dear Director,", b),
        Paragraph(
            f"We formally notify your office of a failed {dispute['tx_type']} transaction "
            f"unresolved beyond the CBN-mandated {dispute['timeline_hours']}-hour window by "
            f"<b>{dispute['bank']}</b>, violating <b>{CBN_REF.get(dispute['tx_type'], 'CBN Circular')}</b>.",
            b),
    ]

    tbl = Table([
        ["Field", "Details"],
        ["Customer", customer_name],
        ["Bank", dispute["bank"]],
        ["TX Reference", dispute["tx_ref"]],
        ["Channel", dispute["tx_type"]],
        ["Amount", f"NGN {dispute['amount']:,.2f}"],
        ["Logged", logged.strftime("%d %b %Y, %H:%M")],
        ["Deadline", deadline.strftime("%d %b %Y, %H:%M")],
        ["Overdue", f"{overdue}h" if overdue > 0 else "Within window"],
    ], colWidths=[5*cm, 11.5*cm])

    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), NAVY),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("GRID", (0,0), (-1,-1), 0.5, GREY),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.3*cm))

    story += [
        Paragraph("<b>DEMANDS:</b>", bo),
        Paragraph(f"1. Immediate refund of <b>NGN {dispute['amount']:,.2f}</b> within 24 hours.", b),
        Paragraph("2. Written confirmation from the bank's Complaint Management Officer.", b),
        Paragraph("3. Statutory interest at CBN Monetary Policy Rate for each day of delay.", b),
        Paragraph(
            "<b>NOTICE:</b> Non-compliance within 48 hours will result in a formal CBN complaint portal filing.",
            r),
        Spacer(1, 0.3*cm),
        Paragraph("Yours faithfully,", b),
        Paragraph("<b>ForgeFlow Dispute Resolution System</b>", bo),
        HRFlowable(width="100%", thickness=1, color=GREEN, spaceAfter=6),
        Paragraph(
            f"Auto-generated {now.strftime('%Y-%m-%d %H:%M')} | "
            f"Hash: {hashlib.sha256(dispute['id'].encode()).hexdigest()[:16].upper()} | NDPA §2.1",
            sm),
    ]

    doc.build(story)
    return path

# ── FastAPI App ─────────────────────────────────────────────────
app = FastAPI(
    title="ForgeFlow API",
    description="AI-Powered Dispute Resolution · Nigeria · CBN Compliant",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

# ── Pydantic Models ─────────────────────────────────────────────
class DisputeIn(BaseModel):
    bank: str
    amount: float
    tx_type: str = "PoS"
    tx_ref: Optional[str] = None
    customer_name: str
    account_number: Optional[str] = ""
    consent_given: bool = False

class OCRIn(BaseModel):
    receipt_text: str

class ResolveIn(BaseModel):
    dispute_id: str
    note: Optional[str] = ""

# ── Routes ──────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "product": "ForgeFlow v2.0",
        "founder": "Ogunremi Ayodele Kingsley",
        "status":  "operational",
        "docs":    "/docs",
    }

@app.get("/health")
def health():
    return {"status": "healthy", "time": datetime.datetime.now().isoformat()}

@app.post("/disputes/intake")
def intake(data: DisputeIn):
    if not data.consent_given:
        raise HTTPException(403, "NDPA §2.1: Consent required.")

    hours    = CBN_TIMELINES.get(data.tx_type, 72)
    now      = datetime.datetime.now()
    deadline = now + datetime.timedelta(hours=hours)
    warning  = now + datetime.timedelta(hours=hours * 0.75)
    did      = str(uuid.uuid4())[:8].upper()
    tx_ref   = data.tx_ref or f"FF-{uuid.uuid4().hex[:10].upper()}"

    audit = json.dumps([{
        "event": "DISPUTE_LOGGED",
        "timestamp": now.isoformat(),
        "actor": "ForgeFlow System"
    }])

    conn = get_db()
    conn.execute("""
        INSERT INTO disputes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        did, data.bank, data.amount, data.tx_type, tx_ref,
        vault.encrypt(data.customer_name),
        vault.encrypt(data.account_number) if data.account_number else "",
        "MONITORING", now.isoformat(), deadline.isoformat(),
        warning.isoformat(), hours, audit
    ))

    consent_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO consent_log VALUES (?,?,?,?,?,?)
    """, (
        consent_id, did, "Dispute resolution",
        "Explicit consent (NDPA §2.1)", now.isoformat(),
        hashlib.sha256(f"{did}{now.isoformat()}".encode()).hexdigest()
    ))
    conn.commit()
    conn.close()

    return {
        "success": True,
        "dispute_id": did,
        "tx_ref": tx_ref,
        "bank": data.bank,
        "amount": data.amount,
        "status": "MONITORING",
        "deadline": deadline.isoformat(),
        "timeline_hours": hours,
        "cbn_reference": CBN_REF.get(data.tx_type),
        "message": f"Dispute #{did} logged. CBN {hours}h window started.",
    }

@app.get("/disputes")
def list_disputes(status: Optional[str] = None):
    conn = get_db()
    rows = conn.execute("SELECT * FROM disputes").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if status and d["status"] != status:
            continue
        d.pop("customer_name", None)
        d.pop("account_number", None)
        d["audit_trail"] = json.loads(d.get("audit_trail", "[]"))
        result.append(d)
    return {"disputes": result, "total": len(result)}

@app.get("/disputes/{dispute_id}")
def get_dispute(dispute_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM disputes WHERE id=?", (dispute_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Dispute not found")
    d = dict(row)
    d.pop("customer_name", None)
    d.pop("account_number", None)
    d["audit_trail"] = json.loads(d.get("audit_trail", "[]"))
    return d

@app.post("/disputes/{dispute_id}/escalate")
def escalate(dispute_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM disputes WHERE id=?", (dispute_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Not found")
    d = dict(row)
    name = vault.decrypt(d["customer_name"])
    pdf_path = generate_pdf(d, name)
    now = datetime.datetime.now()
    trail = json.loads(d.get("audit_trail", "[]"))
    trail.append({"event": "ESCALATED", "timestamp": now.isoformat(), "actor": "ForgeFlow"})
    conn.execute("UPDATE disputes SET status=?, audit_trail=? WHERE id=?",
                 ("ESCALATE", json.dumps(trail), dispute_id))
    conn.commit()
    conn.close()
    return FileResponse(pdf_path, media_type="application/pdf",
                        filename=f"ForgeFlow_Escalation_{dispute_id}.pdf")

@app.post("/disputes/{dispute_id}/resolve")
def resolve(dispute_id: str, data: ResolveIn):
    conn = get_db()
    row = conn.execute("SELECT * FROM disputes WHERE id=?", (dispute_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Not found")
    d = dict(row)
    now = datetime.datetime.now()
    trail = json.loads(d.get("audit_trail", "[]"))
    trail.append({"event": "RESOLVED", "timestamp": now.isoformat(), "actor": "Admin", "note": data.note})
    conn.execute("UPDATE disputes SET status=?, audit_trail=? WHERE id=?",
                 ("RESOLVED", json.dumps(trail), dispute_id))
    conn.commit()
    conn.close()
    return {"success": True, "dispute_id": dispute_id, "status": "RESOLVED"}

@app.post("/ocr/extract")
def ocr_extract(data: OCRIn):
    return parse_receipt(data.receipt_text)

@app.post("/escalation/check")
def check_escalations():
    conn = get_db()
    rows = conn.execute("SELECT * FROM disputes").fetchall()
    now = datetime.datetime.now()
    escalated = []
    warned = []
    for row in rows:
        d = dict(row)
        if d["status"] in ("RESOLVED", "CLOSED", "ESCALATE"):
            continue
        deadline   = datetime.datetime.fromisoformat(d["deadline"])
        warning_at = datetime.datetime.fromisoformat(d["warning_at"])
        trail      = json.loads(d.get("audit_trail", "[]"))
        if now > deadline:
            trail.append({"event": "AUTO_ESCALATED", "timestamp": now.isoformat(), "actor": "Engine"})
            conn.execute("UPDATE disputes SET status=?, audit_trail=? WHERE id=?",
                         ("ESCALATE", json.dumps(trail), d["id"]))
            escalated.append(d["id"])
        elif now > warning_at and d["status"] == "MONITORING":
            trail.append({"event": "WARNING", "timestamp": now.isoformat(), "actor": "Engine"})
            conn.execute("UPDATE disputes SET status=?, audit_trail=? WHERE id=?",
                         ("WARNING", json.dumps(trail), d["id"]))
            warned.append(d["id"])
    conn.commit()
    conn.close()
    return {"escalated": escalated, "warned": warned, "timestamp": now.isoformat()}

@app.get("/stats")
def stats():
    conn = get_db()
    rows = conn.execute("SELECT * FROM disputes").fetchall()
    conn.close()
    by_status = {}
    total = 0
    for r in rows:
        d = dict(r)
        by_status[d["status"]] = by_status.get(d["status"], 0) + 1
        total += d["amount"]
    return {"total_disputes": len(rows), "by_status": by_status, "total_amount": total}
