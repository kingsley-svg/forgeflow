"""
╔══════════════════════════════════════════════════════════════╗
║         ForgeFlow v2.0 — Cloud Backend API                   ║
║         FastAPI + PostgreSQL + AES-256-GCM                   ║
║         Founder: Ogunremi Ayodele Kingsley                   ║
╚══════════════════════════════════════════════════════════════╝
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import datetime
import uuid
import os
import json
import hashlib
import base64
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)

import databases
import sqlalchemy

# ── Database ──────────────────────────────────────────────────────
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./forgeflow.db"  # fallback for local dev
)

# Fix postgres:// → postgresql:// for SQLAlchemy
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

disputes_table = sqlalchemy.Table(
    "disputes", metadata,
    sqlalchemy.Column("id",             sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("bank",           sqlalchemy.String),
    sqlalchemy.Column("amount",         sqlalchemy.Float),
    sqlalchemy.Column("tx_type",        sqlalchemy.String),
    sqlalchemy.Column("tx_ref",         sqlalchemy.String),
    sqlalchemy.Column("customer_name",  sqlalchemy.String),   # encrypted
    sqlalchemy.Column("account_number", sqlalchemy.String),   # encrypted
    sqlalchemy.Column("status",         sqlalchemy.String, default="MONITORING"),
    sqlalchemy.Column("logged_at",      sqlalchemy.String),
    sqlalchemy.Column("deadline",       sqlalchemy.String),
    sqlalchemy.Column("warning_at",     sqlalchemy.String),
    sqlalchemy.Column("timeline_hours", sqlalchemy.Integer),
    sqlalchemy.Column("audit_trail",    sqlalchemy.Text),     # JSON string
)

consent_table = sqlalchemy.Table(
    "consent_log", metadata,
    sqlalchemy.Column("id",             sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("subject_id",     sqlalchemy.String),
    sqlalchemy.Column("purpose",        sqlalchemy.String),
    sqlalchemy.Column("lawful_basis",   sqlalchemy.String),
    sqlalchemy.Column("timestamp",      sqlalchemy.String),
    sqlalchemy.Column("integrity_hash", sqlalchemy.String),
)

engine = sqlalchemy.create_engine(
    DATABASE_URL if "postgresql" in DATABASE_URL
    else DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
metadata.create_all(engine)

# ── Security Vault ────────────────────────────────────────────────
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
            iterations=480_000,
        )
        return kdf.derive(self._MASTER_PASSWORD.encode())

    def encrypt(self, plaintext: str) -> str:
        nonce  = os.urandom(12)
        aesgcm = AESGCM(self._key)
        ct     = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return "ENC::" + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, token: str) -> str:
        if not token or not token.startswith("ENC::"):
            return token or ""
        raw    = base64.urlsafe_b64decode(token[5:])
        nonce  = raw[:12]
        ct     = raw[12:]
        aesgcm = AESGCM(self._key)
        return aesgcm.decrypt(nonce, ct, None).decode()

vault = SecurityVault()

# ── CBN Config ────────────────────────────────────────────────────
CBN_TIMELINES = {"Web": 72, "PoS": 72, "ATM": 48, "USSD": 48}
CBN_REF = {
    "Web":  "CBN Circular FPR/DIR/GEN/CIR/06/010",
    "PoS":  "CBN Circular FPR/DIR/GEN/CIR/06/010",
    "ATM":  "CBN Consumer Protection Framework 2022",
    "USSD": "CBN Consumer Protection Framework 2022",
}

# ── OCR (regex) ───────────────────────────────────────────────────
BANK_ALIASES = {
    r"guaranty|gtbank|gt bank":  "Guaranty Trust Bank (GTBank)",
    r"access bank|access\b":     "Access Bank",
    r"united bank|uba\b":        "United Bank for Africa (UBA)",
    r"zenith":                   "Zenith Bank",
    r"first bank|firstbank":     "First Bank of Nigeria",
    r"kuda":                     "Kuda Microfinance Bank",
    r"opay|o-pay":               "OPay Digital Services",
    r"moniepoint":               "Moniepoint MFB",
    r"palmpay":                  "PalmPay",
    r"wema|alat":                "Wema Bank / ALAT",
    r"sterling":                 "Sterling Bank",
    r"fidelity":                 "Fidelity Bank",
    r"fcmb":                     "First City Monument Bank (FCMB)",
    r"stanbic":                  "Stanbic IBTC Bank",
    r"union bank":               "Union Bank",
    r"ecobank":                  "Ecobank Nigeria",
    r"polaris":                  "Polaris Bank",
    r"providus":                 "Providus Bank",
    r"lotus":                    "Lotus Bank",
}

TX_REF_PATTERNS = [
    r"\b([A-Z]{2,5}\d{10,20})\b",
    r"\bRef(?:erence)?[:\s#]+([A-Z0-9\-]{8,25})\b",
    r"\bTrans(?:action)?[:\s#]+([A-Z0-9\-]{8,25})\b",
    r"\bRRN[:\s]+(\d{12})\b",
    r"\bSession ID[:\s]+([A-Z0-9]{15,30})\b",
    r"\b(\d{22})\b",
]

def parse_receipt_text(text: str) -> dict:
    bank = None
    for pattern, canonical in BANK_ALIASES.items():
        if re.search(pattern, text, re.IGNORECASE):
            bank = canonical
            break

    tx_ref = None
    for pat in TX_REF_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            tx_ref = m.group(1)
            break

    amt_match  = re.search(r"(?:₦|NGN|Amount)[:\s]*([\d,]+(?:\.\d{2})?)", text, re.IGNORECASE)
    date_match = re.search(r"(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})", text)

    found = sum(1 for v in [bank, tx_ref, amt_match, date_match] if v)
    return {
        "bank_name":  bank,
        "tx_ref":     tx_ref,
        "amount":     float(amt_match.group(1).replace(",", "")) if amt_match else None,
        "date":       date_match.group(1) if date_match else None,
        "confidence": {4: "HIGH", 3: "HIGH", 2: "MEDIUM"}.get(found, "LOW"),
    }

# ── PDF Generator ─────────────────────────────────────────────────
def generate_escalation_pdf(dispute: dict, customer_name: str, account_number: str) -> str:
    path = f"/tmp/escalation_{dispute['id']}.pdf"

    GREEN   = colors.HexColor("#006B3F")
    NAVY    = colors.HexColor("#0A1628")
    RED     = colors.HexColor("#C0392B")
    GREY    = colors.HexColor("#7F8C9A")
    LIGHT   = colors.HexColor("#F4F6F8")

    doc = SimpleDocTemplate(path, pagesize=A4,
          leftMargin=2.5*cm, rightMargin=2.5*cm,
          topMargin=2.5*cm, bottomMargin=2.5*cm)

    styles = getSampleStyleSheet()

    def sty(name, **kw): return ParagraphStyle(name, **kw)

    header_sty = sty("H", fontSize=22, textColor=NAVY, fontName="Helvetica-Bold", spaceAfter=2)
    sub_sty    = sty("S", fontSize=10, textColor=GREEN, fontName="Helvetica-Bold", spaceAfter=12)
    body_sty   = sty("B", fontSize=10, leading=16, fontName="Helvetica", spaceAfter=10)
    bold_sty   = sty("Bo", fontSize=10, leading=16, fontName="Helvetica-Bold", spaceAfter=6)
    red_sty    = sty("R", fontSize=10, leading=16, fontName="Helvetica-Bold", textColor=RED, spaceAfter=8)
    small_sty  = sty("Sm", fontSize=8, textColor=GREY, fontName="Helvetica", spaceAfter=4)

    now      = datetime.datetime.now()
    deadline = datetime.datetime.fromisoformat(dispute["deadline"])
    logged   = datetime.datetime.fromisoformat(dispute["logged_at"])
    overdue  = max(0, int((now - deadline).total_seconds() / 3600))
    hours    = dispute["timeline_hours"]

    story = []
    story.append(Paragraph("ForgeFlow", header_sty))
    story.append(Paragraph("AI-Powered Consumer Dispute Resolution · Nigeria", sub_sty))
    story.append(HRFlowable(width="100%", thickness=2, color=GREEN, spaceAfter=10))
    story.append(Paragraph(f"Date: <b>{now.strftime('%d %B %Y')}</b>", body_sty))
    story.append(Paragraph(f"Ref: <b>FF-ESC-{dispute['id']}-{now.strftime('%Y%m%d')}</b>", body_sty))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("<b>TO: The Director, Consumer Protection Dept, CBN, Abuja</b>", bold_sty))
    story.append(Paragraph(f"<b>CC: MD/CEO, {dispute['bank']}</b>", body_sty))
    story.append(Spacer(1, 0.3*cm))

    subject = (f"FORMAL ESCALATION — UNRESOLVED FAILED {dispute['tx_type'].upper()} TRANSACTION | "
               f"{dispute['bank'].upper()} | REF: {dispute['tx_ref']} | "
               f"VIOLATION OF {CBN_REF.get(dispute['tx_type'], 'CBN Circular')}")
    story.append(Paragraph(f"<b>RE: {subject}</b>", red_sty))
    story.append(HRFlowable(width="100%", thickness=0.5, color=GREY, spaceAfter=10))
    story.append(Paragraph("Dear Director,", body_sty))
    story.append(Paragraph(
        f"We write on behalf of our client to formally notify your office of a failed electronic "
        f"funds transfer that has remained unresolved beyond the CBN-mandated {hours}-hour window, "
        f"constituting a clear violation by <b>{dispute['bank']}</b>.", body_sty))

    # Case table
    tbl_data = [
        ["Field", "Details"],
        ["Customer Name", customer_name],
        ["Bank", dispute["bank"]],
        ["Transaction Reference", dispute["tx_ref"]],
        ["Channel", dispute["tx_type"]],
        ["Amount", f"NGN {dispute['amount']:,.2f}"],
        ["Date Logged", logged.strftime("%d %b %Y, %H:%M")],
        ["CBN Deadline", deadline.strftime("%d %b %Y, %H:%M")],
        ["Hours Overdue", f"{'OVERDUE BY ' + str(overdue) + 'h' if overdue > 0 else 'WITHIN WINDOW'}"],
    ]
    tbl = Table(tbl_data, colWidths=[5.5*cm, 11*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), NAVY),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, LIGHT]),
        ("FONTNAME", (0,1), (0,-1), "Helvetica-Bold"),
        ("GRID", (0,0), (-1,-1), 0.5, GREY),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("FONTSIZE", (0,0), (-1,-1), 9),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph("<b>FORMAL DEMANDS:</b>", bold_sty))
    for i, d in enumerate([
        f"Immediate refund of <b>NGN {dispute['amount']:,.2f}</b> within 24 hours.",
        "Written confirmation from the bank's Complaint Management Officer (CMO).",
        "Statutory interest on withheld funds at the CBN Monetary Policy Rate.",
        "Formal apology per the CBN Consumer Protection Framework §4.2.",
    ], 1):
        story.append(Paragraph(f"{i}. {d}", body_sty))

    story.append(Paragraph(
        "<b>NOTICE:</b> Failure to comply within 48 hours will result in a formal complaint "
        "filed with the CBN Consumer Protection portal and the Consumer Protection Council (CPC).",
        red_sty))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Yours faithfully,", body_sty))
    story.append(Paragraph("<b>ForgeFlow Dispute Resolution System</b>", bold_sty))
    story.append(HRFlowable(width="100%", thickness=1, color=GREEN, spaceAfter=6))
    story.append(Paragraph(
        f"Auto-generated by ForgeFlow AI Engine v2.0 on {now.strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Case hash: {hashlib.sha256(dispute['id'].encode()).hexdigest()[:16].upper()} | "
        f"NDPA §2.1 compliant", small_sty))

    doc.build(story)
    return path

# ── FastAPI App ───────────────────────────────────────────────────
app = FastAPI(
    title="ForgeFlow API",
    description="AI-Powered Dispute Resolution for Nigeria · CBN Compliant",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ── Pydantic Models ───────────────────────────────────────────────
class DisputeCreate(BaseModel):
    bank:           str
    amount:         float
    tx_type:        str = "PoS"
    tx_ref:         Optional[str] = None
    customer_name:  str
    account_number: Optional[str] = ""
    consent_given:  bool = False

class OCRRequest(BaseModel):
    receipt_text: str

class ResolveRequest(BaseModel):
    dispute_id: str
    note:       Optional[str] = ""

# ── Routes ────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "product": "ForgeFlow v2.0",
        "founder": "Ogunremi Ayodele Kingsley",
        "status":  "operational",
        "docs":    "/docs",
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.datetime.now().isoformat()}

@app.post("/disputes/intake")
async def intake(data: DisputeCreate):
    if not data.consent_given:
        raise HTTPException(
            status_code=403,
            detail="NDPA §2.1: Explicit consent required before processing personal data."
        )

    hours    = CBN_TIMELINES.get(data.tx_type, 72)
    now      = datetime.datetime.now()
    deadline = now + datetime.timedelta(hours=hours)
    warning  = now + datetime.timedelta(hours=hours * 0.75)

    dispute_id = str(uuid.uuid4())[:8].upper()
    tx_ref     = data.tx_ref or f"FF-{uuid.uuid4().hex[:10].upper()}"

    audit = json.dumps([{
        "event":     "DISPUTE_LOGGED",
        "timestamp": now.isoformat(),
        "actor":     "ForgeFlow System",
    }])

    query = disputes_table.insert().values(
        id             = dispute_id,
        bank           = data.bank,
        amount         = data.amount,
        tx_type        = data.tx_type,
        tx_ref         = tx_ref,
        customer_name  = vault.encrypt(data.customer_name),
        account_number = vault.encrypt(data.account_number) if data.account_number else "",
        status         = "MONITORING",
        logged_at      = now.isoformat(),
        deadline       = deadline.isoformat(),
        warning_at     = warning.isoformat(),
        timeline_hours = hours,
        audit_trail    = audit,
    )
    await database.execute(query)

    # Log consent
    consent_entry = {
        "id":             str(uuid.uuid4()),
        "subject_id":     dispute_id,
        "purpose":        "Dispute resolution processing",
        "lawful_basis":   "Explicit consent (NDPA §2.1)",
        "timestamp":      now.isoformat(),
        "integrity_hash": hashlib.sha256(
            f"{dispute_id}{now.isoformat()}".encode()
        ).hexdigest(),
    }
    await database.execute(consent_table.insert().values(**consent_entry))

    return {
        "success":       True,
        "dispute_id":    dispute_id,
        "tx_ref":        tx_ref,
        "bank":          data.bank,
        "amount":        data.amount,
        "tx_type":       data.tx_type,
        "status":        "MONITORING",
        "logged_at":     now.isoformat(),
        "deadline":      deadline.isoformat(),
        "timeline_hours": hours,
        "cbn_reference": CBN_REF.get(data.tx_type, "CBN Circular"),
        "message":       f"Dispute #{dispute_id} logged. CBN {hours}h window started.",
    }

@app.get("/disputes")
async def list_disputes(status: Optional[str] = None):
    query = disputes_table.select()
    rows  = await database.fetch_all(query)
    result = []
    for r in rows:
        d = dict(r)
        if status and d["status"] != status:
            continue
        # Don't expose encrypted fields in list
        d.pop("customer_name", None)
        d.pop("account_number", None)
        d["audit_trail"] = json.loads(d.get("audit_trail", "[]"))
        result.append(d)
    return {"disputes": result, "total": len(result)}

@app.get("/disputes/{dispute_id}")
async def get_dispute(dispute_id: str):
    query = disputes_table.select().where(disputes_table.c.id == dispute_id)
    row   = await database.fetch_one(query)
    if not row:
        raise HTTPException(status_code=404, detail="Dispute not found")
    d = dict(row)
    d["audit_trail"] = json.loads(d.get("audit_trail", "[]"))
    d.pop("customer_name", None)
    d.pop("account_number", None)
    return d

@app.post("/disputes/{dispute_id}/escalate")
async def escalate(dispute_id: str):
    query = disputes_table.select().where(disputes_table.c.id == dispute_id)
    row   = await database.fetch_one(query)
    if not row:
        raise HTTPException(status_code=404, detail="Dispute not found")

    d    = dict(row)
    name = vault.decrypt(d["customer_name"])
    acct = vault.decrypt(d["account_number"]) if d.get("account_number") else ""

    pdf_path = generate_escalation_pdf(d, name, acct)

    # Update status
    now   = datetime.datetime.now()
    trail = json.loads(d.get("audit_trail", "[]"))
    trail.append({
        "event":     "ESCALATION_LETTER_GENERATED",
        "timestamp": now.isoformat(),
        "actor":     "ForgeFlow Engine",
    })
    await database.execute(
        disputes_table.update()
        .where(disputes_table.c.id == dispute_id)
        .values(status="ESCALATE", audit_trail=json.dumps(trail))
    )

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"ForgeFlow_Escalation_{dispute_id}.pdf"
    )

@app.post("/disputes/{dispute_id}/resolve")
async def resolve(dispute_id: str, data: ResolveRequest):
    query = disputes_table.select().where(disputes_table.c.id == dispute_id)
    row   = await database.fetch_one(query)
    if not row:
        raise HTTPException(status_code=404, detail="Dispute not found")

    d     = dict(row)
    now   = datetime.datetime.now()
    trail = json.loads(d.get("audit_trail", "[]"))
    trail.append({
        "event":     "MARKED_RESOLVED",
        "timestamp": now.isoformat(),
        "actor":     "Admin",
        "note":      data.note,
    })
    await database.execute(
        disputes_table.update()
        .where(disputes_table.c.id == dispute_id)
        .values(status="RESOLVED", audit_trail=json.dumps(trail))
    )
    return {"success": True, "dispute_id": dispute_id, "status": "RESOLVED"}

@app.post("/ocr/extract")
async def ocr_extract(data: OCRRequest):
    return parse_receipt_text(data.receipt_text)

@app.post("/escalation/check")
async def check_escalations():
    query = disputes_table.select()
    rows  = await database.fetch_all(query)
    now   = datetime.datetime.now()
    escalated = []
    warned    = []

    for row in rows:
        d = dict(row)
        if d["status"] in ("RESOLVED", "CLOSED", "ESCALATE"):
            continue

        deadline   = datetime.datetime.fromisoformat(d["deadline"])
        warning_at = datetime.datetime.fromisoformat(d["warning_at"])
        trail      = json.loads(d.get("audit_trail", "[]"))

        if now > deadline:
            trail.append({"event": "AUTO_ESCALATED", "timestamp": now.isoformat(), "actor": "ForgeFlow Engine"})
            await database.execute(
                disputes_table.update()
                .where(disputes_table.c.id == d["id"])
                .values(status="ESCALATE", audit_trail=json.dumps(trail))
            )
            escalated.append(d["id"])

        elif now > warning_at and d["status"] == "MONITORING":
            trail.append({"event": "WARNING_TRIGGERED", "timestamp": now.isoformat(), "actor": "ForgeFlow Engine"})
            await database.execute(
                disputes_table.update()
                .where(disputes_table.c.id == d["id"])
                .values(status="WARNING", audit_trail=json.dumps(trail))
            )
            warned.append(d["id"])

    return {
        "checked":   len(rows),
        "escalated": escalated,
        "warned":    warned,
        "timestamp": now.isoformat(),
    }

@app.get("/stats")
async def stats():
    query = disputes_table.select()
    rows  = await database.fetch_all(query)
    by_status = {}
    total_amount = 0
    for r in rows:
        d = dict(r)
        by_status[d["status"]] = by_status.get(d["status"], 0) + 1
        total_amount += d["amount"]
    return {
        "total_disputes": len(rows),
        "by_status":      by_status,
        "total_amount":   total_amount,
    }
