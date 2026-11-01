"""
PinHire Build Task - Live Webhook Guard
Candidate ID: PH-2026-4061
Seed Token: SEED-4061-PH-CCE6
Header: x-pinhire-hmac-4061
Max Refund: 175 AED
Idempotency TTL: 240s
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from typing import Dict, Any, Tuple

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("guard-webhook")

SEED_TOKEN = os.getenv("SEED_TOKEN", "SEED-4061-PH-CCE6").strip()
HMAC_HEADER = "x-pinhire-hmac-4061"
REFUND_LIMIT_AED = 175.0
IDEMPOTENCY_TTL_SECONDS = 240.0

app = FastAPI(title="PinHire Guard Webhook", version="1.0.0")


class IdempotencyStore:
    def __init__(self, ttl: float = IDEMPOTENCY_TTL_SECONDS):
        self.ttl = ttl
        self._store: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def check_and_lock(self, tx_ref: str) -> bool:
        """
        Atomically checks and registers tx_ref.
        Returns True if this is the FIRST request (acquired).
        Returns False if duplicate within TTL.
        """
        now = time.time()
        async with self._lock:
            # Clean expired records periodically
            if len(self._store) > 1000:
                self._store = {k: ts for k, ts in self._store.items() if now - ts < self.ttl}

            if tx_ref in self._store:
                if now - self._store[tx_ref] < self.ttl:
                    return False  # Duplicate

            # Register current transaction
            self._store[tx_ref] = now
            return True


# Concurrency-safe store for transaction idempotency
idempotency_store = IdempotencyStore(ttl=IDEMPOTENCY_TTL_SECONDS)

# Fast in-memory FAQ cache
faq_cache: Dict[str, str] = {}
faq_cache_lock = asyncio.Lock()

# Pre-populated common FAQ responses
FAQ_KNOWLEDGE_BASE = {
    "refund policy": "Our refund policy allows refunds up to a maximum limit of 175 AED within the allowed timeframe.",
    "maximum refund": "The maximum allowable refund is 175 AED.",
    "refund limit": "The maximum allowable refund is 175 AED per transaction.",
    "how to refund": "To request a refund, submit a signed refund.requested event with a valid transaction reference.",
    "currency": "All transactions and refunds are processed in AED (United Arab Emirates Dirham).",
    "business hours": "Our automated services and support are available 24 hours a day, 7 days a week.",
    "support": "You can contact support via our automated webhook portal or candidate inquiry desk.",
}


def verify_hmac(raw_body: bytes, received_signature: str | None) -> bool:
    """Verifies HMAC-SHA256 signature against the raw body."""
    if not received_signature:
        return False

    computed = hmac.new(
        SEED_TOKEN.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    # Case-insensitive constant-time comparison
    return hmac.compare_digest(computed.lower(), received_signature.strip().lower())


def extract_refund_amount(payload: Dict[str, Any]) -> Tuple[float, bool]:
    """
    Extracts explicit refund amount from payload fields or currency-context text.
    Returns (amount, is_found).
    """
    # 1. Explicit amount fields take highest priority
    for field in ["refund_aed", "amount_aed", "amount", "refund_amount", "value"]:
        val = payload.get(field)
        if val is not None:
            try:
                return float(val), True
            except (ValueError, TypeError):
                pass

    # 2. Check customer_message or notes with currency / refund context
    combined_text = " ".join(
        str(payload.get(k, "")) for k in ["customer_message", "message", "notes", "reason", "query"]
    )

    if combined_text:
        patterns = [
            r'(?:aed|dirhams|dhs)\s*([0-9]+(?:\.[0-9]+)?)',
            r'([0-9]+(?:\.[0-9]+)?)\s*(?:aed|dirhams|dhs)',
            r'refund\s*(?:of\s*)?([0-9]+(?:\.[0-9]+)?)',
            r'([0-9]+(?:\.[0-9]+)?)\s*(?:refund)',
            r'(?:grant|approve|pay|transfer)\s*([0-9]+(?:\.[0-9]+)?)',
        ]
        for pattern in patterns:
            m = re.search(pattern, combined_text, re.IGNORECASE)
            if m:
                try:
                    return float(m.group(1)), True
                except ValueError:
                    pass

    return 0.0, False


def check_injection_override_amount(text: str) -> Tuple[bool, float | None]:
    """
    Checks if text contains prompt injection trying to force a refund amount.
    Returns (is_injection, attempted_amount).
    """
    upper_text = text.upper()
    triggers = [
        "SYSTEM OVERRIDE",
        "SYSTEM_OVERRIDE",
        "OVERRIDE",
        "IGNORE ALL PREVIOUS INSTRUCTIONS",
        "DISREGARD RULES",
        "ADMIN OVERRIDE",
        "GRANT MAXIMUM",
        "UNLIMITED REFUND",
    ]
    is_injection = any(t in upper_text for t in triggers)
    if not is_injection:
        return False, None

    # Check if injection specifies an amount
    patterns = [
        r'(?:aed|dirhams|dhs)\s*([0-9]+(?:\.[0-9]+)?)',
        r'([0-9]+(?:\.[0-9]+)?)\s*(?:aed|dirhams|dhs)',
        r'(?:refund|grant|approve|pay|give|amount)\s*(?:of\s*)?([0-9]+(?:\.[0-9]+)?)',
    ]
    for pattern in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            try:
                return True, float(m.group(1))
            except ValueError:
                pass

    # Numbers in injection text
    numbers = [float(n) for n in re.findall(r'\b[0-9]+(?:\.[0-9]+)?\b', text)]
    if numbers:
        return True, max(numbers)

    return True, None


async def handle_faq_query(payload: Dict[str, Any]) -> JSONResponse:
    """Answers FAQ query with speed caching."""
    question = (
        payload.get("question")
        or payload.get("query")
        or payload.get("faq_query")
        or payload.get("text")
        or payload.get("message")
        or payload.get("customer_message")
        or ""
    )

    clean_key = question.strip().lower()

    # Fast in-memory cache lookup (< 1 ms)
    if clean_key in faq_cache:
        cached_answer = faq_cache[clean_key]
        return JSONResponse(
            status_code=200,
            content={
                "status": "processed",
                "answer": cached_answer,
                "response": cached_answer,
                "cached": True,
            }
        )

    # Determine answer
    answer = None
    for kw, ans in FAQ_KNOWLEDGE_BASE.items():
        if kw in clean_key:
            answer = ans
            break

    if not answer:
        answer = f"Our standard policy provides full service and refunds up to {int(REFUND_LIMIT_AED)} AED. For specific assistance regarding '{question}', our support team is available 24/7."

    # Cache answer for subsequent queries
    async with faq_cache_lock:
        faq_cache[clean_key] = answer

    return JSONResponse(
        status_code=200,
        content={
            "status": "processed",
            "answer": answer,
            "response": answer,
            "cached": False,
        }
    )


async def handle_refund_request(payload: Dict[str, Any]) -> JSONResponse:
    """Handles refund requested event with strict limits and idempotency."""
    tx_ref = payload.get("tx_ref_4061")
    if not tx_ref:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error": "Missing required field: payload.tx_ref_4061"}
        )

    # 1. Idempotency Check (Race-condition safe)
    is_first_call = await idempotency_store.check_and_lock(str(tx_ref))
    if not is_first_call:
        logger.info(f"Duplicate transaction detected: {tx_ref}")
        return JSONResponse(
            status_code=409,
            content={"status": "duplicate", "tx_ref_4061": str(tx_ref)}
        )

    # 2. Extract requested amount and inspect prompt injection
    amount, is_found = extract_refund_amount(payload)
    customer_msg = " ".join(
        str(payload.get(k, "")) for k in ["customer_message", "message", "notes", "reason", "query"]
    )
    is_injection, injection_amount = check_injection_override_amount(customer_msg)

    effective_amount = amount
    if injection_amount is not None:
        effective_amount = max(amount, injection_amount)

    # 3. Enforce Refund Limit (Never refund more than 175 AED)
    if effective_amount > REFUND_LIMIT_AED:
        logger.warning(
            f"Refund refused for tx {tx_ref}: requested {effective_amount} exceeds limit {REFUND_LIMIT_AED} AED (injection={is_injection})"
        )
        return JSONResponse(
            status_code=400,
            content={
                "status": "rejected",
                "refund_aed": 0,
                "error": f"Refund amount ({effective_amount} AED) exceeds maximum allowable limit of {REFUND_LIMIT_AED} AED",
                "tx_ref_4061": str(tx_ref),
            }
        )

    # If injection detected without any valid numeric amount, or claiming unlimited
    if is_injection and not is_found and injection_amount is None:
        logger.warning(f"Prompt injection detected on tx {tx_ref} without valid amount. Refusing.")
        return JSONResponse(
            status_code=400,
            content={
                "status": "rejected",
                "refund_aed": 0,
                "error": "Override rejected. System limits enforced.",
                "tx_ref_4061": str(tx_ref),
            }
        )

    # Valid refund within limit (<= 175 AED)
    approved_amount = min(effective_amount, REFUND_LIMIT_AED)
    logger.info(f"Refund approved for tx {tx_ref}: {approved_amount} AED")

    return JSONResponse(
        status_code=200,
        content={
            "status": "processed",
            "refund_aed": approved_amount,
            "tx_ref_4061": str(tx_ref),
        }
    )


@app.api_route(
    "/api/guard",
    methods=["POST"],
    tags=["Guard Webhook"],
)
@app.api_route(
    "/webhook",
    methods=["POST"],
    tags=["Guard Webhook"],
)
@app.api_route(
    "/",
    methods=["POST"],
    tags=["Guard Webhook"],
)
async def webhook_guard(request: Request):
    # 1. Read exact raw body bytes
    raw_body = await request.body()

    # 2. Extract and verify HMAC signature header
    signature = request.headers.get(HMAC_HEADER)
    if not verify_hmac(raw_body, signature):
        logger.warning(f"Signature verification failed for header {HMAC_HEADER}: {signature}")
        return JSONResponse(
            status_code=401,
            content={
                "status": "unauthorized",
                "error": f"Invalid or missing HMAC signature header: {HMAC_HEADER}"
            }
        )

    # 3. Parse JSON payload
    try:
        body_json = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error": f"Malformed JSON: {str(e)}"}
        )

    event = body_json.get("event")
    payload = body_json.get("payload") or {}

    if not isinstance(payload, dict):
        payload = {}

    # 4. Route by event type
    if event == "refund.requested":
        return await handle_refund_request(payload)
    elif event == "faq.query":
        return await handle_faq_query(payload)
    else:
        # Default response for unknown/generic events
        tx_ref = payload.get("tx_ref_4061")
        if tx_ref:
            is_first = await idempotency_store.check_and_lock(str(tx_ref))
            if not is_first:
                return JSONResponse(
                    status_code=409,
                    content={"status": "duplicate", "tx_ref_4061": str(tx_ref)}
                )
        return JSONResponse(
            status_code=200,
            content={"status": "processed", "event": event}
        )


@app.get("/")
@app.get("/api/guard")
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "candidate": "PH-2026-4061",
        "seed": "SEED-4061-PH-CCE6",
        "header": HMAC_HEADER,
        "refund_limit_aed": REFUND_LIMIT_AED,
        "endpoint": "/api/guard"
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
