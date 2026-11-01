# PinHire Guard Webhook (PH-2026-4061)

Live Webhook Guard implementation for **Candidate PH-2026-4061** with seed `SEED-4061-PH-CCE6`.

## Summary of Specifications

| Requirement | Implementation Details |
| :--- | :--- |
| **HMAC Signature** | Header `x-pinhire-hmac-4061` = hex HMAC-SHA256(`raw_body`, key=`SEED-4061-PH-CCE6`). Rejects invalid or missing signatures with **HTTP 401**. |
| **Idempotency** | Atomic concurrency lock on `payload.tx_ref_4061` (TTL: 240s). First call returns `{"status": "processed"}`, repeated calls return **HTTP 409** `{"status": "duplicate"}`. |
| **Refund Ceiling & Prompt Injection** | Strictly caps refunds at **175 AED**. Refuses any request or prompt injection (e.g. `SYSTEM OVERRIDE`) exceeding 175 AED with **HTTP 400** `{"status": "rejected", "refund_aed": 0}`. |
| **FAQ Speed & Caching** | High-performance in-memory cache for `faq.query` answering repeated questions in **< 1 ms** (benchmark limit: < 650 ms). |

## File Layout

- [app.py](file:///Users/abhisheksajjanapu/Downloads/driftcontrol/guard_webhook/app.py): Complete FastAPI server implementing the 4 requirements.
- [test_suite.py](file:///Users/abhisheksajjanapu/Downloads/driftcontrol/guard_webhook/test_suite.py): Automated test suite for all 5 test scenarios.
- [run_live.sh](file:///Users/abhisheksajjanapu/Downloads/driftcontrol/guard_webhook/run_live.sh): One-click runner starting the server and establishing an HTTPS tunnel.
- [Dockerfile](file:///Users/abhisheksajjanapu/Downloads/driftcontrol/guard_webhook/Dockerfile): Production container configuration.
- [railway.json](file:///Users/abhisheksajjanapu/Downloads/driftcontrol/guard_webhook/railway.json) & [Procfile](file:///Users/abhisheksajjanapu/Downloads/driftcontrol/guard_webhook/Procfile): Zero-config deployment files for Railway.

## Running Locally

```bash
cd guard_webhook
uv run --with fastapi --with "uvicorn[standard]" python3 app.py
```

## Running Tests

```bash
uv run --with httpx python3 test_suite.py
```

## Deploying to Railway

1. Push this folder to a GitHub repository.
2. Go to [railway.app](https://railway.app), click **New Project** -> **Deploy from GitHub repo**.
3. Railway automatically detects `railway.json` and `Dockerfile` and deploys your live HTTPS webhook URL at `https://<your-subdomain>.up.railway.app/api/guard`.
