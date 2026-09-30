import base64
import hashlib
import hmac
import os
import uuid

from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
DEFAULT_PAGE_SIZE = 50


def verify_signature(payload: bytes, signature: str) -> bool:
    expected = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.get("/users/{user_id}")
async def get_user(user_id: str, authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return {"id": user_id, "request_id": str(uuid.uuid4())}


def fingerprint(data: bytes) -> str:
    # e.g. "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    return hashlib.sha256(data).hexdigest()


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"offset:{offset}".encode()).decode()


CHECKSUMS = {
    "model.safetensors": "328239ed2251e14f01374fa21f10e4f87273aacac8322f058352c2ded7847a2d",
    "tokenizer.json": "f372d32aa9441b88ce66d45c093addf8cee7de27b38655dd459a6ddb4c87d214",
    "config.json": "713b894ee92d69a626eccb0d691375d98974f7c915b6bd359c96f9d62c11a335",
}
TEST_USER_ID = "bfcba3f3-31ff-4b5f-a31e-3e2382551b1a"
