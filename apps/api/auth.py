"""
auth.py
-------
API authentication for the EASM backend.

The Next.js frontend authenticates end users with NextAuth (Google). Those
session JWTs are encrypted and awkward to verify in Python, so the frontend
acts as a Backend-For-Frontend (BFF): it authenticates the user, then calls
this API server-side with a shared secret (``X-Internal-Secret``) and the
acting user's email (``X-User-Email``).

This module rejects any request that doesn't carry valid internal credentials,
so the API is no longer open to the world. Routes depend on ``get_current_user``
to obtain the acting user's email for ownership scoping.
"""

import os

from dotenv import load_dotenv
from fastapi import Header, HTTPException

load_dotenv()

INTERNAL_API_SECRET = os.getenv("INTERNAL_API_SECRET")


def get_current_user(
    x_internal_secret: str | None = Header(default=None),
    x_user_email: str | None = Header(default=None),
) -> str:
    """Authenticate an internal (BFF) request and return the acting user's email.

    Fails closed: if the shared secret is not configured, the API cannot be
    trusted to be protected, so requests are refused rather than allowed.
    """
    if not INTERNAL_API_SECRET:
        raise HTTPException(
            status_code=503,
            detail="API auth is not configured (INTERNAL_API_SECRET unset).",
        )
    if x_internal_secret != INTERNAL_API_SECRET:
        raise HTTPException(status_code=401, detail="Invalid or missing internal credentials.")
    if not x_user_email:
        raise HTTPException(status_code=401, detail="Missing user identity.")
    return x_user_email.strip().lower()
