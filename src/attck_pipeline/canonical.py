import hashlib
import json
from datetime import datetime

import rfc8785


def _serialize_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _prepare_for_canonical(obj):
    """Convert datetime objects to ISO strings so rfc8785 can handle them."""
    if isinstance(obj, dict):
        return {k: _prepare_for_canonical(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_prepare_for_canonical(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def canonical_bytes(obj: dict) -> bytes:
    return rfc8785.dumps(_prepare_for_canonical(obj))


def content_hash(obj: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


def bundle_hash(raw_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
