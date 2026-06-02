"""EP-HS: ML-KEM-768 handshake with HMAC key confirmation."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768

DOMAIN = b"QLAZE-EPHS-v1"
KEM = ML_KEM_768


@dataclass
class EPHSKeys:
    ck: bytes
    transcript: bytes


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA384(),
        length=length,
        salt=None,
        info=info,
    ).derive(prk)


def build_transcript(
    pk_a: bytes,
    pk_b: bytes,
    c_a: bytes,
    c_b: bytes,
    n_a: bytes,
    n_b: bytes,
    caps_a: bytes,
    caps_b: bytes,
    epoch: int,
    gpk: bytes,
    id_a: bytes,
    id_b: bytes,
) -> bytes:
    return (
        DOMAIN
        + pk_a
        + pk_b
        + c_a
        + c_b
        + n_a
        + n_b
        + caps_a
        + caps_b
        + epoch.to_bytes(8, "big")
        + gpk
        + id_a
        + id_b
    )


def derive_ck(k_ab: bytes, k_ba: bytes, transcript: bytes) -> bytes:
    ms = hashlib.sha3_256(k_ab + k_ba).digest()
    return _hkdf_expand(ms, transcript, 32)


def key_confirm_tag(ck: bytes, label: bytes, transcript: bytes) -> bytes:
    return hmac.new(ck, label + transcript, hashlib.sha256).digest()[:16]


def ephs_session(
    caps_a: bytes = b"\x00" * 32,
    caps_b: bytes = b"\x00" * 32,
    epoch: int = 1,
    gpk: bytes = b"",
    id_a: bytes = b"A" * 16,
    id_b: bytes = b"B" * 16,
) -> tuple[EPHSKeys, dict]:
    """Full in-process EP-HS (initiator A, responder B) for benchmarking."""
    pk_a, sk_a = KEM.keygen()
    pk_b, sk_b = KEM.keygen()
    n_a, n_b = secrets.token_bytes(16), secrets.token_bytes(16)

    # B -> A: encapsulate to pk_a
    k_ab, c_a = KEM.encaps(pk_a)
    k_ab_check = KEM.decaps(sk_a, c_a)
    if k_ab != k_ab_check:
        raise RuntimeError("EP-HS K_AB mismatch")

    # A -> B: encapsulate to pk_b
    k_ba, c_b = KEM.encaps(pk_b)
    k_ba_check = KEM.decaps(sk_b, c_b)
    if k_ba != k_ba_check:
        raise RuntimeError("EP-HS K_BA mismatch")

    transcript = build_transcript(
        pk_a, pk_b, c_a, c_b, n_a, n_b, caps_a, caps_b, epoch, gpk, id_a, id_b
    )
    ck = derive_ck(k_ab, k_ba, transcript)
    tag_a = key_confirm_tag(ck, b"QLAZE-EPHS-init", transcript)
    tag_b = key_confirm_tag(ck, b"QLAZE-EPHS-resp", transcript)

    if key_confirm_tag(ck, b"QLAZE-EPHS-init", transcript) != tag_a:
        raise RuntimeError("EP-HS tag_A failed")
    if key_confirm_tag(ck, b"QLAZE-EPHS-resp", transcript) != tag_b:
        raise RuntimeError("EP-HS tag_B failed")

    return EPHSKeys(ck=ck, transcript=transcript), {
        "pk_a_len": len(pk_a),
        "c_a_len": len(c_a),
        "c_b_len": len(c_b),
        "transcript_len": len(transcript),
    }
