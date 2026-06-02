"""AuthBind: ML-DSA-65 signature on H_bind = Hash(transcript || gpk || ids)."""

from __future__ import annotations

import hashlib

from dilithium_py.ml_dsa import ML_DSA_65

BIND_DOMAIN = b"QLAZE-BIND-v1"
DSA = ML_DSA_65


def h_bind(transcript: bytes, gpk: bytes, id_a: bytes, id_b: bytes) -> bytes:
    return hashlib.sha3_256(BIND_DOMAIN + transcript + gpk + id_a + id_b).digest()


def authbind_sign(sk: bytes, transcript: bytes, gpk: bytes, id_a: bytes, id_b: bytes) -> bytes:
    msg = h_bind(transcript, gpk, id_a, id_b)
    return DSA.sign(sk, msg)


def authbind_verify(
    pk: bytes, sig: bytes, transcript: bytes, gpk: bytes, id_a: bytes, id_b: bytes
) -> bool:
    return DSA.verify(pk, h_bind(transcript, gpk, id_a, id_b), sig)


def authbind_keygen() -> tuple[bytes, bytes]:
    return DSA.keygen()
