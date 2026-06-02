"""ZTARP: 96-byte DPR encode/verify with LRU cache fast path."""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

DPR_MAGIC = b"QZ"
DPR_VERSION = 1
DPR_SIZE = 96


@dataclass
class DPR:
    root_id: bytes
    cur_id: bytes
    edge_hash: bytes
    depth: int
    epoch: int
    sig_fp: bytes

    def encode(self) -> bytes:
        if len(self.root_id) != 16 or len(self.cur_id) != 16:
            raise ValueError("IDs must be 16 bytes")
        if len(self.edge_hash) != 32 or len(self.sig_fp) != 24:
            raise ValueError("hash/fingerprint size")
        buf = bytearray(DPR_SIZE)
        buf[0:2] = DPR_MAGIC
        buf[2] = DPR_VERSION
        buf[3] = self.depth & 0xFF
        struct.pack_into("<I", buf, 4, self.epoch)
        buf[8:24] = self.root_id
        buf[24:40] = self.cur_id
        buf[40:72] = self.edge_hash
        buf[72:96] = self.sig_fp
        return bytes(buf)

    @classmethod
    def decode(cls, data: bytes) -> "DPR":
        if len(data) != DPR_SIZE or data[0:2] != DPR_MAGIC:
            raise ValueError("invalid DPR")
        return cls(
            root_id=data[8:24],
            cur_id=data[24:40],
            edge_hash=data[40:72],
            depth=data[3],
            epoch=struct.unpack_from("<I", data, 4)[0],
            sig_fp=data[72:96],
        )


def edge_hash(parent_h: bytes, cur_id: bytes, caps: bytes, ts: int) -> bytes:
    return hashlib.sha3_256(parent_h + cur_id + caps + ts.to_bytes(8, "big")).digest()


def sig_fingerprint(sigma_full: bytes) -> bytes:
    return hashlib.sha3_256(sigma_full).digest()[:24]


class DPRVerifier:
    """Fast-path cache + slow-path ML-DSA verify hook."""

    def __init__(self) -> None:
        self._cache: Dict[bytes, Tuple[bytes, bytes]] = {}
        self.hits = 0
        self.misses = 0

    def cache_insert(self, sig_fp: bytes, edge_h: bytes, sigma_full: bytes) -> None:
        self._cache[sig_fp] = (edge_h, sigma_full)

    def verify_fast(self, dpr: DPR) -> bool:
        entry = self._cache.get(dpr.sig_fp)
        if entry is None:
            self.misses += 1
            return False
        edge_h, _sigma = entry
        if edge_h != dpr.edge_hash:
            return False
        self.hits += 1
        return True

    def verify_slow(
        self,
        dpr: DPR,
        gpk: bytes,
        verify_fn,
    ) -> bool:
        entry = self._cache.get(dpr.sig_fp)
        if entry is None:
            self.misses += 1
            return False
        edge_h, sigma_full = entry
        if edge_h != dpr.edge_hash:
            return False
        ok = verify_fn(gpk, (edge_h, dpr.depth, dpr.epoch), sigma_full)
        if ok:
            self.hits += 1
        return ok
