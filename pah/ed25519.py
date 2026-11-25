"""Ed25519 signatures (RFC 8032) in pure Python, so shield bundles can be verified without a third-party package.

Python's standard library hashes but does not sign. This follows the reference implementation in RFC 8032 section 6,
with extended coordinates, and verifies strictly: the public key and R must decode to curve points and S must be
below the group order, so a signature cannot be altered into a second valid one.

Verification is what the guard needs and takes a few milliseconds. Signing is here for publishers of shield bundles;
it is not constant-time, so sign on a machine only you use.
"""
from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _add(a: tuple, b: tuple) -> tuple:
    """Point addition in extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z."""
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(scalar: int, point: tuple) -> tuple:
    result = (0, 1, 1, 0)  # the neutral element
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(a: tuple, b: tuple) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, -1, P) % P
_GX = _recover_x(_GY, 0)
BASE = (_GX, _GY, 1, _GX * _GY % P)


def _compress(point: tuple) -> bytes:
    zinv = pow(point[2], -1, P)
    x, y = point[0] * zinv % P, point[1] * zinv % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data: bytes) -> tuple | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _expand(secret: bytes) -> tuple[int, bytes]:
    if len(secret) != 32:
        raise ValueError("an Ed25519 secret key is 32 bytes")
    h = _sha512(bytes(secret))
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret: bytes) -> bytes:
    """The 32-byte public key for a 32-byte secret key (the seed)."""
    a, _ = _expand(secret)
    return _compress(_mul(a, BASE))


def sign(secret: bytes, message: bytes) -> bytes:
    """A 64-byte signature of message."""
    a, prefix = _expand(secret)
    pub = _compress(_mul(a, BASE))
    r = int.from_bytes(_sha512(prefix + bytes(message)), "little") % L
    R = _compress(_mul(r, BASE))
    h = int.from_bytes(_sha512(R + pub + bytes(message)), "little") % L
    return R + ((r + h * a) % L).to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True only for a valid signature by this public key; malformed input is False, never an exception."""
    try:
        public, message, signature = bytes(public), bytes(message), bytes(signature)
    except TypeError:
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(_sha512(signature[:32] + public + message), "little") % L
    return _equal(_mul(s, BASE), _add(R, _mul(h, A)))
