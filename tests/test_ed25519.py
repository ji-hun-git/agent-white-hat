"""Ed25519 in pure Python, against RFC 8032's test vectors (section 7.1). Vectors 2 and 3 were also reproduced with
OpenSSL 3.5. Standard library only: python -m unittest discover -s tests"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PAH_HOME", tempfile.mkdtemp(prefix="pah-test-home-"))

from pah import ed25519  # noqa: E402

VECTORS = [  # secret key (seed), public key, message, signature
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
L = 2**252 + 27742317777372353535851937790883648493


class Ed25519Test(unittest.TestCase):
    def test_public_keys_match_rfc_8032(self):
        for seed, pub, _, _ in VECTORS:
            self.assertEqual(ed25519.public_key(bytes.fromhex(seed)).hex(), pub)

    def test_signatures_match_rfc_8032(self):
        for seed, _, msg, sig in VECTORS:
            self.assertEqual(ed25519.sign(bytes.fromhex(seed), bytes.fromhex(msg)).hex(), sig)

    def test_rfc_8032_signatures_verify(self):
        for _, pub, msg, sig in VECTORS:
            self.assertTrue(ed25519.verify(bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)))

    def test_a_changed_message_does_not_verify(self):
        _, pub, _, sig = VECTORS[1]
        self.assertFalse(ed25519.verify(bytes.fromhex(pub), b"\x73", bytes.fromhex(sig)))

    def test_a_changed_signature_does_not_verify(self):
        _, pub, msg, sig = VECTORS[1]
        bad = bytearray(bytes.fromhex(sig))
        bad[10] ^= 1
        self.assertFalse(ed25519.verify(bytes.fromhex(pub), bytes.fromhex(msg), bytes(bad)))

    def test_another_key_does_not_verify(self):
        _, _, msg, sig = VECTORS[1]
        self.assertFalse(ed25519.verify(bytes.fromhex(VECTORS[2][1]), bytes.fromhex(msg), bytes.fromhex(sig)))

    def test_a_malleable_signature_is_refused(self):
        # S + L verifies under a lax check; RFC 8032 requires S < L.
        _, pub, msg, sig = VECTORS[1]
        raw = bytes.fromhex(sig)
        s = int.from_bytes(raw[32:], "little") + L
        self.assertFalse(ed25519.verify(bytes.fromhex(pub), bytes.fromhex(msg), raw[:32] + s.to_bytes(32, "little")))

    def test_wrong_lengths_and_bad_points_are_refused_not_raised(self):
        _, pub, msg, sig = VECTORS[1]
        self.assertFalse(ed25519.verify(bytes.fromhex(pub)[:31], bytes.fromhex(msg), bytes.fromhex(sig)))
        self.assertFalse(ed25519.verify(bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)[:63]))
        self.assertFalse(ed25519.verify(b"\xff" * 32, bytes.fromhex(msg), bytes.fromhex(sig)))

    def test_a_new_key_signs_and_verifies(self):
        seed = os.urandom(32)
        pub = ed25519.public_key(seed)
        sig = ed25519.sign(seed, b"shield bundle")
        self.assertTrue(ed25519.verify(pub, b"shield bundle", sig))
        self.assertFalse(ed25519.verify(pub, b"shield bundle!", sig))


if __name__ == "__main__":
    unittest.main()
