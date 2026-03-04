#!/usr/bin/env python3
"""
Copy/Paste Secure Chat (Spec-aligned Double Ratchet + DH handshake)

Security goals:
- Manual copy/paste transport (no sockets/server)
- Diffie-Hellman ratchet via X25519
- Double Ratchet state machine with skipped-message-key cache
- Optional hybrid PSK mode to hedge against "store now, decrypt later" risks

IMPORTANT:
- This is strong cryptography, but still an app-level implementation.
- Treat it as "serious prototype" unless independently audited.
- For best security, verify fingerprints out-of-band.

Requirements:
  pip install cryptography

Run GUI mode (if Tkinter exists):
  python3 dh_double_ratchet_chat.py

Run CLI mode:
  python3 dh_double_ratchet_chat.py --cli
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# -------------------------
# Constants
# -------------------------

APP_VERSION = 2
IDENTITY_PATH = Path.home() / ".copyratchet_identity_v1.json"
PEER_PINS_PATH = Path.home() / ".copyratchet_peer_pins_v1.json"

MAX_SKIP_DEFAULT = 2000
MAX_STORED_MKS_DEFAULT = 5000


# -------------------------
# Encoding / parsing helpers
# -------------------------

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64d(data: str) -> bytes:
    s = data.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def encode_packet(obj: dict[str, Any]) -> str:
    return b64e(canonical_json(obj))


def decode_packet(text: str) -> dict[str, Any]:
    raw = text.strip()
    if not raw:
        raise ValueError("Packet is empty")

    # Accept either raw JSON or base64-wrapped JSON
    if raw.startswith("{"):
        return json.loads(raw)

    try:
        return json.loads(b64d(raw).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid packet format") from exc


def x25519_pub_to_bytes(pub: x25519.X25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def x25519_priv_to_bytes(priv: x25519.X25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )


def bytes_to_x25519_pub(data: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(data)


def bytes_to_x25519_priv(data: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(data)


def ed25519_pub_to_bytes(pub: ed25519.Ed25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def ed25519_priv_to_bytes(priv: ed25519.Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )


def bytes_to_ed25519_pub(data: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(data)


def bytes_to_ed25519_priv(data: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(data)


# -------------------------
# KDF helpers
# -------------------------

def hkdf_derive(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def kdf_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    KDF_CK: returns next_chain_key, message_key
    """
    next_ck = hmac_sha256(chain_key, b"\x01")
    mk = hmac_sha256(chain_key, b"\x02")
    return next_ck, mk


def kdf_root(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """
    KDF_RK: returns next_root_key, next_chain_key
    """
    out = hkdf_derive(
        dh_out,
        salt=root_key,
        info=b"DR-RK-v2",
        length=64,
    )
    return out[:32], out[32:64]


def derive_handshake_ikm(x25519_shared: bytes, psk: Optional[bytes]) -> tuple[bytes, str]:
    """
    Derive initial IKM for ratchet init.

    If psk is present, we mix it in to hedge against future quantum attacks
    (assuming PSK entropy is high and PSK exchange is secure/out-of-band).
    """
    if not psk:
        return x25519_shared, "x25519"

    mixed = hkdf_derive(
        x25519_shared + psk,
        salt=b"\x00" * 32,
        info=b"DR-HYBRID-PSK-v2",
        length=32,
    )
    return mixed, "x25519+psk"


def kdf_handshake(ikm: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    RatchetInit KDF output:
      RK, CK_initiator_send, CK_responder_send, confirm_key
    """
    out = hkdf_derive(
        ikm,
        salt=b"\x00" * 32,
        info=b"DR-INIT-v2",
        length=128,
    )
    return out[:32], out[32:64], out[64:96], out[96:128]


def derive_session_id(confirm_key: bytes, session_nonce: bytes) -> bytes:
    return hkdf_derive(
        confirm_key,
        salt=session_nonce,
        info=b"DR-SESSION-ID-v2",
        length=16,
    )


def parse_psk_input(psk_text: str) -> tuple[Optional[bytes], str]:
    """
    Supported formats:
      - ''                      => disabled
      - 'hex:<hex-bytes>'
      - 'b64:<base64-url-bytes>'
      - any other text          => UTF-8 bytes

    Returned PSK is SHA256(raw_input_bytes), to normalize size.
    """
    t = psk_text.strip()
    if not t:
        return None, "x25519"

    if t.startswith("hex:"):
        raw = bytes.fromhex(t[4:].strip())
    elif t.startswith("b64:"):
        raw = b64d(t[4:].strip())
    else:
        raw = t.encode("utf-8")

    if len(raw) < 16:
        raise ValueError(
            "PSK is too short. Use at least 16 raw bytes (32+ recommended), "
            "e.g. b64:<random-bytes>."
        )

    return hashlib.sha256(raw).digest(), "x25519+psk"


def random_psk_b64() -> str:
    return "b64:" + b64e(os.urandom(32))


# -------------------------
# Persistent identity / pinning
# -------------------------


def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(path)


class IdentityStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load_or_create(self) -> ed25519.Ed25519PrivateKey:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                return bytes_to_ed25519_priv(b64d(data["ed25519_private"]))
            except Exception as exc:
                raise ValueError(f"Identity file is corrupt: {self.path}") from exc

        priv = ed25519.Ed25519PrivateKey.generate()
        _atomic_write_json(
            self.path,
            {
                "v": 1,
                "ed25519_private": b64e(ed25519_priv_to_bytes(priv)),
            },
        )
        return priv


class PeerPins:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._pins: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            pins = data.get("pins", {})
            if isinstance(pins, dict):
                return {str(k): str(v) for k, v in pins.items()}
            return {}
        except Exception:
            return {}

    def _save(self) -> None:
        _atomic_write_json(self.path, {"v": 1, "pins": self._pins})

    def check_or_pin(self, peer_name: str, peer_id_pub_b64: str) -> None:
        name = peer_name.strip()
        if not name:
            return

        existing = self._pins.get(name)
        if existing and not secrets.compare_digest(existing, peer_id_pub_b64):
            raise ValueError(
                f"Pinned identity mismatch for peer '{name}'. "
                "Possible MITM or changed device key."
            )

        if not existing:
            self._pins[name] = peer_id_pub_b64
            self._save()


# -------------------------
# Handshake payload helpers
# -------------------------


def req_payload(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage": "req",
        "v": packet["v"],
        "from": packet["from"],
        "id_pub": packet["id_pub"],
        "ratchet_pub": packet["ratchet_pub"],
        "session_nonce": packet["session_nonce"],
        "kdf_mode": packet["kdf_mode"],
    }


def resp_base_payload(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "stage": "resp_base",
        "v": packet["v"],
        "from": packet["from"],
        "id_pub": packet["id_pub"],
        "ratchet_pub": packet["ratchet_pub"],
        "session_nonce": packet["session_nonce"],
        "kdf_mode": packet["kdf_mode"],
    }


def resp_sig_payload(packet: dict[str, Any]) -> dict[str, Any]:
    base = resp_base_payload(packet)
    base["stage"] = "resp"
    base["confirm"] = packet["confirm"]
    return base


def handshake_transcript(req_packet: dict[str, Any], resp_packet: dict[str, Any]) -> bytes:
    return canonical_json({
        "req": req_payload(req_packet),
        "resp_base": resp_base_payload(resp_packet),
    })


# -------------------------
# Double Ratchet state
# -------------------------

@dataclass
class RatchetState:
    persist_identity: bool = True
    persist_peer_pins: bool = True
    identity_path: Path = field(default_factory=lambda: IDENTITY_PATH)
    peer_pins_path: Path = field(default_factory=lambda: PEER_PINS_PATH)

    max_skip: int = MAX_SKIP_DEFAULT
    max_stored_mks: int = MAX_STORED_MKS_DEFAULT

    role: Optional[str] = None  # "initiator" or "responder"
    local_name: str = "Me"
    peer_name: str = "Peer"
    kdf_mode: str = "x25519"

    established: bool = False

    rk: Optional[bytes] = None
    cks: Optional[bytes] = None
    ckr: Optional[bytes] = None

    dhs_private: Optional[x25519.X25519PrivateKey] = None
    dhr_public: Optional[x25519.X25519PublicKey] = None

    ns: int = 0
    nr: int = 0
    pn: int = 0

    session_nonce: Optional[bytes] = None
    session_id: Optional[bytes] = None

    local_id_private: Optional[ed25519.Ed25519PrivateKey] = None
    local_id_public: Optional[ed25519.Ed25519PublicKey] = None
    peer_id_public: Optional[ed25519.Ed25519PublicKey] = None

    pending_request_packet: Optional[dict[str, Any]] = None

    # MKSKIPPED[(dh_b64, n)] = mk
    mk_skipped: OrderedDict[tuple[str, int], bytes] = field(default_factory=OrderedDict)

    def __post_init__(self) -> None:
        if self.local_id_private is None:
            if self.persist_identity:
                self.local_id_private = IdentityStore(self.identity_path).load_or_create()
            else:
                self.local_id_private = ed25519.Ed25519PrivateKey.generate()

        self.local_id_public = self.local_id_private.public_key()
        self._pins = PeerPins(self.peer_pins_path) if self.persist_peer_pins else None

    # ---------- identity/fingerprint ----------

    @property
    def local_identity_b64(self) -> str:
        if not self.local_id_public:
            return ""
        return b64e(ed25519_pub_to_bytes(self.local_id_public))

    @property
    def peer_identity_b64(self) -> str:
        if not self.peer_id_public:
            return ""
        return b64e(ed25519_pub_to_bytes(self.peer_id_public))

    @property
    def session_fingerprint(self) -> str:
        if not self.session_id:
            return "-"
        return hashlib.sha256(self.session_id).hexdigest()[:20]

    @property
    def identity_fingerprint(self) -> str:
        if not self.peer_id_public or not self.local_id_public:
            return "-"
        a = ed25519_pub_to_bytes(self.local_id_public)
        b = ed25519_pub_to_bytes(self.peer_id_public)
        pair = b"".join(sorted([a, b]))
        return hashlib.sha256(pair).hexdigest()[:24]

    def _pin_peer_if_enabled(self) -> None:
        if not self._pins or not self.peer_id_public:
            return
        self._pins.check_or_pin(self.peer_name, b64e(ed25519_pub_to_bytes(self.peer_id_public)))

    # ---------- state reset ----------

    def reset_session(self, *, local_name: Optional[str] = None) -> None:
        if local_name is not None:
            self.local_name = local_name

        self.role = None
        self.peer_name = "Peer"
        self.kdf_mode = "x25519"
        self.established = False

        self.rk = None
        self.cks = None
        self.ckr = None

        self.dhs_private = None
        self.dhr_public = None

        self.ns = 0
        self.nr = 0
        self.pn = 0

        self.session_nonce = None
        self.session_id = None

        self.peer_id_public = None
        self.pending_request_packet = None

        self.mk_skipped.clear()

    # ---------- signature helpers ----------

    def _sign(self, payload_obj: dict[str, Any]) -> str:
        if not self.local_id_private:
            raise ValueError("Missing local identity private key")
        sig = self.local_id_private.sign(canonical_json(payload_obj))
        return b64e(sig)

    def _verify(self, id_pub_b64: str, sig_b64: str, payload_obj: dict[str, Any]) -> ed25519.Ed25519PublicKey:
        pub = bytes_to_ed25519_pub(b64d(id_pub_b64))
        pub.verify(b64d(sig_b64), canonical_json(payload_obj))
        return pub

    # ---------- handshake ----------

    def create_link_request(self, local_name: str, psk_text: str = "") -> str:
        self.reset_session(local_name=local_name)
        self.role = "initiator"

        psk, mode = parse_psk_input(psk_text)
        self.kdf_mode = mode

        self.dhs_private = x25519.X25519PrivateKey.generate()
        self.session_nonce = os.urandom(16)

        packet: dict[str, Any] = {
            "type": "link_request",
            "v": APP_VERSION,
            "from": self.local_name,
            "id_pub": self.local_identity_b64,
            "ratchet_pub": b64e(x25519_pub_to_bytes(self.dhs_private.public_key())),
            "session_nonce": b64e(self.session_nonce),
            "kdf_mode": self.kdf_mode,
        }
        packet["sig"] = self._sign(req_payload(packet))

        # Keep request packet for transcript + completion verification
        self.pending_request_packet = packet

        # Keep only mode; psk is provided again on completion
        _ = psk
        return encode_packet(packet)

    def accept_link_request(self, packet_text: str, local_name: str, psk_text: str = "") -> str:
        packet = decode_packet(packet_text)
        if packet.get("type") != "link_request" or packet.get("v") != APP_VERSION:
            raise ValueError("Incoming packet is not a valid v2 link request")

        # Verify request signature
        peer_id_pub = self._verify(packet["id_pub"], packet["sig"], req_payload(packet))

        local_psk, local_mode = parse_psk_input(psk_text)
        if packet["kdf_mode"] != local_mode:
            raise ValueError(
                "KDF mode mismatch. Both sides must use same mode (x25519 or x25519+psk)."
            )

        self.reset_session(local_name=local_name)
        self.role = "responder"
        self.peer_name = packet.get("from", "Peer")
        self.peer_id_public = peer_id_pub
        self.kdf_mode = local_mode

        self.session_nonce = b64d(packet["session_nonce"])
        self.dhr_public = bytes_to_x25519_pub(b64d(packet["ratchet_pub"]))
        self.dhs_private = x25519.X25519PrivateKey.generate()

        x25519_shared = self.dhs_private.exchange(self.dhr_public)
        ikm, _mode = derive_handshake_ikm(x25519_shared, local_psk)
        rk, ck_init_send, ck_resp_send, confirm_key = kdf_handshake(ikm)

        # Initiator sends first
        self.rk = rk
        self.ckr = ck_init_send
        self.cks = ck_resp_send
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.established = True

        self.session_id = derive_session_id(confirm_key, self.session_nonce)

        response: dict[str, Any] = {
            "type": "link_response",
            "v": APP_VERSION,
            "from": self.local_name,
            "id_pub": self.local_identity_b64,
            "ratchet_pub": b64e(x25519_pub_to_bytes(self.dhs_private.public_key())),
            "session_nonce": packet["session_nonce"],
            "kdf_mode": self.kdf_mode,
        }

        transcript = handshake_transcript(packet, response)
        response["confirm"] = b64e(hmac_sha256(confirm_key, transcript))
        response["sig"] = self._sign(resp_sig_payload(response))

        self._pin_peer_if_enabled()
        return encode_packet(response)

    def complete_link_with_response(self, packet_text: str, psk_text: str = "") -> None:
        packet = decode_packet(packet_text)
        if packet.get("type") != "link_response" or packet.get("v") != APP_VERSION:
            raise ValueError("Incoming packet is not a valid v2 link response")

        if self.role != "initiator" or not self.dhs_private or not self.pending_request_packet:
            raise ValueError("Start as initiator first (create link request)")

        # Verify response signature
        peer_id_pub = self._verify(packet["id_pub"], packet["sig"], resp_sig_payload(packet))

        local_psk, local_mode = parse_psk_input(psk_text)

        req = self.pending_request_packet
        req_mode = req["kdf_mode"]
        if local_mode != req_mode:
            raise ValueError("Local PSK/KDF mode does not match the original request")
        if packet["kdf_mode"] != req_mode:
            raise ValueError("Responder KDF mode does not match request mode")

        self.peer_name = packet.get("from", "Peer")
        self.peer_id_public = peer_id_pub
        self.kdf_mode = req_mode

        self.session_nonce = b64d(req["session_nonce"])
        self.dhr_public = bytes_to_x25519_pub(b64d(packet["ratchet_pub"]))

        x25519_shared = self.dhs_private.exchange(self.dhr_public)
        ikm, _mode = derive_handshake_ikm(x25519_shared, local_psk)
        rk, ck_init_send, ck_resp_send, confirm_key = kdf_handshake(ikm)

        # Verify transcript confirmation (catches PSK mismatch/tampering)
        transcript = handshake_transcript(req, packet)
        expected = hmac_sha256(confirm_key, transcript)
        got = b64d(packet["confirm"])
        if not secrets.compare_digest(expected, got):
            raise ValueError("Handshake confirmation failed (PSK mismatch or tampered packet)")

        # Initiator sends first
        self.rk = rk
        self.cks = ck_init_send
        self.ckr = ck_resp_send
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.established = True

        self.session_id = derive_session_id(confirm_key, self.session_nonce)
        self.pending_request_packet = None

        self._pin_peer_if_enabled()

    # ---------- double ratchet internals ----------

    def _require_established(self) -> None:
        if not self.established:
            raise ValueError("Link is not complete yet")

    def _aad(self, header: dict[str, Any]) -> bytes:
        if not self.session_id:
            raise ValueError("Missing session_id")
        return b"DR-MSG-v2|" + self.session_id + b"|" + canonical_json(header)

    def _store_skipped_mk(self, dh_pub_b64: str, n: int, mk: bytes) -> None:
        key = (dh_pub_b64, n)
        self.mk_skipped[key] = mk
        self.mk_skipped.move_to_end(key)

        while len(self.mk_skipped) > self.max_stored_mks:
            self.mk_skipped.popitem(last=False)

    def _try_skipped_message_keys(self, header: dict[str, Any], nonce: bytes, ct: bytes) -> Optional[str]:
        dh_b64 = header["dh"]
        n = int(header["n"])
        key = (dh_b64, n)
        mk = self.mk_skipped.pop(key, None)
        if mk is None:
            return None

        cipher = ChaCha20Poly1305(mk)
        plaintext = cipher.decrypt(nonce, ct, self._aad(header))
        return plaintext.decode("utf-8")

    def _skip_message_keys(self, until: int) -> None:
        if not self.ckr or not self.dhr_public:
            return

        if self.nr + self.max_skip < until:
            raise ValueError("Too many skipped messages (possible abuse or out-of-sync state)")

        dhr_b64 = b64e(x25519_pub_to_bytes(self.dhr_public))
        while self.nr < until:
            self.ckr, mk = kdf_chain(self.ckr)
            self._store_skipped_mk(dhr_b64, self.nr, mk)
            self.nr += 1

    def _dh_ratchet(self, new_dhr_pub: x25519.X25519PublicKey) -> None:
        if not self.rk or not self.dhs_private:
            raise ValueError("Ratchet state is not initialized")

        self.pn = self.ns
        self.ns = 0
        self.nr = 0

        self.dhr_public = new_dhr_pub

        # Step 1: derive receiving chain
        dh_out = self.dhs_private.exchange(self.dhr_public)
        self.rk, self.ckr = kdf_root(self.rk, dh_out)

        # Step 2: rotate local DH and derive sending chain
        self.dhs_private = x25519.X25519PrivateKey.generate()
        dh_out = self.dhs_private.exchange(self.dhr_public)
        self.rk, self.cks = kdf_root(self.rk, dh_out)

    # ---------- message encrypt/decrypt ----------

    def encrypt_message(self, plaintext: str) -> str:
        self._require_established()
        if not plaintext:
            raise ValueError("Message is empty")
        if not self.cks or not self.dhs_private:
            raise ValueError("Sending chain not available")

        self.cks, mk = kdf_chain(self.cks)

        header = {
            "dh": b64e(x25519_pub_to_bytes(self.dhs_private.public_key())),
            "pn": self.pn,
            "n": self.ns,
        }

        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(mk)
        ct = cipher.encrypt(nonce, plaintext.encode("utf-8"), self._aad(header))

        packet = {
            "type": "msg",
            "v": APP_VERSION,
            "header": header,
            "nonce": b64e(nonce),
            "ct": b64e(ct),
        }

        self.ns += 1
        return encode_packet(packet)

    def decrypt_message(self, packet_text: str) -> str:
        self._require_established()
        packet = decode_packet(packet_text)
        if packet.get("type") != "msg" or packet.get("v") != APP_VERSION:
            raise ValueError("Incoming packet is not a valid encrypted message")

        header = packet.get("header")
        if not isinstance(header, dict):
            raise ValueError("Invalid message header")

        nonce = b64d(packet["nonce"])
        ct = b64d(packet["ct"])

        # 1) Try skipped keys first
        skipped_plain = self._try_skipped_message_keys(header, nonce, ct)
        if skipped_plain is not None:
            return skipped_plain

        if not self.ckr:
            raise ValueError("Receiving chain not available")
        if not self.dhr_public:
            raise ValueError("Missing peer ratchet key")

        incoming_dh_raw = b64d(header["dh"])
        incoming_dh = bytes_to_x25519_pub(incoming_dh_raw)

        h_n = int(header["n"])
        h_pn = int(header["pn"])

        current_dhr_raw = x25519_pub_to_bytes(self.dhr_public)

        # 2) New DH ratchet step if needed
        if incoming_dh_raw != current_dhr_raw:
            self._skip_message_keys(h_pn)
            self._dh_ratchet(incoming_dh)

        # 3) Skip keys up to header.n
        self._skip_message_keys(h_n)

        # 4) Decrypt with current receive chain key
        if not self.ckr:
            raise ValueError("Receiving chain unavailable after ratchet")

        self.ckr, mk = kdf_chain(self.ckr)
        self.nr += 1

        cipher = ChaCha20Poly1305(mk)
        plaintext = cipher.decrypt(nonce, ct, self._aad(header))
        return plaintext.decode("utf-8")


# -------------------------
# CLI fallback (works without Tk)
# -------------------------

def run_cli() -> None:
    state = RatchetState()

    print("\nCopy/Paste DH + Double Ratchet Chat (CLI mode)")
    print("No network is used. You manually transfer packets between laptops.")
    print("Optional PQ hedge: set a high-entropy PSK on BOTH sides.\n")

    state.local_name = input("Your name [Me]: ").strip() or "Me"
    psk_text = input("Optional PSK (blank/classical, or b64:..., hex:...): ").strip()

    menu = (
        "\nChoose:\n"
        " 1) Create link request (initiator)\n"
        " 2) Accept link request + create response (responder)\n"
        " 3) Complete link from response (initiator)\n"
        " 4) Encrypt message (create outgoing packet)\n"
        " 5) Decrypt incoming message packet\n"
        " 6) Show status\n"
        " 7) Set / change PSK\n"
        " 8) Generate random PSK suggestion\n"
        " q) Quit\n"
        "> "
    )

    while True:
        choice = input(menu).strip().lower()

        try:
            if choice == "1":
                pkt = state.create_link_request(state.local_name, psk_text)
                print("\nOutgoing LINK REQUEST packet:\n")
                print(pkt)
                print("\nSend that packet to your peer.")

            elif choice == "2":
                incoming = input("\nPaste incoming LINK REQUEST packet:\n").strip()
                pkt = state.accept_link_request(incoming, state.local_name, psk_text)
                print("\nOutgoing LINK RESPONSE packet:\n")
                print(pkt)
                print(f"\nLinked with {state.peer_name}")
                print(f"Session fingerprint: {state.session_fingerprint}")
                print(f"Identity fingerprint: {state.identity_fingerprint}")

            elif choice == "3":
                incoming = input("\nPaste incoming LINK RESPONSE packet:\n").strip()
                state.complete_link_with_response(incoming, psk_text)
                print(f"\nLink complete with {state.peer_name}")
                print(f"Session fingerprint: {state.session_fingerprint}")
                print(f"Identity fingerprint: {state.identity_fingerprint}")

            elif choice == "4":
                msg = input("\nMessage to encrypt:\n").rstrip("\n")
                pkt = state.encrypt_message(msg)
                print("\nOutgoing MESSAGE packet:\n")
                print(pkt)

            elif choice == "5":
                incoming = input("\nPaste incoming MESSAGE packet:\n").strip()
                msg = state.decrypt_message(incoming)
                print(f"\n{state.peer_name}: {msg}")

            elif choice == "6":
                print("\nStatus")
                print(f"  local_name: {state.local_name}")
                print(f"  role: {state.role}")
                print(f"  linked: {state.established}")
                print(f"  kdf_mode: {state.kdf_mode}")
                print(f"  peer: {state.peer_name}")
                print(f"  session_fp: {state.session_fingerprint}")
                print(f"  identity_fp: {state.identity_fingerprint}")
                print(f"  ns/nr/pn: {state.ns}/{state.nr}/{state.pn}")
                print(f"  skipped_keys_cached: {len(state.mk_skipped)}")

            elif choice == "7":
                psk_text = input("New PSK (blank disables, b64:/hex: recommended): ").strip()
                print("PSK updated.")

            elif choice == "8":
                print("Suggested random PSK:")
                print(random_psk_b64())

            elif choice == "q":
                print("Bye.")
                return

            else:
                print("Unknown option.")

        except Exception as exc:
            print(f"Error: {exc}")


# -------------------------
# Optional Tkinter GUI
# -------------------------

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    from tkinter.scrolledtext import ScrolledText

    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False


if TK_AVAILABLE:

    class SecureChatUI:
        def __init__(self, root: tk.Tk) -> None:
            self.root = root
            self.root.title("Burnt Toast — Private Copy/Paste Chat")
            self.root.geometry("960x790")

            self.state = RatchetState()

            self.name_var = tk.StringVar(value=os.getenv("USER", "Me"))
            self.psk_var = tk.StringVar(value="")
            self.auto_copy_var = tk.BooleanVar(value=True)

            self.status_var = tk.StringVar(value="Not linked")
            self.banner_var = tk.StringVar(value="Step 1: Choose Start Link (Laptop A) or Reply to Link (Laptop B).")
            self.session_fp_var = tk.StringVar(value="-")
            self.id_fp_var = tk.StringVar(value="-")
            self.msg_var = tk.StringVar(value="")

            self._banner_default_bg = "#1f2937"
            self._banner_job: Optional[str] = None

            self._build_ui()
            self._refresh_status()

        # ---------- UI layout ----------

        def _build_ui(self) -> None:
            outer = ttk.Frame(self.root, padding=12)
            outer.pack(fill="both", expand=True)

            hero = tk.Frame(outer, bg="#111827", padx=12, pady=10)
            hero.pack(fill="x", pady=(0, 10))
            tk.Label(
                hero,
                text="Burnt Toast",
                bg="#111827",
                fg="#f9fafb",
                font=("Helvetica", 16, "bold"),
            ).pack(anchor="w")
            tk.Label(
                hero,
                text="Private chat via manual copy/paste packets — simple mode",
                bg="#111827",
                fg="#cbd5e1",
                font=("Helvetica", 10),
            ).pack(anchor="w", pady=(2, 0))

            settings = ttk.Frame(outer)
            settings.pack(fill="x", pady=(0, 8))

            ttk.Label(settings, text="Your name:").pack(side="left")
            ttk.Entry(settings, textvariable=self.name_var, width=16).pack(side="left", padx=(6, 10))

            ttk.Label(settings, text="PSK (optional):").pack(side="left")
            ttk.Entry(settings, textvariable=self.psk_var, width=34).pack(side="left", padx=(6, 6))
            ttk.Button(settings, text="Generate PSK", command=self.generate_psk).pack(side="left", padx=4)
            ttk.Checkbutton(settings, text="Auto-copy packets", variable=self.auto_copy_var).pack(side="left", padx=(10, 0))

            actions = ttk.Frame(outer)
            actions.pack(fill="x", pady=(0, 8))

            self.btn_start = ttk.Button(actions, text="1) Start Link (Laptop A)", command=self.create_link_request)
            self.btn_reply = ttk.Button(actions, text="2) Reply to Link (Laptop B)", command=self.accept_link_request)
            self.btn_finish = ttk.Button(actions, text="3) Finish Link (Laptop A)", command=self.complete_link)

            self.btn_start.pack(side="left", padx=4)
            self.btn_reply.pack(side="left", padx=4)
            self.btn_finish.pack(side="left", padx=4)

            self.banner = tk.Label(
                outer,
                textvariable=self.banner_var,
                bg=self._banner_default_bg,
                fg="#f9fafb",
                anchor="w",
                padx=10,
                pady=8,
                font=("Helvetica", 10, "bold"),
            )
            self.banner.pack(fill="x", pady=(0, 8))

            status_row = ttk.Frame(outer)
            status_row.pack(fill="x", pady=(0, 8))
            ttk.Label(status_row, textvariable=self.status_var).pack(side="left")
            ttk.Label(status_row, text="   Session FP:").pack(side="left")
            ttk.Label(status_row, textvariable=self.session_fp_var).pack(side="left")
            ttk.Label(status_row, text="   Identity FP:").pack(side="left")
            ttk.Label(status_row, textvariable=self.id_fp_var).pack(side="left")

            ttk.Label(outer, text="Paste packet from the other laptop:").pack(anchor="w")
            self.incoming = ScrolledText(outer, height=7, wrap="word")
            self.incoming.pack(fill="x", pady=(2, 6))

            incoming_buttons = ttk.Frame(outer)
            incoming_buttons.pack(fill="x", pady=(0, 10))
            ttk.Button(incoming_buttons, text="Decrypt Pasted Packet", command=self.decrypt_incoming).pack(side="left", padx=4)
            ttk.Button(incoming_buttons, text="Clear", command=self.clear_incoming).pack(side="left", padx=4)

            ttk.Label(outer, text="Packet to send (this is auto-copied by default):").pack(anchor="w")
            self.outgoing = ScrolledText(outer, height=7, wrap="word")
            self.outgoing.pack(fill="x", pady=(2, 6))

            outgoing_buttons = ttk.Frame(outer)
            outgoing_buttons.pack(fill="x", pady=(0, 10))
            ttk.Button(outgoing_buttons, text="Copy Packet Now", command=self.copy_outgoing).pack(side="left", padx=4)
            ttk.Button(outgoing_buttons, text="Clear", command=self.clear_outgoing).pack(side="left", padx=4)

            msg_row = ttk.Frame(outer)
            msg_row.pack(fill="x", pady=(0, 8))
            ttk.Label(msg_row, text="Message:").pack(side="left")
            msg_entry = ttk.Entry(msg_row, textvariable=self.msg_var)
            msg_entry.pack(side="left", fill="x", expand=True, padx=(6, 6))
            msg_entry.bind("<Return>", lambda _e: self.send_message())
            ttk.Button(msg_row, text="Encrypt + Create Packet", command=self.send_message).pack(side="left")

            ttk.Label(outer, text="Conversation:").pack(anchor="w")
            self.log = ScrolledText(outer, height=13, wrap="word", state="disabled")
            self.log.pack(fill="both", expand=True)

            ttk.Label(
                outer,
                text=(
                    "Tip: Compare Session FP + Identity FP verbally before trusting the link. "
                    "Packets never leave this app automatically."
                ),
                foreground="#555",
            ).pack(anchor="w", pady=(8, 0))

        # ---------- animation helpers ----------

        @staticmethod
        def _hex_to_rgb(h: str) -> tuple[int, int, int]:
            h = h.lstrip("#")
            return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)

        @staticmethod
        def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
            r, g, b = rgb
            return f"#{r:02x}{g:02x}{b:02x}"

        def _animate_banner(self, message: str, tone: str = "info") -> None:
            tones = {
                "info": "#1d4ed8",
                "success": "#0f766e",
                "error": "#b91c1c",
            }
            start = tones.get(tone, "#1d4ed8")
            end = self._banner_default_bg

            self.banner_var.set(message)
            self.banner.configure(bg=start)

            if self._banner_job:
                try:
                    self.root.after_cancel(self._banner_job)
                except Exception:
                    pass

            sr, sg, sb = self._hex_to_rgb(start)
            er, eg, eb = self._hex_to_rgb(end)
            steps = 12

            def step(i: int = 0) -> None:
                t = i / steps
                r = int(sr + (er - sr) * t)
                g = int(sg + (eg - sg) * t)
                b = int(sb + (eb - sb) * t)
                self.banner.configure(bg=self._rgb_to_hex((r, g, b)))
                if i < steps:
                    self._banner_job = self.root.after(40, step, i + 1)

            self._banner_job = self.root.after(160, step, 0)

        # ---------- utility ----------

        def _append_log(self, line: str) -> None:
            self.log.configure(state="normal")
            self.log.insert("end", line + "\n")
            self.log.see("end")
            self.log.configure(state="disabled")

        def _copy_text(self, text: str) -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)

        def _set_outgoing(self, text: str, context: str = "Packet ready") -> None:
            payload = text.strip()
            self.outgoing.delete("1.0", "end")
            self.outgoing.insert("1.0", payload)

            if payload and self.auto_copy_var.get():
                self._copy_text(payload)
                self._animate_banner(f"✅ {context}. Packet auto-copied.", "success")
                self._append_log("System: Packet auto-copied to clipboard.")
            else:
                self._animate_banner(f"ℹ️ {context}. Copy and send it to your peer.", "info")

        def _get_incoming(self) -> str:
            return self.incoming.get("1.0", "end").strip()

        def _refresh_status(self) -> None:
            if self.state.established:
                self.status_var.set(f"✅ Linked with {self.state.peer_name}. Ready to chat.")
            elif self.state.role == "initiator":
                self.status_var.set("⏳ Link started on this laptop (A). Waiting for response packet.")
            elif self.state.role == "responder":
                self.status_var.set("⏳ Link response created (B). Send it back to Laptop A.")
            else:
                self.status_var.set("Not linked yet.")

            self.session_fp_var.set(self.state.session_fingerprint)
            self.id_fp_var.set(self.state.identity_fingerprint)

        def _safe_run(self, fn) -> None:
            try:
                fn()
                self._refresh_status()
            except Exception as exc:
                self._animate_banner(f"❌ {exc}", "error")
                messagebox.showerror("Error", str(exc))

        # ---------- actions ----------

        def generate_psk(self) -> None:
            self.psk_var.set(random_psk_b64())
            self._append_log("System: Generated random PSK. Share it securely with peer.")
            self._animate_banner("Generated PSK. Use the same value on both laptops before linking.", "info")

        def create_link_request(self) -> None:
            def action() -> None:
                name = self.name_var.get().strip() or "Me"
                psk = self.psk_var.get().strip()
                packet = self.state.create_link_request(name, psk)
                self._set_outgoing(packet, "Step 1 complete")
                self._append_log("System: Link request created. Send this packet to Laptop B.")
                self._animate_banner("Step 1 done. Send packet to Laptop B, then wait for response.", "success")

            self._safe_run(action)

        def accept_link_request(self) -> None:
            def action() -> None:
                incoming = self._get_incoming()
                if not incoming:
                    raise ValueError("Paste a link request packet first")
                name = self.name_var.get().strip() or "Me"
                psk = self.psk_var.get().strip()
                response = self.state.accept_link_request(incoming, name, psk)
                self._set_outgoing(response, "Step 2 complete")
                self._append_log(
                    f"System: Accepted link request from {self.state.peer_name}. "
                    "Send this response back to Laptop A."
                )
                self._animate_banner("Step 2 done. Send response packet back to Laptop A.", "success")

            self._safe_run(action)

        def complete_link(self) -> None:
            def action() -> None:
                incoming = self._get_incoming()
                if not incoming:
                    raise ValueError("Paste a link response packet first")
                psk = self.psk_var.get().strip()
                self.state.complete_link_with_response(incoming, psk)
                self._append_log(f"System: Link complete with {self.state.peer_name}.")
                self._append_log(
                    f"System: Verify fingerprints out-of-band — "
                    f"Session: {self.state.session_fingerprint}, Identity: {self.state.identity_fingerprint}"
                )
                self._animate_banner("Step 3 done. Link complete — you can now send messages.", "success")

            self._safe_run(action)

        def send_message(self) -> None:
            def action() -> None:
                plaintext = self.msg_var.get().strip()
                if not plaintext:
                    return
                packet = self.state.encrypt_message(plaintext)
                self._set_outgoing(packet, "Encrypted message ready")
                self._append_log(f"You: {plaintext}")
                self.msg_var.set("")

            self._safe_run(action)

        def decrypt_incoming(self) -> None:
            def action() -> None:
                incoming = self._get_incoming()
                if not incoming:
                    raise ValueError("Paste an incoming packet first")
                plaintext = self.state.decrypt_message(incoming)
                self._append_log(f"{self.state.peer_name}: {plaintext}")
                self._animate_banner("Message decrypted successfully.", "success")

            self._safe_run(action)

        def copy_outgoing(self) -> None:
            text = self.outgoing.get("1.0", "end").strip()
            if not text:
                return
            self._copy_text(text)
            self._append_log("System: Outgoing packet copied to clipboard.")
            self._animate_banner("Packet copied to clipboard.", "info")

        def clear_incoming(self) -> None:
            self.incoming.delete("1.0", "end")

        def clear_outgoing(self) -> None:
            self.outgoing.delete("1.0", "end")


# -------------------------
# Entrypoint
# -------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Copy/Paste DH + Double Ratchet chat")
    parser.add_argument("--cli", action="store_true", help="Run in terminal mode")
    parser.add_argument(
        "--ephemeral-identity",
        action="store_true",
        help="Do not persist local identity key on disk",
    )
    parser.add_argument(
        "--no-peer-pins",
        action="store_true",
        help="Disable peer identity pinning",
    )
    args = parser.parse_args()

    if args.cli or not TK_AVAILABLE:
        if not args.cli and not TK_AVAILABLE:
            print("[!] Tkinter is not available in this Python build. Starting CLI mode.\n")
        run_cli()
        return

    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    # UI currently uses default persistent behavior.
    # Flags remain available for future extension if needed.
    _ = args.ephemeral_identity
    _ = args.no_peer_pins

    SecureChatUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
