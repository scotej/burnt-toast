# Hardened Copy/Paste Chat (Diffie-Hellman + Double Ratchet)

This app is a **manual copy/paste encrypted chat** for two laptops.

- No sockets, no server, no auto-transport
- You copy packets from one device and paste to the other

## Crypto used

- **Diffie-Hellman:** X25519
- **Ratchet:** Double Ratchet state machine (spec-aligned core)
  - RK / CKs / CKr
  - DH ratchet steps
  - `Ns`, `Nr`, `PN`
  - skipped-message-key cache (`MKSKIPPED`) for out-of-order delivery
- **Encryption:** ChaCha20-Poly1305
- **KDFs:** HKDF-SHA256 + HMAC-SHA256
- **Handshake integrity:** Ed25519 signatures + transcript confirmation MAC

## Post-quantum hedge mode

There is an optional **hybrid PSK mode**: `x25519+psk`.

If both sides use the same high-entropy PSK (shared out-of-band), the handshake secret mixes:

- X25519 shared secret, and
- PSK material

This helps hedge against "store-now-decrypt-later" risk if classical DH is broken in the future.

> Use a strong random PSK (32 bytes recommended), e.g. `b64:<...>`.

## Files

- `dh_double_ratchet_chat.py`
- `dh_double_ratchet_chat_requirements.txt`

## Install (both laptops)

```bash
python3 -m pip install -r dh_double_ratchet_chat_requirements.txt
```

## Run

GUI mode (if Tkinter is available):
```bash
python3 dh_double_ratchet_chat.py
```

CLI mode:
```bash
python3 dh_double_ratchet_chat.py --cli
```

---

## Link setup flow

### Laptop A (initiator)
1. (Optional) set PSK
2. Click **Create Link Request (Initiator)**
3. Copy outgoing packet to Laptop B

### Laptop B (responder)
1. Use same PSK mode/value (if enabled)
2. Paste request packet in **Incoming**
3. Click **Accept Link Request + Respond**
4. Copy response packet to Laptop A

### Laptop A
1. Paste response packet in **Incoming**
2. Click **Complete Link from Response**

Now compare fingerprints out-of-band:
- Session FP
- Identity FP

---

## Sending messages

1. Type plaintext in **Message**
2. Click **Encrypt + Create Outgoing Packet**
3. Copy packet and send to peer
4. Peer pastes and decrypts

---

## Security notes

- This is strong crypto, but still app-level code (not an audited production messenger).
- If peer identity pinning reports mismatch, treat it as serious.
- Keep local machine secure (disk encryption, account security, updates).
