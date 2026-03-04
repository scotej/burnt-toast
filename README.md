# Burnt Toast — Private Copy/Paste Chat

This app lets two laptops send private messages using strong encryption, with **no server** and **no automatic network connection**.

You manually copy a packet from one laptop and paste it into the other.

---

## 1) Simple guide (non-technical)

If you just want it to work, follow this section.

### What you need
- Two laptops
- Python 3 on both
- Both people can copy/paste text between devices (Signal/WhatsApp/email/USB/etc.)

### Install (both laptops)
1. Open Terminal
2. Go into this project folder
3. Run:

```bash
python3 -m pip install -r dh_double_ratchet_chat_requirements.txt
python3 dh_double_ratchet_chat.py
```

> If window mode does not open, use:
>
> ```bash
> python3 dh_double_ratchet_chat.py --cli
> ```

### First-time link setup

#### Laptop A
1. Enter your name.
2. (Optional) Set a PSK (extra security phrase/key).
3. Click **Create Link Request (Initiator)**.
4. Copy the outgoing packet and send it to Laptop B.

#### Laptop B
1. Enter your name.
2. Use the **same PSK** if you are using one.
3. Paste A's packet into **Incoming**.
4. Click **Accept Link Request + Respond**.
5. Copy the outgoing packet and send it back to Laptop A.

#### Laptop A
1. Paste B's response into **Incoming**.
2. Click **Complete Link from Response**.

Now both sides are linked.

### Send messages
1. Type a message.
2. Click **Encrypt + Create Outgoing Packet**.
3. Copy packet and send it to the other person.
4. Other person pastes into **Incoming** and decrypts.

### Safety checklist
- Compare **Session FP** and **Identity FP** verbally or in person.
- If identity mismatch appears, stop and verify.
- Keep your laptop secure (password, updates, disk encryption).

---

## 2) Technical explanation

This project implements a hardened, manual-transport secure messenger prototype.

## Protocol overview

### Transport
- Out-of-band, manual copy/paste packet transfer.
- No socket listener or server in this app.

### Handshake
- X25519 ephemeral key agreement.
- Ed25519 identity signatures on handshake payloads.
- Transcript confirmation MAC to detect tampering and PSK mismatch.
- Optional identity pinning (`~/.copyratchet_peer_pins_v1.json`).
- Local identity persistence (`~/.copyratchet_identity_v1.json`) unless disabled.

### Ratchet core
- Signal-style Double Ratchet core state:
  - `RK` (root key)
  - `CKs` / `CKr` (send/recv chain keys)
  - `Ns`, `Nr`, `PN` counters
- DH ratchet when remote DH public key changes.
- Symmetric ratchet per message (`KDF_CK`).
- Skipped-key cache (`MKSKIPPED`) for out-of-order delivery with limits.

### Message encryption
- AEAD: ChaCha20-Poly1305
- AAD includes session binding + canonical header encoding
- Header fields: `dh`, `pn`, `n`

### KDFs
- HKDF-SHA256 for root/handshake derivations
- HMAC-SHA256 for chain key progression

### Post-quantum hedge mode
- Optional mode: `x25519+psk`
- Handshake secret mixes X25519 shared secret + high-entropy PSK.
- This is a hedge against store-now/decrypt-later risk, assuming PSK is high quality and exchanged securely.

> Note: This is **not** a formal PQ KEM integration (e.g., ML-KEM/Kyber) yet.

## Current limitations
- No full production hardening/audit.
- No full persistent conversation state snapshots/recovery workflow.
- Not a complete Signal protocol reimplementation.

## Files
- `dh_double_ratchet_chat.py` — GUI + CLI app
- `dh_double_ratchet_chat_requirements.txt` — dependencies
- `dh_double_ratchet_chat_README.md` — additional notes

---

If you want, next step can be adding:
- packaged desktop app build
- export/import encrypted session state
- true PQ KEM hybrid handshake
