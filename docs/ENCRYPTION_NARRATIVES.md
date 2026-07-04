# Encryption levels of the world — security narratives

This catalog covers **encryption classes and assurance levels** used in real systems. “Every scheme ever published” is infinite; this is the complete **operational map** defenders and attackers actually reason about: classical → modern → post-quantum → quantum-threatened.

Each entry is a **security narrative**: what is promised, and the workflow that must hold for the promise to be true.

---

## Layer 0 — Pre-modern / classical

### 0.1 Substitution & transposition (Caesar, Vigenère, Playfair, columnar)

**Promise:** Obscurity of letters.

**Workflow:** Alphabet map or key schedule → transform plaintext symbols → ciphertext.

**Breaks when:** Frequency analysis, known plaintext, key reuse, small keyspace.

### 0.2 Rotor machines (Enigma-class)

**Promise:** Poly-alphabetic confusion via daily settings.

**Workflow:** Plugboard → rotors → reflector → reverse path.

**Breaks when:** Operational mistakes (cribs, repeated indicators), mathematical structure of the machine.

---

## Layer 1 — Information-theoretic

### 1.1 One-time pad (OTP)

**Promise:** Perfect secrecy if key is truly random, as long as message, never reused.

**Workflow:** `c = m ⊕ k` with `|k| ≥ |m|`, single use, secure key distribution.

**Breaks when:** Key reuse, weak RNG, key exfiltration, implementation that “pads” with a stream cipher and calls it OTP.

---

## Layer 2 — Symmetric encryption

### 2.1 Block ciphers (AES-128/192/256, legacy DES/3DES, Blowfish, Twofish)

**Promise:** Pseudorandom permutation under a secret key.

**Workflow:** Key schedule → rounds (SubBytes/ShiftRows/MixColumns/AddRoundKey for AES) → ciphertext block.

**Modes (sub-levels):**

| Mode | Narrative workflow | Integrity? |
| --- | --- | --- |
| ECB | Independent blocks | No — pattern leakage |
| CBC | IV ⊕ block chain | No — padding oracles if misused |
| CTR | Keystream from counter | No — malleable |
| CFB/OFB | Stream-like from block cipher | No |

**Breaks when:** ECB for structured data, IV reuse (CBC/CTR/GCM), padding oracles, related-key attacks on weak ciphers, DES 56-bit brute force.

### 2.2 Stream ciphers (ChaCha20, legacy RC4)

**Promise:** Keystream ⊕ plaintext.

**Workflow:** Key + nonce → keystream generator → XOR.

**Breaks when:** Nonce reuse (catastrophic for ChaCha20/AES-CTR), RC4 biases.

### 2.3 AEAD (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, AES-CCM)

**Promise:** Confidentiality **and** authenticity of ciphertext + AAD.

**Workflow:** Encrypt → tag; decrypt verifies tag before releasing plaintext.

**Breaks when:** Nonce reuse (GCM), truncated tags, releasing plaintext before tag check, “encrypt-then-MAC” inverted to MAC-then-encrypt incorrectly, weak IV generation.

---

## Layer 3 — Hashing & integrity (not encryption, but in every crypto workflow)

### 3.1 Unkeyed hashes (SHA-256/512, SHA-3, BLAKE2/3; broken: MD5, SHA-1)

**Promise:** Collision / preimage resistance (algorithm-dependent).

**Workflow:** Absorb message → compress → digest.

**Breaks when:** Used for passwords, used for integrity without a key, MD5/SHA-1 collisions.

### 3.2 MACs (HMAC-SHA256, KMAC, Poly1305 as part of AEAD)

**Promise:** Integrity + authenticity under a shared key.

**Workflow:** Keyed hash construction → tag.

**Breaks when:** Timing leaks on tag compare, key = password without KDF, truncated verify.

### 3.3 KDFs (HKDF, PBKDF2, scrypt, **argon2id**, bcrypt)

**Promise:** Derive strong keys from secrets / passwords.

**Workflow:** Input keying material + salt + params → output key.

**Breaks when:** No salt, low iteration/memory params, PBKDF2 where argon2id is required, salt reuse across users without domain separation.

---

## Layer 4 — Asymmetric encryption & key encapsulation

### 4.1 RSA encryption (PKCS#1 v1.5, RSA-OAEP)

**Promise:** Anyone with `e, N` can seal; only `d` (or factors of `N`) can open.

**Workflow:** Pad plaintext → `c = m^e mod N` → decrypt `m = c^d mod N`.

**Breaks when:** No padding (textbook RSA), Bleichenbacher on v1.5, small `e` + small `m`, **factoring `N` (classical or Shor)**, side channels, modulus reuse with shared primes.

### 4.2 ElGamal / ECIES-style

**Promise:** Discrete-log hardness.

**Workflow:** Ephemeral key → shared secret → symmetric seal (usually hybrid).

**Breaks when:** Reused ephemeral keys, weak curves, invalid curve attacks, bad KDF into symmetric key.

### 4.3 Post-quantum KEMs (ML-KEM/Kyber, Classic McEliece, HQC, …)

**Promise:** IND-CCA security against quantum adversaries (design goal).

**Workflow:** `KeyGen` → `Encaps(pk) → (ct, ss)` → `Decaps(sk, ct) → ss` → use `ss` in AEAD.

**Breaks when:** Implementation bugs, side channels, hybrid not used during migration, binding failures between KEM and AEAD transcript.

---

## Layer 5 — Signatures & identity

### 5.1 Classical signatures (RSA-PSS, ECDSA, Ed25519)

**Promise:** Unforgeability under chosen message attack.

**Workflow:** Hash message → sign with `sk` → verify with `pk`.

**Breaks when:** Nonce reuse in ECDSA (private key leak), IEEE P1363 vs DER malleability, missing `aud`/`iss` binding at application layer, **Shor breaks ECDSA/RSA** on large quantum computers.

### 5.2 Post-quantum signatures (ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon)

**Promise:** Existential unforgeability post-quantum.

**Workflow:** Same sign/verify API; larger keys/signatures.

**Breaks when:** Fault attacks, incorrect parameter sets, hybrid verification not enforced.

---

## Layer 6 — Key exchange & session security

### 6.1 Diffie–Hellman / ECDH

**Promise:** Shared secret over insecure channel (passive adversary).

**Workflow:** Ephemeral keys → shared secret → KDF → session keys.

**Breaks when:** Static-static without authentication (MITM), small subgroup, invalid points, **Shor on DL**.

### 6.2 Authenticated KE (TLS 1.2/1.3, Noise, Signal Double Ratchet)

**Promise:** Confidentiality, integrity, forward secrecy, auth (profile-dependent).

**Workflow:** Handshake (certs/PQ hybrid) → traffic keys → AEAD records → rekey/ratchet.

**Breaks when:** Cert validation skipped, old TLS versions, compression oracles (CRIME/BREACH class), session ticket key longevity, downgrade, implementation taxonomy flaws (see companion doc).

---

## Layer 7 — Password & token layers (application crypto)

### 7.1 Password storage

**Promise:** Offline cracking is expensive.

**Workflow:** argon2id(password, salt, params) → store hash; verify constant-time.

**Breaks when:** Plaintext, MD5/SHA1, unsalted, fast hashes, user enumeration via timing.

### 7.2 JWTs / bearer tokens

**Promise:** Stateless auth assertions.

**Workflow:** Header.payload.signature; verify `alg`, `aud`, `iss`, `exp`, signature.

**Breaks when:** `alg=none`, HS256 with public key confusion, missing `aud`/`iss`/`exp`, long-lived tokens, secrets in client.

---

## Layer 8 — Assurance / “levels” (policy, not algorithms)

These are **evaluation levels**, not ciphers:

| Level family | Narrative |
| --- | --- |
| **FIPS 140-3** modules | Cryptographic module validation (roles, key entry, physical) |
| **Common Criteria EAL** | Assurance of development/process, not “unbreakable crypto” |
| **CNSA 2.0 / NIST PQC** | Algorithm allow-lists for national systems |
| **PCI / HIPAA technical** | Controls around crypto use, key management, access |

**Breaks when:** Checkbox compliance without correct mode/nonce/key lifecycle; validated module used incorrectly by the app.

---

## Layer 9 — Quantum threat model (meta-level)

| Adversary | Breaks |
| --- | --- |
| **Grover** | Quadratic speedup on brute force → prefer AES-256, larger hashes |
| **Shor** | Polynomial factoring & DL → RSA, DH, ECDSA, ECDH collapse |
| **Harvest-now-decrypt-later** | Today’s RSA/TLS transcripts decrypted later |

**ZOSMA’s live Shor path** sits here: it demonstrates the **Shor narrative** against **toy RSA**, not AES or AES-GCM.

---

## Universal crypto workflow (all modern systems)

```text
entropy → key hierarchy (KDF) → algorithm + parameters
     → AEAD or KEM+AEAD (hybrid)
     → identity binding (certs/signatures/PQ)
     → rotation + destruction
     → monitoring
```

Any broken step collapses the narrative even if the algorithm name is “AES-256-GCM”.
