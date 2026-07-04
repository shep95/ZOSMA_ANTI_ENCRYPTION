# ZOSMA Anti-Encryption

**Educational cryptanalysis lab** — break toy RSA by factoring the public modulus with Shor’s algorithm.

> Teaching demo only. Classical period finding on small moduli. Not a weapon against real-world RSA.

[![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/license-see%20LICENSE-blue)](./LICENSE)
[![Status](https://img.shields.io/badge/status-runnable-success)](#quickstart)

---

## Why this exists

RSA’s public key exposes `N = p × q`. If you can factor `N`, you can rebuild the private exponent and read ciphertext that was never meant for you.

This repo turns that idea into a **runnable TypeScript workflow**: generate a toy lock, encrypt a message, factor `N` with Shor’s control flow, recover `d`, and decrypt — without the original private key.

Full story: [NARRATIVE.md](./NARRATIVE.md)

---

## Architecture

```mermaid
flowchart TB
  subgraph CLI["CLI Surface"]
    DEMO["npm run demo<br/>end-to-end crack"]
    FACTOR["npm run factor<br/>factor N only"]
  end

  subgraph Core["Core Modules"]
    RSA["rsa.ts<br/>keygen · encrypt · decrypt"]
    SHOR["shor.ts<br/>period find · factor"]
    MATH["math.ts<br/>gcd · modPow · modInverse"]
  end

  DEMO --> RSA
  DEMO --> SHOR
  FACTOR --> SHOR
  RSA --> MATH
  SHOR --> MATH
```

| Module | Responsibility |
| --- | --- |
| `src/rsa.ts` | Toy RSA keypair, encrypt, decrypt, recover `d` from factors |
| `src/shor.ts` | Shor factoring loop + classical period finding |
| `src/math.ts` | BigInt arithmetic primitives |
| `src/index.ts` | Full attack demo CLI |
| `src/factor.ts` | Standalone factorizer CLI |

---

## Attack workflow

End-to-end path implemented by `npm run demo`:

```mermaid
sequenceDiagram
  participant U as Operator
  participant RSA as RSA Module
  participant SHOR as Shor Module
  participant CT as Ciphertext

  U->>RSA: generateKeypair(bitLength)
  RSA-->>U: public (e, N), private (d, N)

  U->>RSA: encrypt(message, public)
  RSA-->>CT: ciphertext[]

  U->>RSA: decrypt(ciphertext, private)
  RSA-->>U: plaintext (sanity check)

  U->>SHOR: shorsBreaker(N)
  Note over SHOR: pick a → find period r<br/>gcd(a^(r/2) ± 1, N)
  SHOR-->>U: factors (p, q)

  U->>RSA: recoverPrivateKey(public, p, q)
  RSA-->>U: forged (d′, N)

  U->>RSA: decrypt(ciphertext, forged)
  RSA-->>U: cracked plaintext
```

### Shor factoring loop

```mermaid
flowchart TD
  A([Start with N]) --> B[Pick random base a]
  B --> C{gcd(a, N) = 1?}
  C -->|No| D[Return factors from gcd]
  C -->|Yes| E[Find period r of a mod N]
  E --> F{r even and<br/>a^(r/2) ≢ −1 mod N?}
  F -->|No| B
  F -->|Yes| G["p = gcd(a^(r/2)+1, N)<br/>q = gcd(a^(r/2)−1, N)"]
  G --> H{Nontrivial factors?}
  H -->|No| B
  H -->|Yes| I([Return p, q])
  D --> I
```

On a large quantum computer, **period finding** is the quantum step. Here it runs **classically** so the lab works on any laptop — same control flow, educational moduli only.

---

## Quickstart

```bash
git clone https://github.com/shep95/ZOSMA_ANTI_ENCRYPTION.git
cd ZOSMA_ANTI_ENCRYPTION
npm install
npm run demo
```

Expected shape of output:

```text
=== Act 1: Build a small RSA lock ===
Primes p, q: …
Public key  (e, N): …

=== Act 2: Lock a message ===
Encrypted message: …
Decrypted with real private key: 7enTropy7

=== Act 3: Factor N with Shor's procedure ===
Factored N=… into (p, q)

=== Act 4: Forge private key and read the message ===
Message cracked using Shor's algorithm: 7enTropy7

Success: ciphertext recovered without the original private key.
```

---

## Commands

| Command | What it does |
| --- | --- |
| `npm run demo` | Full RSA generate → encrypt → factor → crack |
| `npm start -- -b 10 -m "secret"` | Custom bit length and message |
| `npm run factor -- 21` | Factor a single integer (e.g. `21 → 3 × 7`) |
| `npm run build` | Emit `dist/` via `tsc` |

### CLI options (`npm start`)

| Flag | Description | Default |
| --- | --- | --- |
| `-b`, `--bit-length` | Modulus size in bits (4–24) | `8` |
| `-m`, `--message` | Plaintext to encrypt and crack | `7enTropy7` |
| `-h`, `--help` | Show help | — |

---

## Developer workflow

```mermaid
flowchart LR
  A[Clone] --> B[npm install]
  B --> C{Goal?}
  C -->|Learn the attack| D[npm run demo]
  C -->|Factor only| E[npm run factor -- N]
  C -->|Ship JS| F[npm run build]
  F --> G[node dist/index.js …]
  D --> H[Read NARRATIVE.md]
  E --> H
```

```bash
# interactive-style run
npm start -- --bit-length 12 --message "hello"

# compile + run artifacts
npm run build
node dist/index.js --bit-length 8 --message "7enTropy7"
```

---

## Threat model (lab scope)

```mermaid
flowchart LR
  subgraph Public["Attacker can see"]
    PK["Public key (e, N)"]
    CT["Ciphertext"]
  end

  subgraph Secret["Attacker must not need"]
    SK["Original private key (d, N)"]
  end

  subgraph Recovered["Attacker recovers"]
    PQ["Factors p, q"]
    DK["Forged d"]
    PT["Plaintext"]
  end

  PK --> PQ
  PQ --> DK
  DK --> PT
  CT --> PT
  SK -.->|bypassed| PT
```

| In scope | Out of scope |
| --- | --- |
| Toy RSA (≈8–16 bit moduli) | Production RSA / TLS / real keys |
| Classical period finding | Real quantum hardware |
| Character-wise educational cipher | Padding, OAEP, hybrid encryption |

---

## Project layout

```text
ZOSMA_ANTI_ENCRYPTION/
├── NARRATIVE.md          # Story distilled from the original notebooks
├── src/
│   ├── index.ts          # End-to-end crack demo
│   ├── factor.ts         # Standalone factorizer
│   ├── rsa.ts            # Toy RSA
│   ├── shor.ts           # Shor factoring
│   └── math.ts           # BigInt helpers
├── Breaking_RSA.ipynb    # Original notebook (reference)
├── Factorizer_Quantum_Simulator.ipynb
└── RSA_module.py         # Original Python RSA (reference)
```

---

## Requirements

- **Node.js** 18+
- **npm** 9+

---

## License & security

See [LICENSE](./LICENSE) and [SECURITY.md](./SECURITY.md).

This repository is for **cryptography education and post-quantum awareness**. Do not use it against systems you do not own or lack permission to test.
