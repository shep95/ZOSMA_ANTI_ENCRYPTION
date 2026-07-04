# AES-256-GCM — foundational limits theory

Under **flawless** AES-256-GCM (no implementation bugs, no side-channels, pristine host, no known classical/quantum break of the cipher), reading ciphertext **without the key** is impossible under **current** mathematics and physics.

The only “bypasses” in this narrative are **paradigm shifts**, not engineering attacks:

| Vector | Without breakthrough | With hypothetical oracle |
| --- | --- | --- |
| Unknown math weakness | Blocked | Simulated inverse recovers P |
| P=NP / complexity shift | Blocked | Simulated poly inverter recovers P |
| Deterministic universe / Laplace | Blocked | Simulated entropy omniscience recovers P |
| Temporal manipulation | Blocked | Simulated timeline rewrite recovers P |

```bash
npm run gcm-foundational
```

**Claim A:** no leaks + current physics ⇒ cannot read.  
**Claim B:** only granted breakthrough oracles change that (they are not real cryptanalysis).
