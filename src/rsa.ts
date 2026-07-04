import { gcd, isPrime, modInverse, modPow, randomBigInt } from "./math.js";

export type PublicKey = { e: bigint; n: bigint };
export type PrivateKey = { d: bigint; n: bigint };
export type KeyPair = { publicKey: PublicKey; privateKey: PrivateKey; p: bigint; q: bigint };

function primesInRange(start: bigint, stop: bigint): bigint[] {
  const primes: bigint[] = [];
  for (let i = start; i <= stop; i++) {
    if (isPrime(i)) primes.push(i);
  }
  return primes;
}

/**
 * Generate a toy RSA keypair for a modulus of about `bitLength` bits.
 * Educational sizes only (e.g. 8–16 bits).
 */
export function generateKeypair(bitLength: number): KeyPair {
  if (bitLength < 4 || bitLength > 24) {
    throw new Error("bitLength must be between 4 and 24 for this educational demo");
  }

  const nMin = 1n << BigInt(bitLength - 1);
  const nMax = (1n << BigInt(bitLength)) - 1n;
  const half = Math.max(2, Math.floor(bitLength / 2));
  const start = 1n << BigInt(Math.max(1, half - 1));
  const stop = 1n << BigInt(half + 1);

  const primes = primesInRange(start < 3n ? 3n : start, stop);
  if (primes.length < 2) {
    throw new Error(`Not enough primes for bit length ${bitLength}`);
  }

  let p = 0n;
  let q = 0n;
  const candidates = [...primes];

  while (candidates.length > 0) {
    const idx = Number(randomBigInt(0n, BigInt(candidates.length - 1)));
    p = candidates[idx]!;
    candidates.splice(idx, 1);

    const qValues = primes.filter((candidate) => {
      if (candidate === p) return false;
      const n = p * candidate;
      return n >= nMin && n <= nMax;
    });

    if (qValues.length > 0) {
      q = qValues[Number(randomBigInt(0n, BigInt(qValues.length - 1)))]!;
      break;
    }
  }

  if (p === 0n || q === 0n) {
    throw new Error(`Could not find suitable primes for bit length ${bitLength}`);
  }

  const n = p * q;
  const phi = (p - 1n) * (q - 1n);

  let e = 0n;
  let d = 0n;
  for (let attempt = 0; attempt < 10_000; attempt++) {
    e = randomBigInt(3n, phi - 1n);
    if (e % 2n === 0n) continue;
    if (gcd(e, phi) !== 1n) continue;
    d = modInverse(e, phi);
    if (e !== d) break;
  }

  if (e === 0n || d === 0n) {
    throw new Error("Failed to choose public/private exponents");
  }

  return {
    publicKey: { e, n },
    privateKey: { d, n },
    p,
    q,
  };
}

/** Encrypt each character as codePoint^e mod n. */
export function encrypt(plaintext: string, publicKey: PublicKey): bigint[] {
  const { e, n } = publicKey;
  return [...plaintext].map((ch) => {
    const code = BigInt(ch.codePointAt(0)!);
    if (code >= n) {
      throw new Error(
        `Character code ${code} >= modulus ${n}; use a larger bit length or a simpler message`,
      );
    }
    return modPow(code, e, n);
  });
}

/** Decrypt ciphertext numbers with private key (d, n). */
export function decrypt(ciphertext: bigint[], privateKey: PrivateKey): string {
  const { d, n } = privateKey;
  return ciphertext
    .map((c) => String.fromCodePoint(Number(modPow(c, d, n))))
    .join("");
}

/** Recover private exponent from public e and factors of n. */
export function recoverPrivateKey(publicKey: PublicKey, p: bigint, q: bigint): PrivateKey {
  if (p * q !== publicKey.n) {
    throw new Error("Factors do not multiply to N");
  }
  const phi = (p - 1n) * (q - 1n);
  const d = modInverse(publicKey.e, phi);
  return { d, n: publicKey.n };
}

export function formatCiphertext(ciphertext: bigint[]): string {
  return ciphertext.map(String).join(" ");
}
