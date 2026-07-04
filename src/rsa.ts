import { gcd, modInverse, modPow, randomBigInt } from "./math.js";

export type PublicKey = { e: bigint; n: bigint };
export type PrivateKey = { d: bigint; n: bigint };
export type KeyPair = { publicKey: PublicKey; privateKey: PrivateKey; p: bigint; q: bigint };

/**
 * Live-hardware RSA moduli. Order-finding circuits for these N fit current IBM QPUs.
 * See https://quantum.cloud.ibm.com/docs/tutorials/shors-algorithm
 */
export const LIVE_RSA_MODULI = [
  { p: 3n, q: 5n, n: 15n },
  { p: 3n, q: 7n, n: 21n },
] as const;

/** Build a real RSA keypair from secret primes (key holder only). */
export function generateKeypairFromPrimes(p: bigint, q: bigint): KeyPair {
  if (p === q) throw new Error("p and q must be distinct");
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);

  // Prefer e=3 when valid (common RSA public exponent); fall back to a random unit.
  let e = 3n;
  if (gcd(e, phi) !== 1n) {
    e = 0n;
    for (let attempt = 0; attempt < 10_000; attempt++) {
      const candidate = randomBigInt(3n, phi - 1n);
      if (candidate % 2n === 0n) continue;
      if (gcd(candidate, phi) === 1n) {
        e = candidate;
        break;
      }
    }
  }
  if (e === 0n) {
    throw new Error("Failed to choose public exponent");
  }
  const d = modInverse(e, phi);

  return {
    publicKey: { e, n },
    privateKey: { d, n },
    p,
    q,
  };
}

/** Default live demo keypair: N=15 (IBM Quantum Shor tutorial target). */
export function generateLiveKeypair(modulus: 15 | 21 = 15): KeyPair {
  const entry = LIVE_RSA_MODULI.find((m) => m.n === BigInt(modulus));
  if (!entry) throw new Error(`Unsupported live modulus ${modulus}`);
  return generateKeypairFromPrimes(entry.p, entry.q);
}

/**
 * Encode any UTF-8 message as base-N digits in 0..N-1 so RSA works for tiny live moduli.
 */
export function encodeMessage(message: string, n: bigint): bigint[] {
  if (n < 2n) throw new Error("n must be >= 2");
  const bytes = new TextEncoder().encode(message);
  const digits: bigint[] = [];

  for (const byte of bytes) {
    let value = BigInt(byte);
    // 256 needs ceil(log_n(256)) digits; for n=15 that is 3 digits.
    const digitCount = digitsPerByte(n);
    for (let i = 0; i < digitCount; i++) {
      digits.push(value % n);
      value /= n;
    }
    if (value !== 0n) {
      throw new Error(`Byte ${byte} does not fit in ${digitCount} base-${n} digits`);
    }
  }

  return digits;
}

export function decodeMessage(digits: bigint[], n: bigint): string {
  const digitCount = digitsPerByte(n);
  if (digits.length % digitCount !== 0) {
    throw new Error("Digit stream length is not a multiple of digits-per-byte");
  }

  const bytes = new Uint8Array(digits.length / digitCount);
  for (let i = 0; i < bytes.length; i++) {
    let value = 0n;
    let place = 1n;
    for (let j = 0; j < digitCount; j++) {
      const digit = digits[i * digitCount + j]!;
      if (digit < 0n || digit >= n) {
        throw new Error(`Invalid digit ${digit} for modulus ${n}`);
      }
      value += digit * place;
      place *= n;
    }
    if (value > 255n) throw new Error(`Decoded byte out of range: ${value}`);
    bytes[i] = Number(value);
  }

  return new TextDecoder().decode(bytes);
}

const digitsPerByteCache = new Map<string, number>();

function digitsPerByte(n: bigint): number {
  const key = n.toString();
  const cached = digitsPerByteCache.get(key);
  if (cached != null) return cached;

  let capacity = 1n;
  let count = 0;
  // Bound loop: n>=2 ⇒ count ≤ 8 for byte encoding.
  while (capacity < 256n) {
    capacity *= n;
    count += 1;
    if (count > 64) throw new Error(`digitsPerByte diverged for n=${n}`);
  }
  digitsPerByteCache.set(key, count);
  return count;
}

/** Encrypt base-N message digits with public key (real modular exponentiation). */
export function encryptDigits(digits: bigint[], publicKey: PublicKey): bigint[] {
  const { e, n } = publicKey;
  return digits.map((m) => {
    if (m < 0n || m >= n) {
      throw new Error(`Plaintext digit ${m} out of range for modulus ${n}`);
    }
    return modPow(m, e, n);
  });
}

/** Decrypt ciphertext digits with private key. */
export function decryptDigits(ciphertext: bigint[], privateKey: PrivateKey): bigint[] {
  const { d, n } = privateKey;
  return ciphertext.map((c) => modPow(c, d, n));
}

export function encryptMessage(message: string, publicKey: PublicKey): bigint[] {
  return encryptDigits(encodeMessage(message, publicKey.n), publicKey);
}

export function decryptMessage(ciphertext: bigint[], privateKey: PrivateKey): string {
  return decodeMessage(decryptDigits(ciphertext, privateKey), privateKey.n);
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
