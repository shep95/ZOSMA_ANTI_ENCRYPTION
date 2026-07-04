/** Greatest common divisor (Euclidean algorithm). */
export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a;
}

/** Modular exponentiation: base^exp mod modulus. */
export function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = ((base % modulus) + modulus) % modulus;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exp /= 2n;
    base = (base * base) % modulus;
  }
  return result;
}

/** Modular multiplicative inverse via extended Euclidean algorithm. */
export function modInverse(a: bigint, m: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = ((a % m) + m) % m;

  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }

  if (r > 1n) {
    throw new Error(`${a} has no inverse modulo ${m}`);
  }
  if (t < 0n) t += m;
  return t;
}

export function isPrime(n: bigint): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) return false;
  }
  return true;
}

/** Inclusive random bigint in [min, max] via rejection sampling (unbiased). */
export function randomBigInt(min: bigint, max: bigint): bigint {
  if (max < min) throw new Error("max must be >= min");
  const range = max - min + 1n;
  const bits = range.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  const limit = 1n << BigInt(bytes * 8);

  for (;;) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    let value = 0n;
    for (const b of buf) value = (value << 8n) | BigInt(b);
    // Reject values in the biased tail of the byte range.
    if (value >= limit - (limit % range)) continue;
    return min + (value % range);
  }
}

export function randomInt(min: number, max: number): number {
  return Number(randomBigInt(BigInt(min), BigInt(max)));
}
