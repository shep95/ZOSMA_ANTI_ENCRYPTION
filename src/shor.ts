import { gcd, modPow, randomBigInt } from "./math.js";

export type Factors = { p: bigint; q: bigint };

/**
 * Classical period finding for f(x) = a^x mod n.
 * Returns the smallest positive r such that a^r ≡ 1 (mod n).
 *
 * On a quantum computer this is Shor's period-finding subroutine.
 * For educational moduli we compute the order classically.
 */
export function findPeriod(a: bigint, n: bigint): bigint {
  if (gcd(a, n) !== 1n) {
    throw new Error("a and n must be coprime to have an order modulo n");
  }

  let value = 1n;
  for (let r = 1n; r <= n; r++) {
    value = (value * a) % n;
    if (value === 1n) return r;
  }

  throw new Error(`No period found for a=${a}, n=${n}`);
}

/**
 * Factor n using Shor's classical control flow:
 * random base → period → gcd(a^(r/2) ± 1, n).
 */
export function shorsBreaker(n: bigint, maxAttempts = 10_000): Factors {
  if (n <= 1n) throw new Error("n must be > 1");
  if (n % 2n === 0n) return { p: 2n, q: n / 2n };

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const a = randomBigInt(2n, n - 2n);
    const g = gcd(a, n);

    if (g !== 1n) {
      return orderedFactors(g, n / g);
    }

    const r = findPeriod(a, n);
    if (r % 2n !== 0n) continue;

    const half = modPow(a, r / 2n, n);
    // a^(r/2) ≡ -1 (mod n) is unusable
    if (half === n - 1n) continue;

    const p = gcd(half + 1n, n);
    const q = gcd(half - 1n, n);

    if (p > 1n && p < n) return orderedFactors(p, n / p);
    if (q > 1n && q < n) return orderedFactors(q, n / q);
  }

  throw new Error(`Failed to factor ${n} after ${maxAttempts} attempts`);
}

function orderedFactors(a: bigint, b: bigint): Factors {
  return a <= b ? { p: a, q: b } : { p: b, q: a };
}
