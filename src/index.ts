/**
 * End-to-end demo matching Breaking_RSA.ipynb:
 * generate RSA → encrypt → decrypt → factor N with Shor → recover d → crack.
 *
 * See NARRATIVE.md for the story this program implements.
 */

import {
  decrypt,
  encrypt,
  formatCiphertext,
  generateKeypair,
  recoverPrivateKey,
} from "./rsa.js";
import { shorsBreaker } from "./shor.js";

function parseArgs(argv: string[]): { bitLength: number; message: string } {
  let bitLength = 8;
  let message = "7enTropy7";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--bit-length" || arg === "-b") {
      bitLength = Number(argv[++i]);
    } else if (arg === "--message" || arg === "-m") {
      message = argv[++i] ?? message;
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
  }

  if (!Number.isInteger(bitLength) || bitLength < 4) {
    throw new Error("bit length must be an integer >= 4");
  }

  return { bitLength, message };
}

function printHelp(): void {
  console.log(`Usage: npm start -- [options]

Options:
  -b, --bit-length <n>  RSA modulus bit length (default: 8)
  -m, --message <text>  Plaintext to encrypt and crack (default: 7enTropy7)
  -h, --help            Show this help
`);
}

function main(): void {
  const { bitLength, message } = parseArgs(process.argv.slice(2));

  console.log("=== Act 1: Build a small RSA lock ===");
  const { publicKey, privateKey, p, q } = generateKeypair(bitLength);
  console.log(`Primes p, q: ${p}, ${q}`);
  console.log(`Public key  (e, N): (${publicKey.e}, ${publicKey.n})`);
  console.log(`Private key (d, N): (${privateKey.d}, ${privateKey.n})`);

  console.log("\n=== Act 2: Lock a message ===");
  console.log(`Plaintext: ${message}`);
  const ciphertext = encrypt(message, publicKey);
  console.log(`Encrypted message: ${formatCiphertext(ciphertext)}`);

  const legit = decrypt(ciphertext, privateKey);
  console.log(`Decrypted with real private key: ${legit}`);
  if (legit !== message) {
    throw new Error("Legitimate RSA decrypt failed");
  }

  console.log("\n=== Act 3: Factor N with Shor's procedure ===");
  const N = publicKey.n;
  const factors = shorsBreaker(N);
  console.log(`Factored N=${N} into (${factors.p}, ${factors.q})`);

  if (factors.p * factors.q !== N) {
    throw new Error("Factorization does not multiply back to N");
  }

  console.log("\n=== Act 4: Forge private key and read the message ===");
  const crackedKey = recoverPrivateKey(publicKey, factors.p, factors.q);
  console.log(`Recovered private exponent d: ${crackedKey.d}`);

  const cracked = decrypt(ciphertext, crackedKey);
  console.log(`Message cracked using Shor's algorithm: ${cracked}`);

  if (cracked !== message) {
    throw new Error("Crack failed: plaintext mismatch");
  }

  console.log("\nSuccess: ciphertext recovered without the original private key.");
}

main();
