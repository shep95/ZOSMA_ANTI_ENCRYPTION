/**
 * Live end-to-end attack:
 * real RSA → encrypt → factor N on IBM Quantum with Shor → recover d → decrypt.
 */

import {
  decryptMessage,
  encryptMessage,
  formatCiphertext,
  generateLiveKeypair,
  recoverPrivateKey,
} from "./rsa.js";
import { shorsBreaker } from "./shor.js";

function parseArgs(argv: string[]): {
  modulus: 15 | 21;
  message: string;
  shots: number;
  backend?: string;
} {
  let modulus: 15 | 21 = 15;
  let message = "ZOSMA";
  let shots = 4096;
  let backend: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--modulus" || arg === "-n") {
      const value = Number(argv[++i]);
      if (value !== 15 && value !== 21) {
        throw new Error("Live moduli supported today: 15 or 21");
      }
      modulus = value;
    } else if (arg === "--message" || arg === "-m") {
      message = argv[++i] ?? message;
    } else if (arg === "--shots") {
      shots = Number(argv[++i]);
    } else if (arg === "--backend") {
      backend = argv[++i];
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
  }

  return { modulus, message, shots, backend };
}

function printHelp(): void {
  console.log(`Usage: npm start -- [options]

Live RSA break using Shor's algorithm on IBM Quantum hardware.

Options:
  -n, --modulus <15|21>  RSA modulus (default: 15)
  -m, --message <text>   Plaintext (default: ZOSMA)
      --shots <k>        QPU shots (default: 4096)
      --backend <name>   IBM backend (default: least busy real QPU)
  -h, --help             Show help

Requires:
  IBM_QUANTUM_TOKEN   API token from https://quantum.cloud.ibm.com/
  pip install -r quantum/requirements.txt
`);
}

async function main(): Promise<void> {
  const { modulus, message, shots, backend } = parseArgs(process.argv.slice(2));

  if (!process.env.IBM_QUANTUM_TOKEN && !process.env.QISKIT_IBM_TOKEN) {
    console.warn(
      "Warning: IBM_QUANTUM_TOKEN is not set. The quantum step will fail unless Qiskit has a saved account.\n",
    );
  }

  console.log("=== Act 1: Build a live-hardware RSA lock ===");
  const { publicKey, privateKey, p, q } = generateLiveKeypair(modulus);
  console.log(`Secret primes p, q: ${p}, ${q}`);
  console.log(`Public key  (e, N): (${publicKey.e}, ${publicKey.n})`);
  console.log(`Private key (d, N): (${privateKey.d}, ${privateKey.n})`);

  console.log("\n=== Act 2: Lock a message (real RSA) ===");
  console.log(`Plaintext: ${message}`);
  const ciphertext = encryptMessage(message, publicKey);
  console.log(`Encrypted digits: ${formatCiphertext(ciphertext)}`);

  const legit = decryptMessage(ciphertext, privateKey);
  console.log(`Decrypted with real private key: ${legit}`);
  if (legit !== message) {
    throw new Error("Legitimate RSA decrypt failed");
  }

  console.log("\n=== Act 3: Factor N on live IBM Quantum (Shor) ===");
  console.log("Submitting order-finding circuit to a real QPU…");
  const factors = await shorsBreaker(publicKey.n, { shots, backend });
  console.log(`Mode: ${factors.mode}`);
  if (factors.backend) console.log(`Backend: ${factors.backend}`);
  if (factors.jobId) console.log(`Job ID: ${factors.jobId}`);
  if (factors.order != null) console.log(`Recovered order r: ${factors.order}`);
  console.log(`Factored N=${publicKey.n} into (${factors.p}, ${factors.q})`);

  console.log("\n=== Act 4: Forge private key and read the message ===");
  const crackedKey = recoverPrivateKey(publicKey, factors.p, factors.q);
  console.log(`Recovered private exponent d: ${crackedKey.d}`);

  const cracked = decryptMessage(ciphertext, crackedKey);
  console.log(`Message cracked via live Shor: ${cracked}`);

  if (cracked !== message) {
    throw new Error("Crack failed: plaintext mismatch");
  }

  console.log("\nSuccess: ciphertext recovered using factors from a live quantum job.");
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
