/**
 * Patterns for exposed secrets in web/app client bundles.
 * Classification: public-by-design vs likely-secret.
 */

export type KeyClass = "public_by_design" | "likely_secret" | "crypto_material" | "unknown";

export type PatternDef = {
  id: string;
  class: KeyClass;
  description: string;
  /** Risk if this is a real secret in production. */
  impact: string;
  regex: RegExp;
};

export const SECRET_PATTERNS: readonly PatternDef[] = [
  {
    id: "aws_access_key_id",
    class: "likely_secret",
    description: "AWS Access Key ID",
    impact: "With secret key, can access AWS APIs/data the IAM user allows.",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
  },
  {
    id: "aws_secret_access_key",
    class: "likely_secret",
    description: "AWS Secret Access Key (candidate)",
    impact: "Paired with AKIA… grants cloud access.",
    regex: /(?:aws_secret_access_key|secretAccessKey|AWS_SECRET)["'\s:=]+([A-Za-z0-9/+=]{40})/gi,
  },
  {
    id: "stripe_secret",
    class: "likely_secret",
    description: "Stripe secret key",
    impact: "Full Stripe account API access (charges, customers, payouts).",
    regex: /\b(sk_live_[0-9a-zA-Z]{20,})\b/g,
  },
  {
    id: "stripe_test_secret",
    class: "likely_secret",
    description: "Stripe test secret key",
    impact: "Test-mode Stripe API access.",
    regex: /\b(sk_test_[0-9a-zA-Z]{20,})\b/g,
  },
  {
    id: "stripe_publishable",
    class: "public_by_design",
    description: "Stripe publishable key",
    impact: "Public by design; abuse limited if restricted, still fingerprintable.",
    regex: /\b(pk_(?:live|test)_[0-9a-zA-Z]{20,})\b/g,
  },
  {
    id: "github_pat",
    class: "likely_secret",
    description: "GitHub personal access token",
    impact: "Repo/org access per token scopes.",
    regex: /\b(ghp_[A-Za-z0-9]{36,})\b/g,
  },
  {
    id: "github_oauth",
    class: "likely_secret",
    description: "GitHub OAuth/token candidate",
    impact: "GitHub API access.",
    regex: /\b(gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,})\b/g,
  },
  {
    id: "slack_token",
    class: "likely_secret",
    description: "Slack token",
    impact: "Workspace API access.",
    regex: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
  },
  {
    id: "google_api_key",
    class: "public_by_design",
    description: "Google API key (often browser-restricted)",
    impact: "Public if Maps/browser key; dangerous if unrestricted server key.",
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
  },
  {
    id: "firebase_api_key",
    class: "public_by_design",
    description: "Firebase web API key",
    impact: "Usually public client config; abuse depends on security rules.",
    regex: /apiKey["'\s:]+["'](AIza[0-9A-Za-z\-_]{35})["']/g,
  },
  {
    id: "jwt",
    class: "likely_secret",
    description: "JWT (session/bearer)",
    impact: "May grant user/API session until expiry.",
    regex: /\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,
  },
  {
    id: "pem_private_key",
    class: "likely_secret",
    description: "PEM private key block",
    impact: "Full asymmetric private key — decrypt/sign as that identity.",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    id: "aes_key_hex_32",
    class: "crypto_material",
    description: "32-byte AES key as hex (256-bit)",
    impact: "If real AES-256 key, decrypts data sealed with that key (compromised-key path).",
    regex: /\b([0-9a-fA-F]{64})\b/g,
  },
  {
    id: "generic_api_key_assignment",
    class: "unknown",
    description: "Generic apiKey / secret assignment",
    impact: "May be secret or public; manual review required.",
    regex: /(?:api[_-]?key|apiKey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']/gi,
  },
];
