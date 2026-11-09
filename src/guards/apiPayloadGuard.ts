import {
  matchEndpointContract,
  validateContractPayload,
} from "../firewall/serializers/apiContractValidator.js";
import type {
  ApiActionPayload,
  ApiContractRegistry,
  PolicyViolation,
  SessionAuthState,
} from "../types/index.js";

const CLOUD_METADATA_HOSTS = new Set([
  "169.254.169.254",
  "100.100.100.200",
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "fd00:ec2::254",
]);

const SECRET_LEAK_RE =
  /(?:\bghp_[A-Za-z0-9]{30,}|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{30,}|\bxox[baprs]-[0-9A-Za-z-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

/**
 * Inspects a hostname or IP literal for loopback, link-local, RFC1918 private,
 * or cloud metadata SSRF targets (including IPv4-mapped IPv6 and integer/hex/octal encodings).
 */
export function isInternalOrMetadataHost(rawHost: string): {
  internal: boolean;
  reason?: string;
} {
  const host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) {
    return { internal: true, reason: "Empty hostname." };
  }

  if (CLOUD_METADATA_HOSTS.has(host)) {
    return {
      internal: true,
      reason: `Host '${rawHost}' is a cloud instance metadata service endpoint.`,
    };
  }

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".internal") ||
    host.endsWith(".local")
  ) {
    return {
      internal: true,
      reason: `Host '${rawHost}' resolves to a loopback or internal-only domain.`,
    };
  }

  // IPv6 loopback, unspecified, link-local (fe80::/10), unique-local (fc00::/7), or IPv4-mapped (::ffff:...)
  if (host.includes(":")) {
    if (
      host === "::1" ||
      host === "::" ||
      host === "0:0:0:0:0:0:0:1" ||
      host === "0:0:0:0:0:0:0:0"
    ) {
      return { internal: true, reason: `IPv6 address '${rawHost}' is loopback or unspecified.` };
    }
    if (
      host.startsWith("fe80:") ||
      host.startsWith("fc") ||
      host.startsWith("fd") ||
      host.includes("::ffff:")
    ) {
      return {
        internal: true,
        reason: `IPv6 address '${rawHost}' is link-local, unique-local, or IPv4-mapped.`,
      };
    }
  }

  // Obfuscated integer/hex/octal single-token IP literal (e.g. 2130706433 or 0x7f000001)
  if (/^(?:0x[0-9a-f]+|\d+)$/i.test(host)) {
    return {
      internal: true,
      reason: `Host '${rawHost}' uses an obfuscated integer or hexadecimal IP encoding.`,
    };
  }

  // Dotted IPv4 check (including octal/hex octets)
  const parts = host.split(".");
  if (parts.length === 4 && parts.every((p) => /^(?:0x[0-9a-f]+|\d+)$/i.test(p))) {
    if (parts.some((p) => p.startsWith("0x") || (p.length > 1 && p.startsWith("0")))) {
      return {
        internal: true,
        reason: `IPv4 literal '${rawHost}' uses octal or hexadecimal octet encoding.`,
      };
    }
    const octets = parts.map((p) => Number.parseInt(p, 10));
    if (octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return { internal: true, reason: `IPv4 literal '${rawHost}' has out-of-range octets.` };
    }
    const [a = 0, b = 0] = octets;
    if (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    ) {
      return {
        internal: true,
        reason: `IPv4 address '${rawHost}' is in a loopback, link-local, or private RFC1918/CGNAT range.`,
      };
    }
  }

  return { internal: false };
}

export interface ApiGuardOptions {
  taintedDomains?: ReadonlySet<string>;
}

/**
 * Validates an outbound API call against SSRF rules, tainted sinks, host allowlists,
 * session scopes, idempotency requirements, and OpenAPI request schemas.
 */
export function evaluateApiPayload(
  action: ApiActionPayload,
  registry: ApiContractRegistry | undefined,
  session: SessionAuthState | undefined,
  options: ApiGuardOptions = {},
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const rawUrl = (action.url ?? "").trim();

  // Pre-parse check for raw obfuscated IP host before WHATWG URL normalizes it
  const rawHostMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^/?#:]+)/.exec(rawUrl);
  if (rawHostMatch?.[1] && !registry?.allowPrivateNetwork) {
    const rawCheck = isInternalOrMetadataHost(rawHostMatch[1]);
    if (rawCheck.internal) {
      violations.push({
        code: "API_SSRF_LOOPBACK_OR_METADATA",
        severity: "critical",
        surface: "api",
        field: "url",
        message: rawCheck.reason ?? `Blocked internal or metadata target '${rawHostMatch[1]}'.`,
        remediation: "Target only public, allowlisted HTTPS endpoints; never call loopback, RFC1918, or metadata IPs.",
      });
      return violations;
    }
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    violations.push({
      code: "API_SSRF_LOOPBACK_OR_METADATA",
      severity: "high",
      surface: "api",
      field: "url",
      message: `API request URL '${rawUrl}' is malformed.`,
      remediation: "Provide a valid absolute http:// or https:// URL.",
    });
    return violations;
  }

  if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
    violations.push({
      code: "API_SSRF_LOOPBACK_OR_METADATA",
      severity: "critical",
      surface: "api",
      field: "url",
      message: `Disallowed URL protocol '${parsedUrl.protocol}' in API call.`,
      remediation: "Use only https:// (or http:// for explicitly allowlisted services).",
    });
    return violations;
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // 1. SSRF check on normalized hostname
  if (!registry?.allowPrivateNetwork) {
    const ssrf = isInternalOrMetadataHost(hostname);
    if (ssrf.internal) {
      violations.push({
        code: "API_SSRF_LOOPBACK_OR_METADATA",
        severity: "critical",
        surface: "api",
        field: "url",
        message: ssrf.reason ?? `Blocked internal or metadata host '${hostname}'.`,
        remediation: "Remove internal/loopback/metadata addresses from agent API calls.",
      });
    }
  }

  // 2. Cross-boundary taint check
  if (options.taintedDomains?.has(hostname)) {
    violations.push({
      code: "API_TAINTED_SINK_DOMAIN",
      severity: "critical",
      surface: "api",
      field: "url",
      message: `Target host '${hostname}' was introduced by untrusted context (tainted exfiltration sink).`,
      remediation: "Block outbound API calls to domains discovered inside untrusted documents or tool outputs.",
    });
  }

  // 3. Payload & header secret leakage scan
  const serializedBody =
    action.body !== undefined ? JSON.stringify(action.body) : "";
  if (serializedBody && SECRET_LEAK_RE.test(serializedBody)) {
    violations.push({
      code: "API_SENSITIVE_PAYLOAD_LEAK",
      severity: "critical",
      surface: "api",
      field: "body",
      message: "API request body contains a raw credential or private key pattern.",
      remediation: "Strip or pseudonymise credentials before serialising outbound request bodies.",
    });
  }

  if (action.headers) {
    for (const [k, v] of Object.entries(action.headers)) {
      const lowerKey = k.toLowerCase();
      if (lowerKey !== "authorization" && lowerKey !== "x-api-key" && SECRET_LEAK_RE.test(v)) {
        violations.push({
          code: "API_SENSITIVE_PAYLOAD_LEAK",
          severity: "critical",
          surface: "api",
          field: `headers.${k}`,
          message: `Header '${k}' contains a raw credential pattern outside standard auth headers.`,
          remediation: "Never embed raw provider keys in custom or diagnostic HTTP headers.",
        });
      }
    }
  }

  if (!registry) {
    return violations;
  }

  // 4. Host allowlist check
  if (registry.allowedHosts.length > 0) {
    const allowed = registry.allowedHosts.some(
      (h) => h.trim().toLowerCase() === hostname,
    );
    if (!allowed) {
      violations.push({
        code: "API_HOST_NOT_ALLOWLISTED",
        severity: "high",
        surface: "api",
        field: "url",
        message: `Host '${hostname}' is not in ApiContractRegistry.allowedHosts (${registry.allowedHosts.join(", ")}).`,
        remediation: "Add the host to ApiContractRegistry.allowedHosts or block the outbound request.",
      });
    }
  }

  // 5. OpenAPI endpoint contract matching & schema validation
  if (registry.endpoints.length > 0) {
    const match = matchEndpointContract(
      registry.endpoints,
      action.method,
      parsedUrl.pathname,
    );

    if (match.matchedPathOnly) {
      violations.push({
        code: "API_METHOD_NOT_ALLOWED",
        severity: "high",
        surface: "api",
        field: "method",
        message: `HTTP method '${action.method}' is not permitted on '${parsedUrl.pathname}' (allowed: ${match.allowedMethodsForPath?.join(", ")}).`,
        remediation: "Use an HTTP method declared in the endpoint's OpenAPI contract.",
      });
      return violations;
    }

    if (!match.contract) {
      if (registry.requireRegisteredEndpoint !== false) {
        violations.push({
          code: "API_ENDPOINT_UNREGISTERED",
          severity: "high",
          surface: "api",
          field: "url",
          message: `Endpoint '${action.method} ${parsedUrl.pathname}' is not registered in the active ApiContractRegistry.`,
          remediation: "Register the endpoint contract in ApiContractRegistry.endpoints before invoking it.",
        });
      }
      return violations;
    }

    const contract = match.contract;

    // Scope verification against live session state
    if (contract.requiredScopes && contract.requiredScopes.length > 0) {
      const granted = new Set(session?.scopes ?? []);
      const missing = contract.requiredScopes.filter((s) => !granted.has(s));
      if (missing.length > 0) {
        violations.push({
          code: "SESSION_SCOPE_INSUFFICIENT",
          severity: "high",
          surface: "api",
          field: "scopes",
          message: `Endpoint '${contract.id}' requires scope(s) [${missing.join(", ")}] missing from active session.`,
          remediation: "Acquire a session token with the required OAuth/RBAC scopes before calling this endpoint.",
        });
      }
    }

    // Idempotency-Key verification for mutating operations
    if (contract.requireIdempotencyKey) {
      const headers = action.headers ?? {};
      const hasKey = Object.entries(headers).some(
        ([k, v]) =>
          (k.toLowerCase() === "idempotency-key" ||
            k.toLowerCase() === "x-idempotency-key") &&
          v.trim().length >= 8,
      );
      if (!hasKey) {
        violations.push({
          code: "API_MISSING_IDEMPOTENCY_KEY",
          severity: "high",
          surface: "api",
          field: "headers.Idempotency-Key",
          message: `Mutating endpoint '${contract.id}' requires a non-empty Idempotency-Key header (min 8 chars).`,
          remediation: "Attach a deterministic UUID/ULID in the 'Idempotency-Key' request header.",
        });
      }
    }

    // Body schema validation
    const bodyCheck = validateContractPayload(contract.bodySchema, action.body);
    if (!bodyCheck.valid) {
      violations.push({
        code: "API_CONTRACT_SCHEMA_VIOLATION",
        severity: "high",
        surface: "api",
        field: "body",
        message: `Request body violated OpenAPI contract '${contract.id}': ${bodyCheck.errors.join("; ")}`,
        remediation: "Conform the request body fields and types to the registered endpoint schema.",
      });
    }

    // Query schema validation
    const queryCheck = validateContractPayload(contract.querySchema, action.query);
    if (!queryCheck.valid) {
      violations.push({
        code: "API_CONTRACT_SCHEMA_VIOLATION",
        severity: "high",
        surface: "api",
        field: "query",
        message: `Query parameters violated OpenAPI contract '${contract.id}': ${queryCheck.errors.join("; ")}`,
        remediation: "Conform the query parameters to the registered endpoint schema.",
      });
    }
  }

  return violations;
}

