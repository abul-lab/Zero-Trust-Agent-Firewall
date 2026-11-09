import crypto from "node:crypto";
import type {
  AgentAction,
  AuditEntry,
  AuditTelemetrySink,
  ChainVerificationResult,
  ReasonCode,
  VerdictStatus,
} from "../types/index.js";

export const GENESIS_HASH = "GENESIS";

const SENSITIVE_TOKEN_RE =
  /\b(?:ghp_[A-Za-z0-9]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{16,}|Bearer\s+[A-Za-z0-9._-]+)\b/gi;

/**
 * Produces a concise, masked summary of an intercepted action so raw secrets
 * are never written to the audit trail.
 */
export function summarizeActionSafely(action: AgentAction): string {
  let raw: string;
  switch (action.surface) {
    case "ui":
      raw =
        action.actionType === "navigate"
          ? `ui:navigate -> ${action.targetUrl ?? ""}`
          : `ui:${action.actionType} (${action.selector ?? ""})`;
      break;
    case "api":
      raw = `api:${action.method} ${action.url}`;
      break;
    case "cli":
      raw = `cli:${action.executable} ${action.args.join(" ")}`.trim();
      break;
  }
  return raw.replace(SENSITIVE_TOKEN_RE, "[REDACTED]").slice(0, 240);
}

/**
 * Deterministically computes the SHA-256 entryHash linking `prevHash` to the canonical entry fields.
 */
export function computeAuditEntryHash(
  entry: Omit<AuditEntry, "entryHash">,
): string {
  const canonical = [
    String(entry.index),
    entry.entryId,
    entry.timestamp,
    entry.actionSurface,
    entry.actionSummary,
    entry.verdict,
    entry.reasonCodes.join(","),
    entry.evaluationLatencyMs.toFixed(3),
    entry.stateSnapshotHash,
    entry.prevHash,
  ].join("|");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * Append-only, tamper-evident cryptographic audit ledger (SHA-256 hash chain from GENESIS).
 * Supports out-of-band asynchronous SIEM streaming without blocking the synchronous Data-Plane hot path.
 */
export class AuditLedger {
  private readonly chain: AuditEntry[] = [];
  private telemetrySink?: AuditTelemetrySink;

  constructor(telemetrySink?: AuditTelemetrySink) {
    this.telemetrySink = telemetrySink;
  }

  public setTelemetrySink(sink: AuditTelemetrySink | undefined): void {
    this.telemetrySink = sink;
  }

  public record(params: {
    entryId: string;
    timestamp: string;
    action: AgentAction;
    verdict: VerdictStatus;
    reasonCodes: ReasonCode[];
    evaluationLatencyMs: number;
    stateSnapshotHash: string;
  }): AuditEntry {
    const index = this.chain.length;
    const prevHash =
      index === 0 ? GENESIS_HASH : (this.chain[index - 1]?.entryHash ?? GENESIS_HASH);
    const actionSummary = summarizeActionSafely(params.action);

    const draft: Omit<AuditEntry, "entryHash"> = {
      index,
      entryId: params.entryId,
      timestamp: params.timestamp,
      actionSurface: params.action.surface,
      actionSummary,
      verdict: params.verdict,
      reasonCodes: [...params.reasonCodes],
      evaluationLatencyMs: Number(params.evaluationLatencyMs.toFixed(3)),
      stateSnapshotHash: params.stateSnapshotHash,
      prevHash,
    };

    const entryHash = computeAuditEntryHash(draft);
    const committed: AuditEntry = { ...draft, entryHash };
    this.chain.push(committed);

    const sink = this.telemetrySink;
    if (sink) {
      queueMicrotask(() => {
        try {
          void Promise.resolve(sink(committed)).catch(() => {
            // Isolate telemetry transport errors from the Data-Plane runtime
          });
        } catch {
          // Isolate synchronous callback errors
        }
      });
    }

    return committed;
  }

  public getEntries(): readonly AuditEntry[] {
    return this.chain;
  }

  public getHeadHash(): string {
    if (this.chain.length === 0) {
      return GENESIS_HASH;
    }
    return this.chain[this.chain.length - 1]?.entryHash ?? GENESIS_HASH;
  }

  /**
   * Verifies every link in the audit chain starting from GENESIS.
   */
  public verifyChain(entries: readonly AuditEntry[] = this.chain): ChainVerificationResult {
    let expectedPrev = GENESIS_HASH;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (!entry) continue;

      if (entry.index !== i) {
        return {
          valid: false,
          checked: i,
          headHash: expectedPrev,
          brokenAtIndex: i,
          brokenEntryId: entry.entryId,
          reason: `Index sequence gap at position ${i} (found index=${entry.index}).`,
        };
      }

      if (entry.prevHash !== expectedPrev) {
        return {
          valid: false,
          checked: i,
          headHash: expectedPrev,
          brokenAtIndex: i,
          brokenEntryId: entry.entryId,
          reason: `Broken prevHash link at entry '${entry.entryId}' (expected '${expectedPrev.slice(0, 12)}...', got '${entry.prevHash.slice(0, 12)}...').`,
        };
      }

      const recomputed = computeAuditEntryHash(entry);
      if (recomputed !== entry.entryHash) {
        return {
          valid: false,
          checked: i,
          headHash: expectedPrev,
          brokenAtIndex: i,
          brokenEntryId: entry.entryId,
          reason: `Entry payload hash mismatch at '${entry.entryId}' (tampered fields detected).`,
        };
      }

      expectedPrev = entry.entryHash;
    }

    return {
      valid: true,
      checked: entries.length,
      headHash: expectedPrev,
    };
  }

  public exportJsonl(): string {
    return this.chain.map((e) => JSON.stringify(e)).join("\n");
  }

  public static verifyJsonl(jsonlContent: string): ChainVerificationResult {
    const lines = jsonlContent
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const parsed: AuditEntry[] = lines.map((line) => JSON.parse(line) as AuditEntry);
    const ledger = new AuditLedger();
    return ledger.verifyChain(parsed);
  }
}

