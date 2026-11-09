import { describe, expect, it } from "vitest";
import {
  AuditLedger,
  GENESIS_HASH,
  summarizeActionSafely,
  type AgentAction,
  type AuditEntry
} from "../src/index.js";

describe("AuditLedger - SHA-256 Tamper-Evident Hash Chain", () => {
  const sampleAction1: AgentAction = {
    surface: "ui",
    actionId: "act-audit-1",
    actionType: "click",
    selector: "#submit-btn"
  };

  const sampleAction2: AgentAction = {
    surface: "api",
    actionId: "act-audit-2",
    method: "POST",
    url: "https://api.example.com/v1/orders"
  };

  it("links every entry from GENESIS using deterministic SHA-256 hashes", () => {
    const ledger = new AuditLedger();

    const entry1 = ledger.record({
      entryId: "fw_001",
      timestamp: "2026-01-15T10:00:00.000Z",
      action: sampleAction1,
      verdict: "ALLOW",
      reasonCodes: [],
      stateSnapshotHash: "a".repeat(32),
      evaluationLatencyMs: 0.42
    });

    const entry2 = ledger.record({
      entryId: "fw_002",
      timestamp: "2026-01-15T10:00:01.000Z",
      action: sampleAction2,
      verdict: "BLOCK",
      reasonCodes: ["API_SSRF_LOOPBACK_OR_METADATA"],
      stateSnapshotHash: "b".repeat(32),
      evaluationLatencyMs: 0.31
    });

    expect(entry1.index).toBe(0);
    expect(entry1.prevHash).toBe(GENESIS_HASH);
    expect(entry1.entryHash).toMatch(/^[a-f0-9]{64}$/);

    expect(entry2.index).toBe(1);
    expect(entry2.prevHash).toBe(entry1.entryHash);
    expect(entry2.entryHash).toMatch(/^[a-f0-9]{64}$/);

    const verification = ledger.verifyChain();
    expect(verification.valid).toBe(true);
    expect(verification.checked).toBe(2);
    expect(verification.headHash).toBe(entry2.entryHash);
  });

  it("detects tampering if any historical audit entry payload or prevHash is modified", () => {
    const ledger = new AuditLedger();
    const e1 = ledger.record({
      entryId: "fw_001",
      timestamp: "2026-01-15T10:00:00.000Z",
      action: sampleAction1,
      verdict: "BLOCK",
      reasonCodes: ["UI_ELEMENT_DISABLED"],
      stateSnapshotHash: "c".repeat(32),
      evaluationLatencyMs: 0.55
    });
    const e2 = ledger.record({
      entryId: "fw_002",
      timestamp: "2026-01-15T10:00:02.000Z",
      action: sampleAction2,
      verdict: "ALLOW",
      reasonCodes: [],
      stateSnapshotHash: "d".repeat(32),
      evaluationLatencyMs: 0.48
    });

    // Tamper with entry 0 verdict (e.g., attacker tries to rewrite BLOCK -> ALLOW)
    const tamperedEntries: AuditEntry[] = [
      { ...e1, verdict: "ALLOW" },
      e2
    ];
    const tamperedReport = ledger.verifyChain(tamperedEntries);
    expect(tamperedReport.valid).toBe(false);
    expect(tamperedReport.brokenAtIndex).toBe(0);
    expect(tamperedReport.reason).toContain("hash mismatch");

    // Tamper with prevHash linkage at index 1
    const brokenLinkEntries: AuditEntry[] = [
      e1,
      { ...e2, prevHash: "0".repeat(64) }
    ];
    const brokenLinkReport = ledger.verifyChain(brokenLinkEntries);
    expect(brokenLinkReport.valid).toBe(false);
    expect(brokenLinkReport.brokenAtIndex).toBe(1);
    expect(brokenLinkReport.reason).toContain("Broken prevHash link");
  });

  it("exports and verifies JSONL audit logs and masks secrets in action summaries", () => {
    const ledger = new AuditLedger();
    const assembledSecret = ["ghp", "Z".repeat(36)].join("_");

    const cliWithSecret: AgentAction = {
      surface: "cli",
      actionId: "act-cli-secret",
      executable: "git",
      args: ["clone", `https://${assembledSecret}@github.com/example/repo.git`]
    };

    const summary = summarizeActionSafely(cliWithSecret);
    expect(summary).not.toContain(assembledSecret);
    expect(summary).toContain("[REDACTED]");

    ledger.record({
      entryId: "fw_003",
      timestamp: "2026-01-15T10:00:05.000Z",
      action: cliWithSecret,
      verdict: "BLOCK",
      reasonCodes: ["CLI_TAINTED_SINK_ARGUMENT"],
      stateSnapshotHash: "e".repeat(32),
      evaluationLatencyMs: 0.29
    });

    const jsonl = ledger.exportJsonl();
    expect(jsonl).not.toContain(assembledSecret);

    const jsonlReport = AuditLedger.verifyJsonl(jsonl);
    expect(jsonlReport.valid).toBe(true);
    expect(jsonlReport.checked).toBe(1);
  });
});
