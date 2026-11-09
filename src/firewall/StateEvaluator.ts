import crypto from "node:crypto";
import type {
  AgentAction,
  PolicyViolation,
  SystemStateSnapshot,
} from "../types/index.js";
import {
  type NormalizedDomState,
  parseDomState,
} from "./serializers/domStateParser.js";

export interface StateEvaluationContext {
  stateSnapshotHash: string;
  normalizedDom?: NormalizedDomState;
  taintedDomains: ReadonlySet<string>;
  violations: PolicyViolation[];
}

function isMutatingAction(action: AgentAction): boolean {
  switch (action.surface) {
    case "api":
      return (
        action.method === "POST" ||
        action.method === "PUT" ||
        action.method === "PATCH" ||
        action.method === "DELETE"
      );
    case "ui":
      return (
        action.actionType === "click" ||
        action.actionType === "dblclick" ||
        action.actionType === "fill" ||
        action.actionType === "select" ||
        action.actionType === "check" ||
        action.actionType === "uncheck" ||
        action.actionType === "press"
      );
    case "cli": {
      const sub = (action.args[0] ?? "").toLowerCase();
      return !["status", "diff", "log", "branch", "--version", "-v", "--help"].includes(sub);
    }
  }
}

/**
 * Computes a deterministic SHA-256 digest of the system state snapshot for audit linkage.
 */
export function computeStateSnapshotHash(state: SystemStateSnapshot): string {
  const canonical = JSON.stringify({
    snapshotId: state.snapshotId,
    capturedAtMs: state.capturedAtMs,
    session: state.session
      ? {
          authenticated: state.session.authenticated,
          principalId: state.session.principalId ?? null,
          expiresAtMs: state.session.expiresAtMs ?? null,
          scopes: [...state.session.scopes].sort(),
          dbLockActive: Boolean(state.session.dbLockActive),
          readOnlyMode: Boolean(state.session.readOnlyMode),
        }
      : null,
    domUrl: state.dom?.currentUrl ?? null,
    domModal: state.dom?.activeModalSelector ?? null,
    domElementCount: state.dom?.elements.length ?? 0,
    endpointCount: state.apiContracts?.endpoints.length ?? 0,
    taintedDomains: [...(state.taintedDomains ?? [])].sort(),
  });
  return crypto.createHash("sha256").update(canonical).digest("hex").slice(0, 32);
}

/**
 * Evaluates cross-surface system state cages:
 * 1. Snapshot temporal freshness (anti-TOCTOU cage)
 * 2. Session authentication & token expiration
 * 3. Active database lock / maintenance freeze
 * 4. Read-only mode enforcement
 */
export class StateEvaluator {
  private readonly defaultMaxStalenessMs: number;
  private readonly nowMs: () => number;

  constructor(options: { defaultMaxStalenessMs?: number; nowMs?: () => number } = {}) {
    this.defaultMaxStalenessMs = options.defaultMaxStalenessMs ?? 5000;
    this.nowMs = options.nowMs ?? (() => Date.now());
  }

  public evaluateState(
    action: AgentAction,
    state: SystemStateSnapshot,
  ): StateEvaluationContext {
    const violations: PolicyViolation[] = [];
    const now = this.nowMs();
    const maxStaleness = state.maxStalenessMs ?? this.defaultMaxStalenessMs;
    const ageMs = now - state.capturedAtMs;

    // 1. Temporal freshness cage
    if (ageMs > maxStaleness || ageMs < -5000) {
      violations.push({
        code: "STATE_SNAPSHOT_STALE",
        severity: "critical",
        surface: "state",
        field: "capturedAtMs",
        message: `State snapshot '${state.snapshotId}' is stale (age ${ageMs}ms exceeds maxStalenessMs ${maxStaleness}ms).`,
        remediation: "Re-sample live DOM/session state immediately before evaluating the agent action.",
      });
    }

    // 2. Session authentication & expiration cage
    if (state.session) {
      if (!state.session.authenticated) {
        violations.push({
          code: "SESSION_UNAUTHENTICATED",
          severity: "critical",
          surface: "state",
          field: "session.authenticated",
          message: "Active session is unauthenticated (authenticated=false).",
          remediation: "Complete authentication handshake before dispatching agent actions.",
        });
      } else if (
        state.session.expiresAtMs !== undefined &&
        now >= state.session.expiresAtMs
      ) {
        violations.push({
          code: "SESSION_EXPIRED",
          severity: "critical",
          surface: "state",
          field: "session.expiresAtMs",
          message: `Session token expired ${now - state.session.expiresAtMs}ms ago.`,
          remediation: "Refresh the session token and capture a new SystemStateSnapshot.",
        });
      }

      // 3. Database lock cage
      if (state.session.dbLockActive && isMutatingAction(action)) {
        violations.push({
          code: "DATABASE_LOCK_ACTIVE",
          severity: "critical",
          surface: "state",
          field: "session.dbLockActive",
          message: `Mutating ${action.surface.toUpperCase()} action blocked while database lock / migration freeze is active.`,
          remediation: "Wait for database lock release before permitting state-changing actions.",
        });
      }

      // 4. Read-only mode cage
      if (state.session.readOnlyMode && isMutatingAction(action)) {
        violations.push({
          code: "READONLY_MODE_VIOLATION",
          severity: "high",
          surface: "state",
          field: "session.readOnlyMode",
          message: `Mutating ${action.surface.toUpperCase()} action is forbidden while session is in readOnlyMode.`,
          remediation: "Restrict the agent to read-only queries/navigation or disable readOnlyMode.",
        });
      }
    }

    const normalizedDom = state.dom ? parseDomState(state.dom) : undefined;
    const taintedDomains = new Set(
      (state.taintedDomains ?? []).map((d) => d.trim().toLowerCase()).filter(Boolean),
    );

    return {
      stateSnapshotHash: computeStateSnapshotHash(state),
      normalizedDom,
      taintedDomains,
      violations,
    };
  }
}

