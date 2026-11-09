import crypto from "node:crypto";
import { performance } from "node:perf_hooks";
import { AuditLedger } from "../audit/auditLedger.js";
import { evaluateApiPayload } from "../guards/apiPayloadGuard.js";
import { evaluateCliCommand } from "../guards/cliCommandGuard.js";
import { evaluateUiAction } from "../guards/uiActionGuard.js";
import type {
  AgentAction,
  AuditEntry,
  ChainVerificationResult,
  ControlPlanePolicyPack,
  FirewallConfig,
  FirewallDecision,
  PolicyViolation,
  ReasonCode,
  SystemStateSnapshot,
  VerdictStatus,
} from "../types/index.js";
import { computeStateSnapshotHash, StateEvaluator } from "./StateEvaluator.js";

/**
 * Structured error thrown by `firewall.guardToolCall()` when the Data-Plane
 * execution cage returns a `BLOCK` or `HOLD` verdict.
 */
export class FirewallBlockedError extends Error {
  public readonly decision: FirewallDecision;

  constructor(decision: FirewallDecision) {
    super(
      `[Zero-Trust Agent Firewall] Action ${decision.verdict} (${decision.reasonCodes.join(", ")})`,
    );
    this.name = "FirewallBlockedError";
    this.decision = decision;
  }
}

/**
 * In-Process & Sidecar Data-Plane Execution Firewall ("Gate 2") that intercepts
 * autonomous AI agent tool calls (MCP, Function-Calling, API, CLI, Browser/UI) and
 * validates them against live system state cages in sub-10ms before execution.
 */
export class ActionFirewall {
  private maxEvaluationLatencyMs: number;
  private disallowBrittleSelectors: boolean;
  private circuitBreakerThreshold: number;
  private readonly nowMs: () => number;
  private stateEvaluator: StateEvaluator;
  private readonly ledger: AuditLedger;
  private policyPack?: ControlPlanePolicyPack;
  private consecutiveBlocks = 0;

  constructor(config: FirewallConfig = {}, ledger?: AuditLedger) {
    this.maxEvaluationLatencyMs =
      config.policyPack?.maxEvaluationLatencyMs ??
      config.maxEvaluationLatencyMs ??
      10;
    this.disallowBrittleSelectors =
      config.policyPack?.disallowBrittleSelectors ??
      config.disallowBrittleSelectors ??
      true;
    this.circuitBreakerThreshold =
      config.policyPack?.circuitBreakerThreshold ??
      config.circuitBreakerThreshold ??
      5;
    this.nowMs = config.nowMs ?? (() => Date.now());
    this.policyPack = config.policyPack;
    this.stateEvaluator = new StateEvaluator({
      defaultMaxStalenessMs:
        config.policyPack?.defaultMaxStalenessMs ??
        config.defaultMaxStalenessMs ??
        5000,
      nowMs: this.nowMs,
    });
    this.ledger = ledger ?? new AuditLedger(config.onAuditEntry);
    if (ledger && config.onAuditEntry) {
      this.ledger.setTelemetrySink(config.onAuditEntry);
    }
  }

  /**
   * Hot-reloads a versioned Control-Plane policy pack into the Data-Plane firewall
   * without restarting the host process or sidecar container.
   */
  public loadPolicyPack(pack: ControlPlanePolicyPack): void {
    this.policyPack = pack;
    if (pack.maxEvaluationLatencyMs !== undefined) {
      this.maxEvaluationLatencyMs = pack.maxEvaluationLatencyMs;
    }
    if (pack.disallowBrittleSelectors !== undefined) {
      this.disallowBrittleSelectors = pack.disallowBrittleSelectors;
    }
    if (pack.circuitBreakerThreshold !== undefined) {
      this.circuitBreakerThreshold = pack.circuitBreakerThreshold;
    }
    if (pack.defaultMaxStalenessMs !== undefined) {
      this.stateEvaluator = new StateEvaluator({
        defaultMaxStalenessMs: pack.defaultMaxStalenessMs,
        nowMs: this.nowMs,
      });
    }
  }

  public getPolicyPack(): ControlPlanePolicyPack | undefined {
    return this.policyPack;
  }

  private mergeWithControlPlanePolicy(
    state: SystemStateSnapshot,
  ): SystemStateSnapshot {
    if (!this.policyPack) {
      return state;
    }

    const mergedTainted =
      this.policyPack.globalTaintedDomains || state.taintedDomains
        ? [
            ...(this.policyPack.globalTaintedDomains ?? []),
            ...(state.taintedDomains ?? []),
          ]
        : undefined;

    const mergedDom =
      state.dom && this.policyPack.defaultAllowedOrigins
        ? {
            ...state.dom,
            allowedOrigins:
              state.dom.allowedOrigins ?? this.policyPack.defaultAllowedOrigins,
          }
        : state.dom;

    return {
      ...state,
      dom: mergedDom,
      apiContracts: state.apiContracts ?? this.policyPack.defaultApiContracts,
      cliPolicy: state.cliPolicy ?? this.policyPack.defaultCliPolicy,
      taintedDomains: mergedTainted,
    };
  }

  /**
   * Synchronously evaluates an intercepted agent tool call against the live state snapshot
   * and active Control-Plane policy pack in sub-millisecond time (<10ms SLA).
   */
  public evaluate(
    action: AgentAction,
    rawState: SystemStateSnapshot,
  ): FirewallDecision {
    const startPerf = performance.now();
    const decisionId = `fw_${crypto.randomBytes(8).toString("hex")}`;
    const timestamp = new Date(this.nowMs()).toISOString();
    const state = this.mergeWithControlPlanePolicy(rawState);

    // 1. Check runaway agent circuit breaker first
    if (
      this.circuitBreakerThreshold > 0 &&
      this.consecutiveBlocks >= this.circuitBreakerThreshold
    ) {
      const stateSnapshotHash = computeStateSnapshotHash(state);
      const cbViolation: PolicyViolation = {
        code: "CIRCUIT_BREAKER_OPEN",
        severity: "critical",
        surface: "runtime",
        message: `Agent circuit breaker is OPEN after ${this.consecutiveBlocks} consecutive blocked actions.`,
        remediation:
          "Reset the circuit breaker (firewall.resetCircuitBreaker()) after inspecting the agent loop.",
      };
      const elapsed = Number((performance.now() - startPerf).toFixed(3));
      const auditEntry = this.ledger.record({
        entryId: decisionId,
        timestamp,
        action,
        verdict: "BLOCK",
        reasonCodes: ["CIRCUIT_BREAKER_OPEN"],
        evaluationLatencyMs: elapsed,
        stateSnapshotHash,
      });

      return {
        decisionId,
        actionSurface: action.surface,
        verdict: "BLOCK",
        allowed: false,
        reasonCodes: ["CIRCUIT_BREAKER_OPEN"],
        violations: [cbViolation],
        evaluationLatencyMs: elapsed,
        withinLatencyBudget: elapsed <= this.maxEvaluationLatencyMs,
        stateSnapshotHash,
        auditEntryHash: auditEntry.entryHash,
        timestamp,
      };
    }

    // 2. Evaluate cross-surface system state cages
    const stateCtx = this.stateEvaluator.evaluateState(action, state);
    const violations: PolicyViolation[] = [...stateCtx.violations];

    // 3. Evaluate surface-specific guard invariants
    switch (action.surface) {
      case "ui": {
        const uiViolations = evaluateUiAction(action, stateCtx.normalizedDom, {
          disallowBrittleSelectors: this.disallowBrittleSelectors,
          taintedDomains: stateCtx.taintedDomains,
        });
        violations.push(...uiViolations);
        break;
      }
      case "api": {
        const apiViolations = evaluateApiPayload(
          action,
          state.apiContracts,
          state.session,
          { taintedDomains: stateCtx.taintedDomains },
        );
        violations.push(...apiViolations);
        break;
      }
      case "cli": {
        const cliViolations = evaluateCliCommand(action, state.cliPolicy, {
          taintedDomains: stateCtx.taintedDomains,
        });
        violations.push(...cliViolations);
        break;
      }
    }

    const elapsedMs = Number((performance.now() - startPerf).toFixed(3));
    const withinBudget = elapsedMs <= this.maxEvaluationLatencyMs;
    if (!withinBudget) {
      violations.push({
        code: "EVALUATION_BUDGET_EXCEEDED",
        severity: "medium",
        surface: "runtime",
        message: `Evaluation took ${elapsedMs}ms, exceeding the ${this.maxEvaluationLatencyMs}ms latency budget.`,
        remediation:
          "Reduce state snapshot size or simplify custom regex patterns.",
      });
    }

    const reasonCodes: ReasonCode[] = Array.from(
      new Set(violations.map((v) => v.code)),
    );

    // Determine verdict:
    // - If only UI_DESTRUCTIVE_ACTION_UNCONFIRMED is present, return HOLD for human confirmation.
    // - If any other violation is present, return BLOCK.
    // - Otherwise return ALLOW.
    let verdict: VerdictStatus = "ALLOW";
    if (reasonCodes.length > 0) {
      const onlyUnconfirmedDestructive =
        reasonCodes.length === 1 &&
        reasonCodes[0] === "UI_DESTRUCTIVE_ACTION_UNCONFIRMED";
      verdict = onlyUnconfirmedDestructive ? "HOLD" : "BLOCK";
    }

    if (verdict === "BLOCK") {
      this.consecutiveBlocks += 1;
    } else if (verdict === "ALLOW") {
      this.consecutiveBlocks = 0;
    }

    const auditEntry = this.ledger.record({
      entryId: decisionId,
      timestamp,
      action,
      verdict,
      reasonCodes,
      evaluationLatencyMs: elapsedMs,
      stateSnapshotHash: stateCtx.stateSnapshotHash,
    });

    return {
      decisionId,
      actionSurface: action.surface,
      verdict,
      allowed: verdict === "ALLOW",
      reasonCodes,
      violations,
      evaluationLatencyMs: elapsedMs,
      withinLatencyBudget: withinBudget,
      stateSnapshotHash: stateCtx.stateSnapshotHash,
      auditEntryHash: auditEntry.entryHash,
      timestamp,
    };
  }

  /**
   * Universal agent tool-call wrapper.
   * Executes `executeFn` only if the synchronous check returns `ALLOW`;
   * otherwise throws `FirewallBlockedError` without invoking the tool.
   */
  public async guardToolCall<T>(
    action: AgentAction,
    state: SystemStateSnapshot,
    executeFn: (decision: FirewallDecision) => Promise<T> | T,
  ): Promise<{ result: T; decision: FirewallDecision }> {
    const decision = this.evaluate(action, state);
    if (!decision.allowed) {
      throw new FirewallBlockedError(decision);
    }
    const result = await executeFn(decision);
    return { result, decision };
  }

  public resetCircuitBreaker(): void {
    this.consecutiveBlocks = 0;
  }

  public getConsecutiveBlocks(): number {
    return this.consecutiveBlocks;
  }

  public getCircuitBreakerThreshold(): number {
    return this.circuitBreakerThreshold;
  }

  public getAuditEntries(): readonly AuditEntry[] {
    return this.ledger.getEntries();
  }

  public verifyAuditChain(): ChainVerificationResult {
    return this.ledger.verifyChain();
  }

  public exportAuditJsonl(): string {
    return this.ledger.exportJsonl();
  }
}
