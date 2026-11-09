import { describe, expect, it } from "vitest";
import {
  ActionFirewall,
  FirewallBlockedError,
  startFirewallServer,
  type AgentAction,
  type AuditEntry,
  type SystemStateSnapshot
} from "../src/index.js";

function createBaseState(overrides: Partial<SystemStateSnapshot> = {}): SystemStateSnapshot {
  const now = 1_700_000_000_000;
  return {
    snapshotId: "snap-1001",
    capturedAtMs: now - 120,
    maxStalenessMs: 5000,
    session: {
      principalId: "runner-alpha-01",
      authenticated: true,
      expiresAtMs: now + 3_600_000,
      scopes: ["orders:read", "orders:write", "ui:interact"],
      dbLockActive: false,
      readOnlyMode: false
    },
    dom: {
      currentUrl: "https://app.example.com/checkout",
      elements: [
        {
          selector: "#pay-now",
          testId: "pay-now-btn",
          role: "button",
          tagName: "button",
          name: "Pay Now",
          visible: true,
          enabled: true
        }
      ]
    },
    apiContracts: {
      allowedHosts: ["api.example.com"],
      endpoints: [
        {
          id: "createOrder",
          method: "POST",
          pathPattern: "/v1/orders",
          requiredScopes: ["orders:write"],
          requireIdempotencyKey: true,
          bodySchema: {
            orderId: { type: "string", required: true, minLength: 4 },
            amountCents: {
              type: "integer",
              required: true,
              minimum: 100,
              maximum: 500000
            }
          }
        }
      ]
    },
    ...overrides
  };
}

describe("ActionFirewall - Core State Cage & Orchestration", () => {
  const now = 1_700_000_000_000;

  it("allows a valid UI action in sub-10ms and appends a SHA-256 audit entry", () => {
    const firewall = new ActionFirewall({ nowMs: () => now });
    const state = createBaseState();
    const action: AgentAction = {
      surface: "ui",
      actionId: "act-001",
      actionType: "click",
      selector: "#pay-now"
    };

    const decision = firewall.evaluate(action, state);

    expect(decision.verdict).toBe("ALLOW");
    expect(decision.allowed).toBe(true);
    expect(decision.reasonCodes).toEqual([]);
    expect(decision.evaluationLatencyMs).toBeLessThan(10);
    expect(decision.withinLatencyBudget).toBe(true);
    expect(decision.stateSnapshotHash).toMatch(/^[a-f0-9]{32}$/);
    expect(decision.auditEntryHash).toMatch(/^[a-f0-9]{64}$/);
    expect(firewall.getAuditEntries()[0]?.prevHash).toBe("GENESIS");
  });

  it("blocks execution when the state snapshot is stale (STATE_SNAPSHOT_STALE)", () => {
    const firewall = new ActionFirewall({
      defaultMaxStalenessMs: 2000,
      nowMs: () => now
    });
    const state = createBaseState({
      capturedAtMs: now - 4500,
      maxStalenessMs: 2000
    });
    const action: AgentAction = {
      surface: "ui",
      actionId: "act-stale-01",
      actionType: "click",
      selector: "#pay-now"
    };

    const decision = firewall.evaluate(action, state);

    expect(decision.verdict).toBe("BLOCK");
    expect(decision.allowed).toBe(false);
    expect(decision.reasonCodes).toContain("STATE_SNAPSHOT_STALE");
    expect(decision.evaluationLatencyMs).toBeLessThan(10);
  });

  it("blocks execution when session is unauthenticated or expired", () => {
    const firewall = new ActionFirewall({ nowMs: () => now });
    const unauthState = createBaseState({
      session: {
        principalId: "sess-unauth",
        authenticated: false,
        expiresAtMs: now + 60_000,
        scopes: []
      }
    });
    const expiredState = createBaseState({
      session: {
        principalId: "sess-expired",
        authenticated: true,
        expiresAtMs: now - 10,
        scopes: ["orders:write"]
      }
    });
    const action: AgentAction = {
      surface: "ui",
      actionId: "act-auth-check",
      actionType: "click",
      selector: "#pay-now"
    };

    const res1 = firewall.evaluate(action, unauthState);
    expect(res1.verdict).toBe("BLOCK");
    expect(res1.reasonCodes).toContain("SESSION_UNAUTHENTICATED");

    const res2 = firewall.evaluate(action, expiredState);
    expect(res2.verdict).toBe("BLOCK");
    expect(res2.reasonCodes).toContain("SESSION_EXPIRED");
  });

  it("blocks state-mutating actions when active database locks exist or readOnlyMode is enabled", () => {
    const firewall = new ActionFirewall({ nowMs: () => now });
    const lockedState = createBaseState({
      session: {
        principalId: "sess-locked",
        authenticated: true,
        expiresAtMs: now + 3_600_000,
        scopes: ["orders:read", "orders:write"],
        dbLockActive: true,
        readOnlyMode: true
      }
    });

    const postAction: AgentAction = {
      surface: "api",
      actionId: "act-mutate-api",
      method: "POST",
      url: "https://api.example.com/v1/orders",
      headers: { "Idempotency-Key": "idem-12345678" },
      body: { orderId: "ORD-9001", amountCents: 2500 }
    };

    const decision = firewall.evaluate(postAction, lockedState);
    expect(decision.verdict).toBe("BLOCK");
    expect(decision.reasonCodes).toContain("DATABASE_LOCK_ACTIVE");
    expect(decision.reasonCodes).toContain("READONLY_MODE_VIOLATION");

    // Read-only GET requests are allowed even when readOnlyMode & dbLockActive are true
    const getState = createBaseState({
      session: {
        principalId: "sess-locked",
        authenticated: true,
        expiresAtMs: now + 3_600_000,
        scopes: ["orders:read"],
        dbLockActive: true,
        readOnlyMode: true
      },
      apiContracts: {
        allowedHosts: ["api.example.com"],
        endpoints: [
          {
            id: "getOrder",
            method: "GET",
            pathPattern: "/v1/orders/:id",
            requiredScopes: ["orders:read"]
          }
        ]
      }
    });
    const getAction: AgentAction = {
      surface: "api",
      actionId: "act-read-api",
      method: "GET",
      url: "https://api.example.com/v1/orders/ORD-9001"
    };
    const getDecision = firewall.evaluate(getAction, getState);
    expect(getDecision.verdict).toBe("ALLOW");
  });

  it("trips the circuit breaker after consecutive blocked actions and recovers on reset", () => {
    const firewall = new ActionFirewall({
      circuitBreakerThreshold: 3,
      nowMs: () => now
    });
    const state = createBaseState();
    const badAction: AgentAction = {
      surface: "ui",
      actionId: "act-bad",
      actionType: "click",
      selector: "#non-existent-btn"
    };

    expect(firewall.evaluate(badAction, state).reasonCodes).toContain(
      "UI_ELEMENT_NOT_FOUND"
    );
    expect(firewall.evaluate(badAction, state).reasonCodes).toContain(
      "UI_ELEMENT_NOT_FOUND"
    );
    expect(firewall.evaluate(badAction, state).reasonCodes).toContain(
      "UI_ELEMENT_NOT_FOUND"
    );

    // 4th attempt should short-circuit with CIRCUIT_BREAKER_OPEN
    const validAction: AgentAction = {
      surface: "ui",
      actionId: "act-good-after-trip",
      actionType: "click",
      selector: "#pay-now"
    };
    const trippedDecision = firewall.evaluate(validAction, state);
    expect(trippedDecision.verdict).toBe("BLOCK");
    expect(trippedDecision.reasonCodes).toEqual(["CIRCUIT_BREAKER_OPEN"]);

    // Reset circuit breaker and verify recovery
    firewall.resetCircuitBreaker();
    const recoveredDecision = firewall.evaluate(validAction, state);
    expect(recoveredDecision.verdict).toBe("ALLOW");
  });

  it("serves out-of-band HTTP interception evaluations on /v1/evaluate and verifies audit ledger", async () => {
    const handle = await startFirewallServer({
      port: 0,
      host: "127.0.0.1",
      apiKey: "test-ephemeral-gate-key"
    });

    try {
      const baseUrl = `http://127.0.0.1:${handle.port}`;

      // Healthz requires no API key
      const healthRes = await fetch(`${baseUrl}/healthz`);
      expect(healthRes.status).toBe(200);
      const healthBody = (await healthRes.json()) as {
        status: string;
        auditChainValid: boolean;
      };
      expect(healthBody.status).toBe("ok");
      expect(healthBody.auditChainValid).toBe(true);

      // Unauthorized without X-API-Key
      const unauthRes = await fetch(`${baseUrl}/v1/audit`);
      expect(unauthRes.status).toBe(401);

      // Valid evaluation via HTTP POST
      const liveNow = Date.now();
      const liveState = createBaseState({
        capturedAtMs: liveNow,
        session: {
          principalId: "runner-http-01",
          authenticated: true,
          expiresAtMs: liveNow + 3_600_000,
          scopes: ["orders:read", "orders:write", "ui:interact"]
        }
      });
      const evalRes = await fetch(`${baseUrl}/v1/evaluate?strictHttpStatus=true`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": "test-ephemeral-gate-key"
        },
        body: JSON.stringify({
          action: {
            surface: "ui",
            actionId: "http-ui-1",
            actionType: "click",
            selector: "#pay-now"
          },
          state: liveState
        })
      });
      expect(evalRes.status).toBe(200);
      expect(evalRes.headers.get("x-firewall-verdict")).toBe("ALLOW");

      // Blocked SSRF evaluation with strictHttpStatus=true returns 403
      const ssrfRes = await fetch(`${baseUrl}/v1/evaluate?strictHttpStatus=true`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": "test-ephemeral-gate-key"
        },
        body: JSON.stringify({
          action: {
            surface: "api",
            actionId: "http-api-ssrf",
            method: "GET",
            url: "http://169.254.169.254/latest/meta-data/"
          },
          state: { ...liveState, capturedAtMs: Date.now() }
        })
      });
      expect(ssrfRes.status).toBe(403);
      const ssrfDecision = (await ssrfRes.json()) as {
        verdict: string;
        reasonCodes: string[];
      };
      expect(ssrfDecision.verdict).toBe("BLOCK");
      expect(ssrfDecision.reasonCodes).toContain("API_SSRF_LOOPBACK_OR_METADATA");

      // Verify audit chain over HTTP
      const verifyRes = await fetch(`${baseUrl}/v1/audit/verify`, {
        headers: { "X-API-Key": "test-ephemeral-gate-key" }
      });
      expect(verifyRes.status).toBe(200);
      const verifyReport = (await verifyRes.json()) as {
        valid: boolean;
        checked: number;
      };
      expect(verifyReport.valid).toBe(true);
      expect(verifyReport.checked).toBe(2);

      // Hot-reload Control-Plane Policy Pack via PUT /v1/policy
      const policyUpdateRes = await fetch(`${baseUrl}/v1/policy`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": "test-ephemeral-gate-key"
        },
        body: JSON.stringify({
          policyVersion: "2026.11.0-enterprise",
          globalTaintedDomains: ["exfil-sink.example.org"]
        })
      });
      expect(policyUpdateRes.status).toBe(200);

      const policyGetRes = await fetch(`${baseUrl}/v1/policy`, {
        headers: { "X-API-Key": "test-ephemeral-gate-key" }
      });
      const policyPayload = (await policyGetRes.json()) as {
        policyPack: { policyVersion: string };
      };
      expect(policyPayload.policyPack.policyVersion).toBe("2026.11.0-enterprise");
    } finally {
      await handle.close();
    }
  });

  it("wraps universal agent tool calls via guardToolCall and streams SIEM audit entries out-of-band", async () => {
    const streamedEntries: AuditEntry[] = [];
    const firewall = new ActionFirewall({
      nowMs: () => now,
      policyPack: {
        policyVersion: "v1.2-control-plane",
        globalTaintedDomains: ["untrusted-rag-domain.example.net"]
      },
      onAuditEntry: (entry) => {
        streamedEntries.push(entry);
      }
    });

    const state = createBaseState();

    // 1. Allowed tool call executes callback
    let executed = false;
    const { result, decision } = await firewall.guardToolCall(
      {
        surface: "api",
        actionId: "mcp-tool-1",
        method: "POST",
        url: "https://api.example.com/v1/orders",
        headers: { "Idempotency-Key": "idem-mcp-9001" },
        body: { orderId: "ORD-7712", amountCents: 4500 }
      },
      state,
      () => {
        executed = true;
        return { orderStatus: "created" };
      }
    );
    expect(executed).toBe(true);
    expect(result.orderStatus).toBe("created");
    expect(decision.verdict).toBe("ALLOW");

    // 2. Blocked tool call (hitting Control-Plane globalTaintedDomains) throws FirewallBlockedError without executing callback
    let blockedCallbackRan = false;
    await expect(
      firewall.guardToolCall(
        {
          surface: "api",
          actionId: "mcp-tool-2",
          method: "POST",
          url: "https://untrusted-rag-domain.example.net/webhook"
        },
        state,
        () => {
          blockedCallbackRan = true;
          return { ok: true };
        }
      )
    ).rejects.toBeInstanceOf(FirewallBlockedError);
    expect(blockedCallbackRan).toBe(false);

    // Allow microtask queue to flush SIEM telemetry sink
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(streamedEntries).toHaveLength(2);
    expect(streamedEntries[0]?.verdict).toBe("ALLOW");
    expect(streamedEntries[1]?.verdict).toBe("BLOCK");
    expect(streamedEntries[1]?.reasonCodes).toContain("API_TAINTED_SINK_DOMAIN");
  });

  it("serves the Web Console UI, seeds demo traffic, computes dashboard stats, and detects simulated audit tampering", async () => {
    const handle = await startFirewallServer({
      port: 0,
      host: "127.0.0.1"
    });

    try {
      const baseUrl = `http://127.0.0.1:${handle.port}`;

      // 1. Web Console HTML served at /
      const uiRes = await fetch(`${baseUrl}/`);
      expect(uiRes.status).toBe(200);
      expect(uiRes.headers.get("content-type")).toContain("text/html");
      const html = await uiRes.text();
      expect(html).toContain("Zero-Trust Agent Firewall");

      // 2. Seed 8-step multi-surface demo traffic
      const seedRes = await fetch(`${baseUrl}/v1/demo/seed`, { method: "POST" });
      expect(seedRes.status).toBe(200);

      // 3. Dashboard stats reflect allowed, blocked, and held actions
      const statsRes = await fetch(`${baseUrl}/v1/stats`);
      expect(statsRes.status).toBe(200);
      const stats = (await statsRes.json()) as {
        total: number;
        allowCount: number;
        blockCount: number;
        holdCount: number;
        auditChain: { valid: boolean };
      };
      expect(stats.total).toBe(8);
      expect(stats.allowCount).toBe(3);
      expect(stats.blockCount).toBe(4);
      expect(stats.holdCount).toBe(1);
      expect(stats.auditChain.valid).toBe(true);

      // 4. Non-destructive tamper simulation proves SHA-256 verification catches altered records
      const tamperRes = await fetch(`${baseUrl}/v1/audit/tamper-test`, {
        method: "POST"
      });
      const tamperReport = (await tamperRes.json()) as {
        simulated: boolean;
        valid: boolean;
      };
      expect(tamperReport.simulated).toBe(true);
      expect(tamperReport.valid).toBe(false);

      // Real ledger remains untouched and valid
      const realAuditCheck = await (await fetch(`${baseUrl}/v1/audit/verify`)).json();
      expect((realAuditCheck as { valid: boolean }).valid).toBe(true);

      // 5. Ephemeral 1,000-action benchmark endpoint
      const benchRes = await fetch(`${baseUrl}/v1/benchmark/run`, { method: "POST" });
      const bench = (await benchRes.json()) as {
        iterations: number;
        p99Ms: number;
        chainValid: boolean;
      };
      expect(bench.iterations).toBe(1000);
      expect(bench.p99Ms).toBeLessThan(10);
      expect(bench.chainValid).toBe(true);
    } finally {
      await handle.close();
    }
  });
});
