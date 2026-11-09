import crypto from "node:crypto";
import http from "node:http";
import { performance } from "node:perf_hooks";
import { URL } from "node:url";
import { z } from "zod";
import { AuditLedger } from "./audit/auditLedger.js";
import { ActionFirewall } from "./firewall/ActionFirewall.js";
import type {
  AgentAction,
  AuditEntry,
  ControlPlanePolicyPack,
  FirewallConfig,
  SystemStateSnapshot
} from "./types/index.js";
import { renderConsoleHtml } from "./ui/consoleApp.js";

const DEFAULT_CONSOLE_POLICY_PACK: ControlPlanePolicyPack = {
  policyVersion: "2026.11-balanced",
  maxEvaluationLatencyMs: 10,
  defaultMaxStalenessMs: 5000,
  disallowBrittleSelectors: true,
  circuitBreakerThreshold: 5,
  globalTaintedDomains: ["exfil-drop.example.org"],
  defaultAllowedOrigins: ["https://portal.example.com", "https://app.example.com"],
  defaultApiContracts: {
    allowedHosts: ["orders-api.example.com", "api.example.com"],
    requireRegisteredEndpoint: true,
    endpoints: [
      {
        id: "createOrder",
        method: "POST",
        pathPattern: "/v1/orders",
        requiredScopes: ["orders:write"],
        requireIdempotencyKey: true,
        bodySchema: {
          sku: { type: "string", required: true, pattern: "^SKU-[0-9]{3}$" },
          quantity: { type: "integer", required: true, minimum: 1, maximum: 50 }
        }
      },
      {
        id: "getOrder",
        method: "GET",
        pathPattern: "/v1/orders/:id",
        requiredScopes: ["orders:read"]
      }
    ]
  },
  defaultCliPolicy: {
    allowedExecutables: ["git", "playwright", "vitest", "tsc"],
    allowedWorkdirs: ["/workspace/project"]
  }
};

const UiActionSchema = z.object({
  surface: z.literal("ui"),
  actionId: z.string().optional(),
  actionType: z.enum([
    "click",
    "dblclick",
    "fill",
    "select",
    "check",
    "uncheck",
    "hover",
    "press",
    "navigate"
  ]),
  selector: z.string().optional(),
  targetUrl: z.string().optional(),
  value: z.string().optional(),
  confirmationToken: z.string().optional()
});

const ApiActionSchema = z.object({
  surface: z.literal("api"),
  actionId: z.string().optional(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
  url: z.string().min(1),
  headers: z.record(z.string(), z.string()).optional(),
  query: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  body: z.unknown().optional(),
  operationId: z.string().optional()
});

const CliActionSchema = z.object({
  surface: z.literal("cli"),
  actionId: z.string().optional(),
  executable: z.string().min(1),
  args: z.array(z.string()),
  cwd: z.string().optional(),
  env: z.record(z.string(), z.string()).optional()
});

const AgentActionSchema = z.discriminatedUnion("surface", [
  UiActionSchema,
  ApiActionSchema,
  CliActionSchema
]);

const SystemStateSnapshotSchema = z.object({
  snapshotId: z.string().min(1),
  capturedAtMs: z.number(),
  maxStalenessMs: z.number().positive().optional(),
  taintedDomains: z.array(z.string()).optional(),
  session: z
    .object({
      authenticated: z.boolean(),
      principalId: z.string().optional(),
      expiresAtMs: z.number().optional(),
      scopes: z.array(z.string()),
      dbLockActive: z.boolean().optional(),
      readOnlyMode: z.boolean().optional()
    })
    .optional(),
  dom: z
    .object({
      currentUrl: z.string(),
      allowedOrigins: z.array(z.string()).optional(),
      activeModalSelector: z.string().optional(),
      elements: z.array(
        z.object({
          selector: z.string(),
          testId: z.string().optional(),
          role: z.string().optional(),
          name: z.string().optional(),
          tagName: z.string().optional(),
          visible: z.boolean(),
          enabled: z.boolean(),
          readonly: z.boolean().optional(),
          ariaBusy: z.boolean().optional(),
          inActiveModal: z.boolean().optional(),
          obscuredBy: z.string().optional(),
          destructive: z.boolean().optional()
        })
      )
    })
    .optional(),
  apiContracts: z
    .object({
      allowedHosts: z.array(z.string()),
      allowPrivateNetwork: z.boolean().optional(),
      requireRegisteredEndpoint: z.boolean().optional(),
      endpoints: z.array(
        z.object({
          id: z.string(),
          method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
          pathPattern: z.string(),
          requiredScopes: z.array(z.string()).optional(),
          requireIdempotencyKey: z.boolean().optional(),
          bodySchema: z.any().optional(),
          querySchema: z.any().optional()
        })
      )
    })
    .optional(),
  cliPolicy: z
    .object({
      allowedExecutables: z.array(z.string()),
      allowedWorkdirs: z.array(z.string()),
      maxArgLength: z.number().optional(),
      allowNetworkTools: z.boolean().optional()
    })
    .optional()
});

const ControlPlanePolicyPackSchema = z.object({
  policyVersion: z.string().min(1),
  updatedAtIso: z.string().optional(),
  maxEvaluationLatencyMs: z.number().positive().optional(),
  defaultMaxStalenessMs: z.number().positive().optional(),
  disallowBrittleSelectors: z.boolean().optional(),
  circuitBreakerThreshold: z.number().nonnegative().optional(),
  defaultAllowedOrigins: z.array(z.string()).optional(),
  defaultApiContracts: z
    .object({
      allowedHosts: z.array(z.string()),
      allowPrivateNetwork: z.boolean().optional(),
      requireRegisteredEndpoint: z.boolean().optional(),
      endpoints: z.array(
        z.object({
          id: z.string(),
          method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
          pathPattern: z.string(),
          requiredScopes: z.array(z.string()).optional(),
          requireIdempotencyKey: z.boolean().optional(),
          bodySchema: z.any().optional(),
          querySchema: z.any().optional()
        })
      )
    })
    .optional(),
  defaultCliPolicy: z
    .object({
      allowedExecutables: z.array(z.string()),
      allowedWorkdirs: z.array(z.string()),
      maxArgLength: z.number().optional(),
      allowNetworkTools: z.boolean().optional()
    })
    .optional(),
  globalTaintedDomains: z.array(z.string()).optional()
});

const EvaluateRequestSchema = z.object({
  action: AgentActionSchema,
  state: SystemStateSnapshotSchema
});

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)
  );
  return sorted[idx] ?? 0;
}

function seedDemoTraffic(firewall: ActionFirewall): void {
  // Warm up V8 JIT & schema cache on an isolated instance so demo latencies reflect steady state
  runEphemeralBenchmark(40);
  firewall.resetCircuitBreaker();
  const now = Date.now();

  const baseState = (): SystemStateSnapshot => ({
    snapshotId: `snap-demo-${Date.now()}`,
    capturedAtMs: Date.now(),
    maxStalenessMs: 5000,
    session: {
      principalId: "worker-01",
      authenticated: true,
      expiresAtMs: now + 3_600_000,
      scopes: ["orders:read", "orders:write", "ui:interact"],
      dbLockActive: false,
      readOnlyMode: false
    },
    dom: {
      currentUrl: "https://portal.example.com/settings",
      activeModalSelector: "#confirm-dialog",
      elements: [
        {
          selector: "#save-settings-btn",
          testId: "save-settings",
          role: "button",
          name: "Save Changes",
          visible: true,
          enabled: true,
          inActiveModal: false
        },
        {
          selector: "#modal-confirm-btn",
          role: "button",
          name: "Confirm",
          visible: true,
          enabled: true,
          inActiveModal: true
        },
        {
          selector: "#delete-workspace-btn",
          role: "button",
          name: "Delete Workspace",
          visible: true,
          enabled: true,
          inActiveModal: true,
          destructive: true
        }
      ]
    }
  });

  const demoSequence: Array<{ action: AgentAction; state: SystemStateSnapshot }> = [
    {
      action: {
        surface: "api",
        actionId: "demo-1",
        method: "POST",
        url: "https://orders-api.example.com/v1/orders",
        headers: { "Idempotency-Key": "idem-demo-1001" },
        body: { sku: "SKU-204", quantity: 2 }
      },
      state: baseState()
    },
    {
      action: {
        surface: "api",
        actionId: "demo-2",
        method: "GET",
        url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
      },
      state: baseState()
    },
    {
      action: {
        surface: "cli",
        actionId: "demo-3",
        executable: "vitest",
        args: ["run", "tests/guards.test.ts"],
        cwd: "/workspace/project"
      },
      state: baseState()
    },
    {
      action: {
        surface: "cli",
        actionId: "demo-4",
        executable: "git",
        args: ["--upload-pack=touch /tmp/test", "status; cat /etc/passwd"],
        cwd: "/workspace/project"
      },
      state: baseState()
    },
    {
      action: {
        surface: "ui",
        actionId: "demo-5",
        actionType: "click",
        selector: 'role=button[name="Confirm"]'
      },
      state: baseState()
    },
    {
      action: {
        surface: "ui",
        actionId: "demo-6",
        actionType: "click",
        selector: "#save-settings-btn"
      },
      state: baseState()
    },
    {
      action: {
        surface: "ui",
        actionId: "demo-7",
        actionType: "click",
        selector: "#delete-workspace-btn"
      },
      state: baseState()
    },
    {
      action: {
        surface: "api",
        actionId: "demo-8",
        method: "POST",
        url: "https://orders-api.example.com/v1/orders",
        body: { sku: "INVALID", quantity: 900 }
      },
      state: baseState()
    }
  ];

  for (const step of demoSequence) {
    firewall.evaluate(step.action, step.state);
  }
}

function runEphemeralBenchmark(iterations = 1000) {
  const benchFw = new ActionFirewall({
    circuitBreakerThreshold: 100000,
    policyPack: DEFAULT_CONSOLE_POLICY_PACK
  });
  const now = Date.now();
  const state: SystemStateSnapshot = {
    snapshotId: "snap-bench-ui",
    capturedAtMs: now,
    session: {
      principalId: "bench-worker",
      authenticated: true,
      expiresAtMs: now + 3_600_000,
      scopes: ["orders:read", "orders:write"]
    },
    dom: {
      currentUrl: "https://portal.example.com/orders",
      elements: [
        {
          selector: "#submit-order",
          role: "button",
          name: "Submit",
          visible: true,
          enabled: true
        }
      ]
    }
  };

  const actions: AgentAction[] = [
    { surface: "ui", actionType: "click", selector: "#submit-order" },
    {
      surface: "api",
      method: "POST",
      url: "https://orders-api.example.com/v1/orders",
      headers: { "Idempotency-Key": "idem-bench-9901" },
      body: { sku: "SKU-101", quantity: 1 }
    },
    {
      surface: "api",
      method: "GET",
      url: "http://169.254.169.254/latest/meta-data/"
    },
    {
      surface: "cli",
      executable: "git",
      args: ["status; id"],
      cwd: "/workspace/project"
    }
  ];

  const latencies: number[] = [];
  const startWall = performance.now();
  for (let i = 0; i < iterations; i += 1) {
    const d = benchFw.evaluate(actions[i % actions.length]!, {
      ...state,
      capturedAtMs: Date.now()
    });
    latencies.push(d.evaluationLatencyMs);
  }
  const totalWallMs = performance.now() - startWall;
  latencies.sort((a, b) => a - b);

  return {
    iterations,
    p50Ms: percentile(latencies, 50),
    p95Ms: percentile(latencies, 95),
    p99Ms: percentile(latencies, 99),
    maxMs: latencies[latencies.length - 1] ?? 0,
    totalWallMs,
    throughputPerSec: Math.round((iterations / Math.max(totalWallMs, 0.1)) * 1000),
    chainValid: benchFw.verifyAuditChain().valid
  };
}

export interface FirewallServerOptions {
  port?: number;
  host?: string;
  apiKey?: string;
  maxBodyBytes?: number;
  config?: FirewallConfig;
  firewall?: ActionFirewall;
}

export interface FirewallServerHandle {
  server: http.Server;
  firewall: ActionFirewall;
  port: number;
  close: () => Promise<void>;
}

/**
 * Out-of-band HTTP service & interactive Runtime Console separated from pure domain logic.
 */
export async function startFirewallServer(
  options: FirewallServerOptions = {}
): Promise<FirewallServerHandle> {
  const envLatency = Number(process.env.FIREWALL_MAX_LATENCY_MS);
  const envStaleness = Number(process.env.FIREWALL_MAX_STATE_STALENESS_MS);
  const envBreaker = Number(process.env.FIREWALL_CIRCUIT_BREAKER_THRESHOLD);

  const defaultPackWithOverrides: ControlPlanePolicyPack = {
    ...DEFAULT_CONSOLE_POLICY_PACK,
    maxEvaluationLatencyMs:
      options.config?.maxEvaluationLatencyMs ??
      (Number.isFinite(envLatency) && envLatency > 0
        ? envLatency
        : DEFAULT_CONSOLE_POLICY_PACK.maxEvaluationLatencyMs),
    defaultMaxStalenessMs:
      options.config?.defaultMaxStalenessMs ??
      (Number.isFinite(envStaleness) && envStaleness > 0
        ? envStaleness
        : DEFAULT_CONSOLE_POLICY_PACK.defaultMaxStalenessMs),
    circuitBreakerThreshold:
      options.config?.circuitBreakerThreshold ??
      (Number.isFinite(envBreaker) && envBreaker >= 0
        ? envBreaker
        : DEFAULT_CONSOLE_POLICY_PACK.circuitBreakerThreshold)
  };

  const effectiveConfig: FirewallConfig = {
    ...options.config,
    policyPack: options.config?.policyPack ?? defaultPackWithOverrides
  };
  const firewall = options.firewall ?? new ActionFirewall(effectiveConfig);
  const maxBodyBytes = options.maxBodyBytes ?? 256 * 1024;
  const configuredApiKey =
    options.apiKey ?? (process.env.FIREWALL_API_KEY?.trim() || undefined);

  const isValidApiKey = (provided: string | string[] | undefined): boolean => {
    if (!configuredApiKey) return true;
    if (typeof provided !== "string") return false;
    const expectedBuf = Buffer.from(configuredApiKey, "utf8");
    const providedBuf = Buffer.from(provided, "utf8");
    if (expectedBuf.length !== providedBuf.length) return false;
    return crypto.timingSafeEqual(expectedBuf, providedBuf);
  };

  const sendJson = (
    res: http.ServerResponse,
    statusCode: number,
    payload: unknown,
    extraHeaders: Record<string, string> = {}
  ): void => {
    const body = JSON.stringify(payload);
    res.writeHead(statusCode, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders
    });
    res.end(body);
  };

  const readJsonBody = (req: http.IncomingMessage): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      req.on("data", (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > maxBodyBytes) {
          reject(new Error("PAYLOAD_TOO_LARGE"));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => {
        try {
          const raw = Buffer.concat(chunks).toString("utf8");
          resolve(raw.length > 0 ? JSON.parse(raw) : {});
        } catch {
          reject(new Error("INVALID_JSON"));
        }
      });
      req.on("error", reject);
    });

  const server = http.createServer(async (req, res) => {
    const method = req.method ?? "GET";
    const parsedUrl = new URL(req.url ?? "/", "http://localhost");
    const pathname = parsedUrl.pathname;

    // Serve Web Console at root
    if (method === "GET" && pathname === "/") {
      const html = renderConsoleHtml();
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store"
      });
      res.end(html);
      return;
    }

    if (configuredApiKey && pathname !== "/healthz") {
      if (!isValidApiKey(req.headers["x-api-key"])) {
        sendJson(res, 401, {
          error: "UNAUTHORIZED",
          message: "Missing or invalid X-API-Key header."
        });
        return;
      }
    }

    if (method === "GET" && pathname === "/healthz") {
      const verification = firewall.verifyAuditChain();
      sendJson(res, 200, {
        status: "ok",
        service: "zero-trust-agent-firewall",
        version: "1.0.0",
        auditChainValid: verification.valid,
        ledgerSize: verification.checked
      });
      return;
    }

    if (method === "GET" && pathname === "/v1/stats") {
      const entries = firewall.getAuditEntries();
      const verification = firewall.verifyAuditChain();
      let allowCount = 0;
      let blockCount = 0;
      let holdCount = 0;
      let latencySum = 0;
      const latencies: number[] = [];
      const bySurface: Record<string, number> = { api: 0, cli: 0, ui: 0 };
      const reasonCounts = new Map<string, number>();

      for (const e of entries) {
        if (e.verdict === "ALLOW") allowCount += 1;
        else if (e.verdict === "BLOCK") blockCount += 1;
        else if (e.verdict === "HOLD") holdCount += 1;

        latencySum += e.evaluationLatencyMs;
        latencies.push(e.evaluationLatencyMs);
        bySurface[e.actionSurface] = (bySurface[e.actionSurface] ?? 0) + 1;
        for (const r of e.reasonCodes) {
          reasonCounts.set(r, (reasonCounts.get(r) ?? 0) + 1);
        }
      }

      latencies.sort((a, b) => a - b);
      const topReasons = Array.from(reasonCounts.entries())
        .map(([code, count]) => ({ code, count }))
        .sort((a, b) => b.count - a.count);

      const threshold = firewall.getCircuitBreakerThreshold();
      const consecutiveBlocks = firewall.getConsecutiveBlocks();

      sendJson(res, 200, {
        total: entries.length,
        allowCount,
        blockCount,
        holdCount,
        avgLatencyMs: entries.length > 0 ? latencySum / entries.length : 0,
        p99LatencyMs: percentile(latencies, 99),
        bySurface,
        topReasons,
        consecutiveBlocks,
        circuitBreakerThreshold: threshold,
        circuitBreakerOpen: threshold > 0 && consecutiveBlocks >= threshold,
        auditChain: verification
      });
      return;
    }

    if (method === "POST" && pathname === "/v1/demo/seed") {
      seedDemoTraffic(firewall);
      sendJson(res, 200, { status: "seeded", total: firewall.getAuditEntries().length });
      return;
    }

    if (method === "POST" && pathname === "/v1/benchmark/run") {
      sendJson(res, 200, runEphemeralBenchmark(1000));
      return;
    }

    if (method === "POST" && pathname === "/v1/audit/tamper-test") {
      const entries = firewall.getAuditEntries();
      if (entries.length === 0) {
        sendJson(res, 200, {
          simulated: false,
          message: "Audit ledger is empty. Evaluate at least one action or click 'Simulate Traffic' first."
        });
        return;
      }

      const cloned: AuditEntry[] = entries.map((e) => ({ ...e, reasonCodes: [...e.reasonCodes] }));
      const targetIdx = cloned.findIndex((e) => e.verdict === "BLOCK");
      const mutateIdx = targetIdx >= 0 ? targetIdx : 0;
      const target = cloned[mutateIdx]!;
      cloned[mutateIdx] = {
        ...target,
        verdict: target.verdict === "ALLOW" ? "BLOCK" : "ALLOW"
      };

      const verifier = new AuditLedger();
      const report = verifier.verifyChain(cloned);
      sendJson(res, 200, {
        simulated: true,
        ...report
      });
      return;
    }

    if (method === "POST" && pathname === "/v1/evaluate") {
      let rawBody: unknown;
      try {
        rawBody = await readJsonBody(req);
      } catch (err) {
        const code = err instanceof Error ? err.message : "BAD_REQUEST";
        sendJson(res, code === "PAYLOAD_TOO_LARGE" ? 413 : 400, {
          error: code,
          message:
            code === "PAYLOAD_TOO_LARGE"
              ? `Request body exceeds ${maxBodyBytes} bytes.`
              : "Request body must be valid JSON."
        });
        return;
      }

      const parsed = EvaluateRequestSchema.safeParse(rawBody);
      if (!parsed.success) {
        sendJson(res, 422, {
          error: "VALIDATION_ERROR",
          issues: parsed.error.issues.map((issue) => ({
            path: issue.path.join("."),
            message: issue.message
          }))
        });
        return;
      }

      const decision = firewall.evaluate(
        parsed.data.action as AgentAction,
        parsed.data.state as SystemStateSnapshot
      );

      const strictHttp = parsedUrl.searchParams.get("strictHttpStatus") === "true";
      const statusCode =
        strictHttp && decision.verdict === "BLOCK"
          ? 403
          : strictHttp && decision.verdict === "HOLD"
            ? 428
            : 200;

      sendJson(res, statusCode, decision, {
        "X-Firewall-Verdict": decision.verdict,
        "X-Firewall-Audit-Hash": decision.auditEntryHash
      });
      return;
    }

    if (method === "GET" && pathname === "/v1/audit") {
      sendJson(res, 200, {
        entries: firewall.getAuditEntries(),
        verification: firewall.verifyAuditChain()
      });
      return;
    }

    if (method === "GET" && pathname === "/v1/audit/verify") {
      sendJson(res, 200, firewall.verifyAuditChain());
      return;
    }

    if (method === "GET" && pathname === "/v1/policy") {
      sendJson(res, 200, {
        policyPack: firewall.getPolicyPack() ?? null
      });
      return;
    }

    if (method === "PUT" && pathname === "/v1/policy") {
      let rawBody: unknown;
      try {
        rawBody = await readJsonBody(req);
      } catch {
        sendJson(res, 400, { error: "INVALID_JSON" });
        return;
      }
      const parsed = ControlPlanePolicyPackSchema.safeParse(rawBody);
      if (!parsed.success) {
        sendJson(res, 422, {
          error: "VALIDATION_ERROR",
          issues: parsed.error.issues.map((issue) => ({
            path: issue.path.join("."),
            message: issue.message
          }))
        });
        return;
      }
      firewall.loadPolicyPack(parsed.data as ControlPlanePolicyPack);
      sendJson(res, 200, {
        status: "updated",
        policyVersion: parsed.data.policyVersion
      });
      return;
    }

    if (method === "POST" && pathname === "/v1/circuit-breaker/reset") {
      firewall.resetCircuitBreaker();
      sendJson(res, 200, { status: "reset" });
      return;
    }

    sendJson(res, 404, {
      error: "NOT_FOUND",
      message: `Route ${method} ${pathname} not found.`
    });
  });

  const requestedPort =
    options.port ?? (Number(process.env.FIREWALL_PORT) || 4100);
  const host = options.host ?? process.env.FIREWALL_HOST ?? "127.0.0.1";

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, host, () => resolve());
  });

  const address = server.address();
  const actualPort =
    typeof address === "object" && address !== null ? address.port : requestedPort;

  return {
    server,
    firewall,
    port: actualPort,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      })
  };
}
