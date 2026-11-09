import fs from "node:fs";
import { ActionFirewall } from "./firewall/ActionFirewall.js";
import { AuditLedger } from "./audit/auditLedger.js";
import { startFirewallServer } from "./server.js";
import type { AgentAction, SystemStateSnapshot } from "./types/index.js";

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((p / 100) * sorted.length) - 1)
  );
  return sorted[idx] ?? 0;
}

function runBenchmark(iterations = 3000): void {
  const firewall = new ActionFirewall({
    circuitBreakerThreshold: 100000
  });

  const now = Date.now();
  const state: SystemStateSnapshot = {
    snapshotId: "snap-bench-001",
    capturedAtMs: now,
    maxStalenessMs: 60_000,
    session: {
      principalId: "runner-bench-001",
      authenticated: true,
      expiresAtMs: now + 3_600_000,
      scopes: ["orders:read", "orders:write", "ui:interact"],
      dbLockActive: false,
      readOnlyMode: false
    },
    dom: {
      currentUrl: "https://portal.example.com/orders",
      elements: [
        {
          selector: "#submit-order",
          testId: "submit-order-btn",
          role: "button",
          tagName: "button",
          name: "Submit Order",
          visible: true,
          enabled: true
        },
        {
          selector: "#disabled-archive",
          testId: "archive-btn",
          role: "button",
          tagName: "button",
          name: "Archive",
          visible: true,
          enabled: false
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
            sku: { type: "string", required: true, minLength: 3 },
            quantity: { type: "integer", required: true, minimum: 1, maximum: 100 }
          }
        }
      ]
    },
    cliPolicy: {
      allowedExecutables: ["git", "playwright", "vitest", "tsc"],
      allowedWorkdirs: ["/workspace/app"]
    }
  };

  const sampleActions: AgentAction[] = [
    {
      surface: "ui",
      actionId: "act-ui-allow",
      actionType: "click",
      selector: "#submit-order"
    },
    {
      surface: "ui",
      actionId: "act-ui-block",
      actionType: "click",
      selector: "#disabled-archive"
    },
    {
      surface: "api",
      actionId: "act-api-allow",
      method: "POST",
      url: "https://api.example.com/v1/orders",
      headers: { "Idempotency-Key": "idem-99102-bench" },
      body: { sku: "SKU-401", quantity: 2 }
    },
    {
      surface: "api",
      actionId: "act-api-ssrf",
      method: "GET",
      url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    },
    {
      surface: "cli",
      actionId: "act-cli-allow",
      executable: "playwright",
      args: ["test", "tests/checkout.spec.ts"],
      cwd: "/workspace/app"
    },
    {
      surface: "cli",
      actionId: "act-cli-block",
      executable: "git",
      args: ["status; cat /etc/passwd"],
      cwd: "/workspace/app"
    }
  ];

  // Warmup
  for (let i = 0; i < 100; i += 1) {
    const action = sampleActions[i % sampleActions.length]!;
    firewall.evaluate(action, { ...state, capturedAtMs: Date.now() });
  }

  const benchmarkFirewall = new ActionFirewall({
    circuitBreakerThreshold: 100000
  });
  const latencies: number[] = [];
  let allowedCount = 0;
  let blockedCount = 0;

  const startWall = performance.now();
  for (let i = 0; i < iterations; i += 1) {
    const template = sampleActions[i % sampleActions.length]!;
    const action: AgentAction = {
      ...template,
      actionId: `${template.actionId}-${i}`
    };
    const decision = benchmarkFirewall.evaluate(action, {
      ...state,
      capturedAtMs: Date.now()
    });
    latencies.push(decision.evaluationLatencyMs);
    if (decision.verdict === "ALLOW") allowedCount += 1;
    else blockedCount += 1;
  }
  const totalWallMs = performance.now() - startWall;

  latencies.sort((a, b) => a - b);
  const p50 = percentile(latencies, 50);
  const p95 = percentile(latencies, 95);
  const p99 = percentile(latencies, 99);
  const max = latencies[latencies.length - 1] ?? 0;
  const chainReport = benchmarkFirewall.verifyAuditChain();

  console.log("==============================================================");
  console.log(" Zero-Trust Agent Firewall - Sub-10ms State Cage Benchmark");
  console.log("==============================================================");
  console.log(`Total Evaluations : ${iterations}`);
  console.log(`Decisions         : ${allowedCount} ALLOW / ${blockedCount} BLOCK`);
  console.log(`Total Wall Time   : ${totalWallMs.toFixed(2)} ms`);
  console.log(
    `Throughput        : ${Math.round((iterations / totalWallMs) * 1000).toLocaleString()} actions/sec`
  );
  console.log("--------------------------------------------------------------");
  console.log(`Latency p50       : ${p50.toFixed(3)} ms`);
  console.log(`Latency p95       : ${p95.toFixed(3)} ms`);
  console.log(`Latency p99       : ${p99.toFixed(3)} ms  (Target SLA: < 10.000 ms)`);
  console.log(`Latency Max       : ${max.toFixed(3)} ms`);
  console.log("--------------------------------------------------------------");
  console.log(
    `Audit Chain Valid : ${chainReport.valid} (${chainReport.checked} SHA-256 linked blocks)`
  );
  console.log(`Chain Head Hash   : ${chainReport.headHash}`);
  console.log("==============================================================");

  if (p99 >= 10 || !chainReport.valid) {
    process.exitCode = 1;
  }
}

async function main(): Promise<void> {
  const [command = "serve", arg1] = process.argv.slice(2);

  if (command === "benchmark") {
    const count = arg1 ? Number(arg1) : 3000;
    runBenchmark(Number.isFinite(count) && count > 0 ? count : 3000);
    return;
  }

  if (command === "verify-audit") {
    if (!arg1) {
      console.error("Usage: agent-firewall verify-audit <path-to-audit.jsonl>");
      process.exit(1);
    }
    const content = fs.readFileSync(arg1, "utf8");
    const report = AuditLedger.verifyJsonl(content);
    console.log(JSON.stringify(report, null, 2));
    if (!report.valid) {
      process.exit(1);
    }
    return;
  }

  if (command === "serve") {
    const handle = await startFirewallServer();
    console.log(
      `[Zero-Trust Agent Firewall] Listening on http://localhost:${handle.port}`
    );
    return;
  }

  console.error(
    `Unknown command '${command}'. Supported commands: serve | benchmark | verify-audit`
  );
  process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
