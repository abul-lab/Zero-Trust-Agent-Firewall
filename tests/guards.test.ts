import { describe, expect, it } from "vitest";
import {
  evaluateApiPayload,
  evaluateCliCommand,
  evaluateUiAction,
  isInternalOrMetadataHost,
  parseDomState,
  type ApiActionPayload,
  type CliActionPayload,
  type SystemStateSnapshot,
  type UiActionPayload
} from "../src/index.js";

function makeState(overrides: Partial<SystemStateSnapshot> = {}): SystemStateSnapshot {
  const now = 1_700_000_000_000;
  return {
    snapshotId: "snap-guards-01",
    capturedAtMs: now,
    session: {
      principalId: "sess-guards-01",
      authenticated: true,
      expiresAtMs: now + 3_600_000,
      scopes: ["orders:read", "orders:write"]
    },
    dom: {
      currentUrl: "https://portal.example.com/settings",
      elements: [
        {
          selector: "#save-btn",
          testId: "save-settings",
          role: "button",
          tagName: "button",
          name: "Save Changes",
          visible: true,
          enabled: true
        },
        {
          selector: "#hidden-btn",
          role: "button",
          tagName: "button",
          name: "Hidden Action",
          visible: false,
          enabled: true
        },
        {
          selector: "#disabled-btn",
          role: "button",
          tagName: "button",
          name: "Submit Locked",
          visible: true,
          enabled: false
        },
        {
          selector: "#busy-btn",
          role: "button",
          tagName: "button",
          name: "Loading",
          visible: true,
          enabled: true,
          ariaBusy: true
        },
        {
          selector: "#obscured-btn",
          role: "button",
          tagName: "button",
          name: "Behind Toast",
          visible: true,
          enabled: true,
          obscuredBy: ".toast-backdrop"
        },
        {
          selector: "#readonly-input",
          role: "textbox",
          tagName: "input",
          name: "Account ID",
          visible: true,
          enabled: true,
          readonly: true
        },
        {
          selector: "#delete-tenant-btn",
          role: "button",
          tagName: "button",
          name: "Delete Workspace Permanently",
          visible: true,
          enabled: true,
          destructive: true
        }
      ]
    },
    apiContracts: {
      allowedHosts: ["api.example.com", "telemetry.example.com"],
      endpoints: [
        {
          id: "addOrderItem",
          method: "POST",
          pathPattern: "/v1/orders/:orderId/items",
          requiredScopes: ["orders:write"],
          requireIdempotencyKey: true,
          querySchema: {
            dryRun: { type: "boolean", required: false }
          },
          bodySchema: {
            sku: { type: "string", required: true, pattern: "^SKU-[0-9]{3}$" },
            qty: { type: "integer", required: true, minimum: 1, maximum: 50 },
            contactEmail: { type: "string", required: true, minLength: 5 }
          }
        }
      ]
    },
    ...overrides
  };
}

describe("UI Action Guard (uiActionGuard)", () => {
  it("resolves elements by CSS selector, data-testid, and ARIA role+name", () => {
    const state = makeState();
    const dom = parseDomState(state.dom!);

    const byCss: UiActionPayload = {
      surface: "ui",
      actionId: "ui-1",
      actionType: "click",
      selector: "#save-btn"
    };
    expect(evaluateUiAction(byCss, dom)).toHaveLength(0);

    const byTestId: UiActionPayload = {
      surface: "ui",
      actionId: "ui-2",
      actionType: "click",
      selector: '[data-testid="save-settings"]'
    };
    expect(evaluateUiAction(byTestId, dom)).toHaveLength(0);

    const byRole: UiActionPayload = {
      surface: "ui",
      actionId: "ui-3",
      actionType: "click",
      selector: 'role=button[name="Save Changes"]'
    };
    expect(evaluateUiAction(byRole, dom)).toHaveLength(0);
  });

  it("blocks hidden, disabled, aria-busy, obscured, and readonly elements", () => {
    const state = makeState();
    const dom = parseDomState(state.dom!);

    const hiddenRes = evaluateUiAction(
      { surface: "ui", actionId: "u1", actionType: "click", selector: "#hidden-btn" },
      dom
    );
    expect(hiddenRes.map((v) => v.code)).toContain("UI_ELEMENT_NOT_VISIBLE");

    const disabledRes = evaluateUiAction(
      { surface: "ui", actionId: "u2", actionType: "click", selector: "#disabled-btn" },
      dom
    );
    expect(disabledRes.map((v) => v.code)).toContain("UI_ELEMENT_DISABLED");

    const busyRes = evaluateUiAction(
      { surface: "ui", actionId: "u3", actionType: "click", selector: "#busy-btn" },
      dom
    );
    expect(busyRes.map((v) => v.code)).toContain("UI_ELEMENT_ARIA_BUSY");

    const obscuredRes = evaluateUiAction(
      { surface: "ui", actionId: "u4", actionType: "click", selector: "#obscured-btn" },
      dom
    );
    expect(obscuredRes.map((v) => v.code)).toContain("UI_ELEMENT_OBSCURED");

    const readonlyRes = evaluateUiAction(
      {
        surface: "ui",
        actionId: "u5",
        actionType: "fill",
        selector: "#readonly-input",
        value: "new-id"
      },
      dom
    );
    expect(readonlyRes.map((v) => v.code)).toContain("UI_ELEMENT_READONLY");
  });

  it("blocks background element clicks when an active modal focus trap is open (UI_MODAL_TRAP_OCCLUSION)", () => {
    const dom = parseDomState({
      currentUrl: "https://portal.example.com/settings",
      activeModalSelector: "#confirm-dialog",
      elements: [
        {
          selector: "#save-btn",
          role: "button",
          tagName: "button",
          name: "Save Changes",
          visible: true,
          enabled: true,
          inActiveModal: false
        },
        {
          selector: "#modal-confirm-btn",
          role: "button",
          tagName: "button",
          name: "Confirm",
          visible: true,
          enabled: true,
          inActiveModal: true
        }
      ]
    });

    const occluded = evaluateUiAction(
      { surface: "ui", actionId: "m1", actionType: "click", selector: "#save-btn" },
      dom
    );
    expect(occluded.map((v) => v.code)).toContain("UI_MODAL_TRAP_OCCLUSION");

    const insideModal = evaluateUiAction(
      {
        surface: "ui",
        actionId: "m2",
        actionType: "click",
        selector: "#modal-confirm-btn"
      },
      dom
    );
    expect(insideModal).toHaveLength(0);
  });

  it("detects brittle XPath/nth-child selectors, destructive actions without human confirmation, and unsafe navigation", () => {
    const state = makeState();
    const dom = parseDomState(state.dom!);

    const brittle = evaluateUiAction(
      {
        surface: "ui",
        actionId: "b1",
        actionType: "click",
        selector: "/html/body/div[2]/div[1]/button[4]"
      },
      dom
    );
    expect(brittle.map((v) => v.code)).toContain("UI_SELECTOR_BRITTLE_OR_UNSAFE");

    const destructiveUnconfirmed = evaluateUiAction(
      {
        surface: "ui",
        actionId: "d1",
        actionType: "click",
        selector: "#delete-tenant-btn"
      },
      dom
    );
    expect(destructiveUnconfirmed.map((v) => v.code)).toContain(
      "UI_DESTRUCTIVE_ACTION_UNCONFIRMED"
    );

    const destructiveConfirmed = evaluateUiAction(
      {
        surface: "ui",
        actionId: "d2",
        actionType: "click",
        selector: "#delete-tenant-btn",
        confirmationToken: "human-ack-9910"
      },
      dom
    );
    expect(destructiveConfirmed).toHaveLength(0);

    const unsafeNav = evaluateUiAction(
      {
        surface: "ui",
        actionId: "n1",
        actionType: "navigate",
        targetUrl: "javascript:alert(1)"
      },
      dom
    );
    expect(unsafeNav.map((v) => v.code)).toContain("UI_NAVIGATION_ORIGIN_BLOCKED");
  });
});

describe("API Payload Guard (apiPayloadGuard)", () => {
  it("blocks SSRF attempts targeting cloud metadata, loopback, RFC1918, IPv6 mapped, and hex/integer IPs", () => {
    const state = makeState();
    const ssrfTargets = [
      "http://169.254.169.254/latest/meta-data/iam",
      "http://100.100.100.200/latest/meta-data",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://localhost:8080/admin",
      "http://127.0.0.1:9222/json",
      "http://10.24.1.9/internal",
      "http://192.168.1.1/router",
      "http://172.20.0.5/kubelet",
      "http://[::1]:8000/status",
      "http://[::ffff:127.0.0.1]/secret",
      "http://2130706433/admin",
      "http://0x7f.0.0.1/admin"
    ];

    for (const targetUrl of ssrfTargets) {
      const action: ApiActionPayload = {
        surface: "api",
        actionId: `ssrf-${targetUrl}`,
        method: "GET",
        url: targetUrl
      };
      const violations = evaluateApiPayload(action, state.apiContracts, state.session);
      expect(
        violations.some((v) => v.code === "API_SSRF_LOOPBACK_OR_METADATA"),
        `Expected ${targetUrl} to be blocked as SSRF`
      ).toBe(true);
    }

    expect(isInternalOrMetadataHost("api.example.com").internal).toBe(false);
  });

  it("validates OpenAPI path templates, HTTP methods, request body schemas, idempotency keys, and scopes", () => {
    const state = makeState();

    // Valid request
    const validAction: ApiActionPayload = {
      surface: "api",
      actionId: "api-ok",
      method: "POST",
      url: "https://api.example.com/v1/orders/ORD-55/items",
      query: { dryRun: true },
      headers: { "Idempotency-Key": "idem-abc-12345" },
      body: {
        sku: "SKU-109",
        qty: 3,
        contactEmail: "user1@example.com"
      }
    };
    expect(
      evaluateApiPayload(validAction, state.apiContracts, state.session)
    ).toHaveLength(0);

    // Missing Idempotency-Key + schema violation
    const invalidBodyAction: ApiActionPayload = {
      surface: "api",
      actionId: "api-bad-schema",
      method: "POST",
      url: "https://api.example.com/v1/orders/ORD-55/items",
      body: {
        sku: "INVALID_SKU",
        qty: 999,
        contactEmail: "a@b",
        unexpectedField: true
      }
    };
    const schemaViolations = evaluateApiPayload(
      invalidBodyAction,
      state.apiContracts,
      state.session
    );
    const codes = schemaViolations.map((v) => v.code);
    expect(codes).toContain("API_MISSING_IDEMPOTENCY_KEY");
    expect(codes).toContain("API_CONTRACT_SCHEMA_VIOLATION");

    // Disallowed method on registered path
    const wrongMethod: ApiActionPayload = {
      surface: "api",
      actionId: "api-405",
      method: "DELETE",
      url: "https://api.example.com/v1/orders/ORD-55/items"
    };
    expect(
      evaluateApiPayload(wrongMethod, state.apiContracts, state.session).map(
        (v) => v.code
      )
    ).toContain("API_METHOD_NOT_ALLOWED");

    // Missing scope
    const restrictedSession = {
      principalId: "sess-ro",
      authenticated: true,
      expiresAtMs: 1_700_003_600_000,
      scopes: ["orders:read"]
    };
    expect(
      evaluateApiPayload(validAction, state.apiContracts, restrictedSession).map(
        (v) => v.code
      )
    ).toContain("SESSION_SCOPE_INSUFFICIENT");
  });

  it("blocks outbound credential leakage and tainted domain exfiltration", () => {
    const state = makeState();
    const runtimeAssembledToken = ["sk", "proj", "X".repeat(28)].join("-");

    const leakAction: ApiActionPayload = {
      surface: "api",
      actionId: "api-leak",
      method: "POST",
      url: "https://telemetry.example.com/collect",
      body: {
        debugHeader: runtimeAssembledToken
      }
    };

    const violations = evaluateApiPayload(leakAction, undefined, state.session, {
      taintedDomains: new Set(["telemetry.example.com"])
    });
    expect(violations.map((v) => v.code)).toContain("API_TAINTED_SINK_DOMAIN");
    expect(violations.map((v) => v.code)).toContain("API_SENSITIVE_PAYLOAD_LEAK");
  });
});

describe("CLI Command Guard (cliCommandGuard)", () => {
  const cliPolicy = {
    allowedExecutables: ["git", "playwright", "vitest", "node"],
    allowedWorkdirs: ["/workspace/project"]
  };

  it("allows safe allowlisted binaries and arguments within the workspace sandbox", () => {
    const action: CliActionPayload = {
      surface: "cli",
      actionId: "cli-ok-1",
      executable: "vitest",
      args: ["run", "tests/firewall.test.ts"],
      cwd: "/workspace/project"
    };

    expect(evaluateCliCommand(action, cliPolicy)).toHaveLength(0);
  });

  it("blocks shell interpreters, command chaining operators, path traversal, dangerous flags, and LD_PRELOAD", () => {
    // Disallowed binary (bash / curl)
    const shellAction: CliActionPayload = {
      surface: "cli",
      actionId: "cli-bash",
      executable: "/bin/bash",
      args: ["-c", "whoami"]
    };
    expect(evaluateCliCommand(shellAction, cliPolicy).map((v) => v.code)).toContain(
      "CLI_EXECUTABLE_NOT_ALLOWLISTED"
    );

    // Command chaining + path traversal + eval flag + sandbox escape + dangerous env
    const injectionAction: CliActionPayload = {
      surface: "cli",
      actionId: "cli-inject",
      executable: "node",
      args: ["--eval", "process.exit(1)", "../../etc/passwd; id"],
      cwd: "/etc",
      env: {
        LD_PRELOAD: "/tmp/hook.so"
      }
    };
    const codes = evaluateCliCommand(injectionAction, cliPolicy).map((v) => v.code);
    expect(codes).toContain("CLI_WORKDIR_OUTSIDE_SANDBOX");
    expect(codes).toContain("CLI_DANGEROUS_FLAG_INJECTION");
    expect(codes).toContain("CLI_COMMAND_CHAINING_OR_SUBSHELL");
    expect(codes).toContain("CLI_PATH_TRAVERSAL_OR_SENSITIVE_FILE");
  });
});
