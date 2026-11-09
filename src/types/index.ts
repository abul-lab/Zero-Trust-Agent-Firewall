import type { ZodTypeAny } from "zod";

/**
 * Execution surfaces supported by the Zero-Trust Agent Firewall.
 */
export type ExecutionSurface = "ui" | "api" | "cli";

/**
 * High-level firewall verdict.
 * - ALLOW: Action satisfies all live state cages and surface guard invariants.
 * - BLOCK: Action violates a deterministic security or state invariant; execution must abort.
 * - HOLD: Action requires explicit human-in-the-loop confirmation before execution.
 */
export type VerdictStatus = "ALLOW" | "BLOCK" | "HOLD";

/**
 * Deterministic machine-readable reason codes emitted by state cages and surface guards.
 */
export type ReasonCode =
  // State Cage invariants
  | "STATE_SNAPSHOT_STALE"
  | "SESSION_UNAUTHENTICATED"
  | "SESSION_EXPIRED"
  | "SESSION_SCOPE_INSUFFICIENT"
  | "DATABASE_LOCK_ACTIVE"
  | "READONLY_MODE_VIOLATION"
  // UI Action Guard invariants
  | "UI_ELEMENT_NOT_FOUND"
  | "UI_ELEMENT_NOT_VISIBLE"
  | "UI_ELEMENT_DISABLED"
  | "UI_ELEMENT_READONLY"
  | "UI_ELEMENT_ARIA_BUSY"
  | "UI_ELEMENT_OBSCURED"
  | "UI_MODAL_TRAP_OCCLUSION"
  | "UI_SELECTOR_BRITTLE_OR_UNSAFE"
  | "UI_NAVIGATION_ORIGIN_BLOCKED"
  | "UI_INPUT_SENSITIVE_LEAK"
  | "UI_DESTRUCTIVE_ACTION_UNCONFIRMED"
  // API Payload Guard invariants
  | "API_SSRF_LOOPBACK_OR_METADATA"
  | "API_TAINTED_SINK_DOMAIN"
  | "API_HOST_NOT_ALLOWLISTED"
  | "API_ENDPOINT_UNREGISTERED"
  | "API_METHOD_NOT_ALLOWED"
  | "API_CONTRACT_SCHEMA_VIOLATION"
  | "API_MISSING_IDEMPOTENCY_KEY"
  | "API_SENSITIVE_PAYLOAD_LEAK"
  // CLI Command Guard invariants
  | "CLI_EXECUTABLE_NOT_ALLOWLISTED"
  | "CLI_COMMAND_CHAINING_OR_SUBSHELL"
  | "CLI_PATH_TRAVERSAL_OR_SENSITIVE_FILE"
  | "CLI_DANGEROUS_FLAG_INJECTION"
  | "CLI_WORKDIR_OUTSIDE_SANDBOX"
  | "CLI_TAINTED_SINK_ARGUMENT"
  // Runtime & Circuit-Breaker invariants
  | "EVALUATION_BUDGET_EXCEEDED"
  | "CIRCUIT_BREAKER_OPEN";

export type Severity = "low" | "medium" | "high" | "critical";

export interface PolicyViolation {
  code: ReasonCode;
  severity: Severity;
  surface: ExecutionSurface | "state" | "runtime";
  message: string;
  field?: string;
  remediation: string;
}

// ============================================================================
// Multi-Surface Action Payloads
// ============================================================================

export type UiActionType =
  | "click"
  | "dblclick"
  | "fill"
  | "select"
  | "check"
  | "uncheck"
  | "hover"
  | "press"
  | "navigate";

export interface UiActionPayload {
  surface: "ui";
  actionId?: string;
  actionType: UiActionType;
  /** CSS selector, data-testid="[data-testid='...']", or ARIA role selector e.g. role=button[name="Submit"] */
  selector?: string;
  /** Target URL when actionType === "navigate" */
  targetUrl?: string;
  /** Input text or key for fill / select / press actions */
  value?: string;
  /** Explicit human confirmation token for destructive UI actions (e.g. Delete Workspace) */
  confirmationToken?: string;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";

export interface ApiActionPayload {
  surface: "api";
  actionId?: string;
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  query?: Record<string, string | number | boolean>;
  body?: unknown;
  operationId?: string;
}

export interface CliActionPayload {
  surface: "cli";
  actionId?: string;
  executable: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string>;
}

export type AgentAction = UiActionPayload | ApiActionPayload | CliActionPayload;

// ============================================================================
// Live Local System State Snapshot ("State Cage")
// ============================================================================

export interface DomElementDescriptor {
  /** Primary CSS or test-id selector */
  selector: string;
  /** Optional data-testid attribute */
  testId?: string;
  /** ARIA role (button, textbox, link, dialog, checkbox, etc.) */
  role?: string;
  /** Accessible name / label */
  name?: string;
  /** Element tag name */
  tagName?: string;
  visible: boolean;
  enabled: boolean;
  readonly?: boolean;
  ariaBusy?: boolean;
  /** True if this element lives inside the currently active modal dialog */
  inActiveModal?: boolean;
  /** Selector of an overlay/toast obscuring the element's click target */
  obscuredBy?: string;
  /** True if clicking this element performs an irreversible/destructive operation */
  destructive?: boolean;
}

export interface DomStateSnapshot {
  currentUrl: string;
  allowedOrigins?: string[];
  /** Non-empty when a modal dialog (`[role="dialog"][aria-modal="true"]`) traps focus */
  activeModalSelector?: string;
  elements: DomElementDescriptor[];
}

export interface SessionAuthState {
  authenticated: boolean;
  principalId?: string;
  expiresAtMs?: number;
  scopes: string[];
  /** True when a database migration lock or transaction freeze is active */
  dbLockActive?: boolean;
  /** True when the environment is in read-only mode (e.g. production shadow run) */
  readOnlyMode?: boolean;
}

export interface JsonSchemaProperty {
  type: "string" | "number" | "integer" | "boolean" | "object" | "array";
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  pattern?: string;
  enum?: readonly (string | number | boolean)[];
}

export interface ApiEndpointContract {
  id: string;
  method: HttpMethod;
  /** Path template such as "/v1/orders/:orderId/refund" or "/api/users" */
  pathPattern: string;
  requiredScopes?: string[];
  requireIdempotencyKey?: boolean;
  /** Optional Zod schema or declarative property map for request body validation */
  bodySchema?: ZodTypeAny | Record<string, JsonSchemaProperty>;
  querySchema?: ZodTypeAny | Record<string, JsonSchemaProperty>;
}

export interface ApiContractRegistry {
  allowedHosts: string[];
  allowPrivateNetwork?: boolean;
  requireRegisteredEndpoint?: boolean;
  endpoints: ApiEndpointContract[];
}

export interface CliExecutionPolicy {
  allowedExecutables: string[];
  allowedWorkdirs: string[];
  maxArgLength?: number;
  allowNetworkTools?: boolean;
}

export interface SystemStateSnapshot {
  snapshotId: string;
  /** Epoch timestamp (ms) when the local runner captured this state snapshot */
  capturedAtMs: number;
  /** Override maximum allowed snapshot age (ms) before the state cage rejects it as stale */
  maxStalenessMs?: number;
  session?: SessionAuthState;
  dom?: DomStateSnapshot;
  apiContracts?: ApiContractRegistry;
  cliPolicy?: CliExecutionPolicy;
  /** External domains introduced by untrusted context (RAG / scraped DOM) that must never be contacted */
  taintedDomains?: string[];
}

// ============================================================================
// Control Plane Policy Pack, Firewall Configuration, Decision & Audit Types
// ============================================================================

/**
 * Non-blocking telemetry callback for streaming secret-redacted, SHA-256 linked
 * AuditEntry records to enterprise SIEMs (Splunk, Datadog, SecOps, OpenTelemetry).
 */
export type AuditTelemetrySink = (entry: AuditEntry) => void | Promise<void>;

/**
 * Versioned policy bundle distributed by a Centralized Cloud Control Plane
 * to in-process or Kubernetes sidecar Data-Plane firewall instances.
 */
export interface ControlPlanePolicyPack {
  policyVersion: string;
  updatedAtIso?: string;
  maxEvaluationLatencyMs?: number;
  defaultMaxStalenessMs?: number;
  disallowBrittleSelectors?: boolean;
  circuitBreakerThreshold?: number;
  defaultAllowedOrigins?: string[];
  defaultApiContracts?: ApiContractRegistry;
  defaultCliPolicy?: CliExecutionPolicy;
  globalTaintedDomains?: string[];
}

export interface FirewallConfig {
  /** Hard evaluation latency budget in ms (default: 10ms) */
  maxEvaluationLatencyMs?: number;
  /** Default maximum age of a state snapshot in ms (default: 5000ms) */
  defaultMaxStalenessMs?: number;
  /** Block brittle positional XPath/CSS selectors in UI actions (default: true) */
  disallowBrittleSelectors?: boolean;
  /** Consecutive blocked evaluations before tripping the circuit breaker (default: 5) */
  circuitBreakerThreshold?: number;
  /** Initial Control-Plane policy pack applied across evaluations */
  policyPack?: ControlPlanePolicyPack;
  /** Out-of-band SIEM telemetry sink invoked asynchronously after each decision */
  onAuditEntry?: AuditTelemetrySink;
  /** Clock provider for deterministic testing */
  nowMs?: () => number;
}

export interface FirewallDecision {
  decisionId: string;
  actionSurface: ExecutionSurface;
  verdict: VerdictStatus;
  allowed: boolean;
  reasonCodes: ReasonCode[];
  violations: PolicyViolation[];
  evaluationLatencyMs: number;
  withinLatencyBudget: boolean;
  stateSnapshotHash: string;
  auditEntryHash: string;
  timestamp: string;
}

export interface AuditEntry {
  index: number;
  entryId: string;
  timestamp: string;
  actionSurface: ExecutionSurface;
  /** Masked, secret-safe summary of the intercepted action */
  actionSummary: string;
  verdict: VerdictStatus;
  reasonCodes: ReasonCode[];
  evaluationLatencyMs: number;
  stateSnapshotHash: string;
  prevHash: string;
  entryHash: string;
}

export interface ChainVerificationResult {
  valid: boolean;
  checked: number;
  headHash: string;
  brokenAtIndex?: number;
  brokenEntryId?: string;
  reason?: string;
}

