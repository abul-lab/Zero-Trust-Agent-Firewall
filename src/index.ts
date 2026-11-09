export {
  ActionFirewall,
  FirewallBlockedError
} from "./firewall/ActionFirewall.js";
export {
  StateEvaluator,
  computeStateSnapshotHash,
  type StateEvaluationContext
} from "./firewall/StateEvaluator.js";
export {
  parseDomState,
  resolveDomElement,
  inspectSelectorSafety,
  type NormalizedDomState
} from "./firewall/serializers/domStateParser.js";
export {
  compileDeclarativeSchema,
  matchEndpointContract,
  validateContractPayload,
  type ContractMatchResult,
  type SchemaValidationOutcome
} from "./firewall/serializers/apiContractValidator.js";
export {
  evaluateUiAction,
  type UiGuardOptions
} from "./guards/uiActionGuard.js";
export {
  evaluateApiPayload,
  isInternalOrMetadataHost,
  type ApiGuardOptions
} from "./guards/apiPayloadGuard.js";
export {
  evaluateCliCommand,
  type CliGuardOptions
} from "./guards/cliCommandGuard.js";
export {
  AuditLedger,
  GENESIS_HASH,
  summarizeActionSafely,
  computeAuditEntryHash
} from "./audit/auditLedger.js";
export {
  startFirewallServer,
  type FirewallServerOptions,
  type FirewallServerHandle
} from "./server.js";
export type {
  ExecutionSurface,
  VerdictStatus,
  ReasonCode,
  Severity,
  PolicyViolation,
  UiActionType,
  UiActionPayload,
  HttpMethod,
  ApiActionPayload,
  CliActionPayload,
  AgentAction,
  DomElementDescriptor,
  DomStateSnapshot,
  SessionAuthState,
  JsonSchemaProperty,
  ApiEndpointContract,
  ApiContractRegistry,
  CliExecutionPolicy,
  SystemStateSnapshot,
  ControlPlanePolicyPack,
  AuditTelemetrySink,
  FirewallConfig,
  FirewallDecision,
  AuditEntry,
  ChainVerificationResult
} from "./types/index.js";
