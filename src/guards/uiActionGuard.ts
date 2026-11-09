import {
  inspectSelectorSafety,
  type NormalizedDomState,
  resolveDomElement,
} from "../firewall/serializers/domStateParser.js";
import type { PolicyViolation, UiActionPayload } from "../types/index.js";

const SENSITIVE_OR_XSS_INPUT_RE =
  /(?:\bghp_[A-Za-z0-9]{30,}|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{30,}|\bxox[baprs]-[0-9A-Za-z-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|<script\b|javascript\s*:)/i;

export interface UiGuardOptions {
  disallowBrittleSelectors?: boolean;
  taintedDomains?: ReadonlySet<string>;
}

/**
 * Validates a Playwright/Selenium UI action against the live NormalizedDomState cage.
 */
export function evaluateUiAction(
  action: UiActionPayload,
  dom: NormalizedDomState | undefined,
  options: UiGuardOptions = {},
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const disallowBrittle = options.disallowBrittleSelectors ?? true;

  if (!dom) {
    violations.push({
      code: "UI_ELEMENT_NOT_FOUND",
      severity: "critical",
      surface: "ui",
      message: "UI action cannot be verified because no live DOM state snapshot is present.",
      remediation: "Capture and attach a fresh DomStateSnapshot before dispatching UI actions.",
    });
    return violations;
  }

  // 1. Navigation guard
  if (action.actionType === "navigate") {
    const rawUrl = (action.targetUrl ?? "").trim();
    if (!rawUrl) {
      violations.push({
        code: "UI_NAVIGATION_ORIGIN_BLOCKED",
        severity: "high",
        surface: "ui",
        field: "targetUrl",
        message: "Navigation action is missing a targetUrl.",
        remediation: "Specify an explicit HTTPS/HTTP targetUrl within an allowed origin.",
      });
      return violations;
    }

    if (/^(?:javascript|vbscript|data|file|about|blob)\s*:/i.test(rawUrl)) {
      violations.push({
        code: "UI_NAVIGATION_ORIGIN_BLOCKED",
        severity: "critical",
        surface: "ui",
        field: "targetUrl",
        message: `Navigation to non-web scheme '${rawUrl.slice(0, 32)}' is forbidden.`,
        remediation: "Navigate only to allowlisted http:// or https:// origins.",
      });
      return violations;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      violations.push({
        code: "UI_NAVIGATION_ORIGIN_BLOCKED",
        severity: "high",
        surface: "ui",
        field: "targetUrl",
        message: `Navigation targetUrl '${rawUrl}' is not a valid URL.`,
        remediation: "Provide a well-formed absolute URL.",
      });
      return violations;
    }

    const host = parsedUrl.hostname.toLowerCase();
    if (options.taintedDomains?.has(host)) {
      violations.push({
        code: "UI_NAVIGATION_ORIGIN_BLOCKED",
        severity: "critical",
        surface: "ui",
        field: "targetUrl",
        message: `Navigation target host '${host}' originated from untrusted context (tainted sink).`,
        remediation: "Block navigation to domains extracted from untrusted documents or third-party text.",
      });
    }

    if (dom.allowedOrigins.size > 0 && !dom.allowedOrigins.has(parsedUrl.origin)) {
      violations.push({
        code: "UI_NAVIGATION_ORIGIN_BLOCKED",
        severity: "high",
        surface: "ui",
        field: "targetUrl",
        message: `Navigation origin '${parsedUrl.origin}' is outside allowed origins (${Array.from(dom.allowedOrigins).join(", ")}).`,
        remediation: "Restrict UI navigation to origins registered in DomStateSnapshot.allowedOrigins.",
      });
    }

    return violations;
  }

  // 2. Selector safety & brittleness check
  const selector = (action.selector ?? "").trim();
  if (!selector) {
    violations.push({
      code: "UI_SELECTOR_BRITTLE_OR_UNSAFE",
      severity: "high",
      surface: "ui",
      field: "selector",
      message: `UI action '${action.actionType}' requires a target selector.`,
      remediation: "Provide a data-testid, ARIA role, or CSS selector.",
    });
    return violations;
  }

  if (disallowBrittle) {
    const safety = inspectSelectorSafety(selector);
    if (!safety.safe) {
      violations.push({
        code: "UI_SELECTOR_BRITTLE_OR_UNSAFE",
        severity: "high",
        surface: "ui",
        field: "selector",
        message: safety.reason ?? "Selector failed safety inspection.",
        remediation: "Use a stable '[data-testid=...]' or 'role=button[name=...]' selector.",
      });
    }
  }

  // 3. Input value screening (secrets & XSS injection in fill/select/press)
  if (action.value !== undefined && SENSITIVE_OR_XSS_INPUT_RE.test(action.value)) {
    violations.push({
      code: "UI_INPUT_SENSITIVE_LEAK",
      severity: "critical",
      surface: "ui",
      field: "value",
      message: "UI input value contains a live credential pattern or executable script tag.",
      remediation: "Redact secrets or use synthetic test credentials before filling UI inputs.",
    });
  }

  // 4. Live DOM element existence & interactability state cage
  const el = resolveDomElement(dom, selector);
  if (!el) {
    violations.push({
      code: "UI_ELEMENT_NOT_FOUND",
      severity: "high",
      surface: "ui",
      field: "selector",
      message: `Target element '${selector}' does not exist in the current DOM snapshot (${dom.currentUrl}).`,
      remediation: "Refresh the DOM snapshot or wait for the target component to mount before acting.",
    });
    return violations;
  }

  if (!el.visible) {
    violations.push({
      code: "UI_ELEMENT_NOT_VISIBLE",
      severity: "high",
      surface: "ui",
      field: "selector",
      message: `Target element '${selector}' is present in the DOM but hidden (visible=false).`,
      remediation: "Ensure the element is rendered and visible on screen before interacting.",
    });
  }

  if (!el.enabled && action.actionType !== "hover") {
    violations.push({
      code: "UI_ELEMENT_DISABLED",
      severity: "high",
      surface: "ui",
      field: "selector",
      message: `Target element '${selector}' is disabled (enabled=false) and cannot accept '${action.actionType}'.`,
      remediation: "Satisfy form preconditions so the control becomes enabled before clicking or filling.",
    });
  }

  if (el.ariaBusy) {
    violations.push({
      code: "UI_ELEMENT_ARIA_BUSY",
      severity: "medium",
      surface: "ui",
      field: "selector",
      message: `Target element '${selector}' is currently busy (aria-busy=true).`,
      remediation: "Wait for pending async UI state transitions to settle before dispatching the action.",
    });
  }

  if (
    (action.actionType === "fill" ||
      action.actionType === "select" ||
      action.actionType === "check" ||
      action.actionType === "uncheck") &&
    el.readonly
  ) {
    violations.push({
      code: "UI_ELEMENT_READONLY",
      severity: "high",
      surface: "ui",
      field: "selector",
      message: `Target element '${selector}' is read-only and cannot be modified via '${action.actionType}'.`,
      remediation: "Do not attempt to mutate read-only form controls.",
    });
  }

  if (el.obscuredBy) {
    violations.push({
      code: "UI_ELEMENT_OBSCURED",
      severity: "high",
      surface: "ui",
      field: "selector",
      message: `Target element '${selector}' is obscured by overlay '${el.obscuredBy}'.`,
      remediation: `Dismiss or wait for '${el.obscuredBy}' to close before interacting with '${selector}'.`,
    });
  }

  if (
    dom.activeModalSelector &&
    !el.inActiveModal &&
    el.selector !== dom.activeModalSelector
  ) {
    violations.push({
      code: "UI_MODAL_TRAP_OCCLUSION",
      severity: "high",
      surface: "ui",
      field: "selector",
      message: `Active modal dialog '${dom.activeModalSelector}' traps focus; background element '${selector}' cannot be interacted with.`,
      remediation: `Interact with elements inside '${dom.activeModalSelector}' or close the modal first.`,
    });
  }

  if (el.destructive && !action.confirmationToken) {
    violations.push({
      code: "UI_DESTRUCTIVE_ACTION_UNCONFIRMED",
      severity: "critical",
      surface: "ui",
      field: "confirmationToken",
      message: `Element '${selector}' is marked destructive and requires an explicit human confirmationToken.`,
      remediation: "Request human approval and attach a valid confirmationToken before executing destructive UI actions.",
    });
  }

  return violations;
}

