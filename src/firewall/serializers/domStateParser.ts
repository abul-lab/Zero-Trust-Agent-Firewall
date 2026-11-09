import type { DomElementDescriptor, DomStateSnapshot } from "../../types/index.js";

export interface NormalizedDomState {
  currentUrl: string;
  origin: string | null;
  allowedOrigins: Set<string>;
  activeModalSelector?: string;
  bySelector: Map<string, DomElementDescriptor>;
  byTestId: Map<string, DomElementDescriptor>;
  byRoleAndName: Map<string, DomElementDescriptor>;
  allElements: readonly DomElementDescriptor[];
}

const ROLE_SELECTOR_RE = /^role=([a-zA-Z0-9_-]+)(?:\[\s*name\s*=\s*["']([^"']+)["']\s*\])?$/i;
const TESTID_ATTR_RE = /^\[data-testid\s*=\s*["']([^"']+)["']\]$/i;
const TESTID_PREFIX_RE = /^(?:data-)?testid=(.+)$/i;

// Brittle selector patterns that break on minor layout shifts or carry script payloads
const BRITTLE_XPATH_RE = /^(?:\/html\/body|\(\/\/[a-z]+\[\d+\]){2,}|(?:\/[a-z0-9_-]+\[\d+\]){3,}/i;
// Two or more "> ... :nth-child(n)" segments in one selector, checked per segment (linear in the input).
const NTH_SEGMENT_RE = /^[^{,]+:nth-(?:child|of-type)\(\d+\)/i;
function hasBrittleNthChain(selector: string): boolean {
  return selector.split(">").slice(1).filter((seg) => NTH_SEGMENT_RE.test(seg.trimStart())).length >= 2;
}
const UNSAFE_SELECTOR_RE = /(?:javascript\s*:|vbscript\s*:|data\s*:\s*text\/html|<script\b)/i;

/**
 * Normalizes and indexes a raw DOM state snapshot into O(1) lookup tables
 * for sub-millisecond selector and accessibility-role resolution.
 */
export function parseDomState(snapshot: DomStateSnapshot): NormalizedDomState {
  let origin: string | null = null;
  try {
    origin = new URL(snapshot.currentUrl).origin;
  } catch {
    origin = null;
  }

  const allowedOrigins = new Set<string>();
  if (origin) {
    allowedOrigins.add(origin);
  }
  if (snapshot.allowedOrigins) {
    for (const o of snapshot.allowedOrigins) {
      try {
        allowedOrigins.add(new URL(o).origin);
      } catch {
        allowedOrigins.add(o.trim().toLowerCase());
      }
    }
  }

  const bySelector = new Map<string, DomElementDescriptor>();
  const byTestId = new Map<string, DomElementDescriptor>();
  const byRoleAndName = new Map<string, DomElementDescriptor>();

  for (const el of snapshot.elements) {
    const cleanSel = el.selector.trim();
    bySelector.set(cleanSel, el);

    if (el.testId) {
      byTestId.set(el.testId.trim(), el);
      bySelector.set(`[data-testid="${el.testId.trim()}"]`, el);
      bySelector.set(`[data-testid='${el.testId.trim()}']`, el);
    }

    if (el.role) {
      const roleKey = el.role.trim().toLowerCase();
      if (el.name) {
        const compositeKey = `${roleKey}:${el.name.trim().toLowerCase()}`;
        byRoleAndName.set(compositeKey, el);
      }
      if (!byRoleAndName.has(`${roleKey}:*`)) {
        byRoleAndName.set(`${roleKey}:*`, el);
      }
    }
  }

  return {
    currentUrl: snapshot.currentUrl,
    origin,
    allowedOrigins,
    activeModalSelector: snapshot.activeModalSelector,
    bySelector,
    byTestId,
    byRoleAndName,
    allElements: snapshot.elements,
  };
}

/**
 * Resolves a Playwright/CSS/ARIA selector against the indexed DOM state in O(1) time.
 */
export function resolveDomElement(
  dom: NormalizedDomState,
  rawSelector: string,
): DomElementDescriptor | undefined {
  const sel = rawSelector.trim();
  const direct = dom.bySelector.get(sel);
  if (direct) {
    return direct;
  }

  const testIdAttr = TESTID_ATTR_RE.exec(sel);
  if (testIdAttr?.[1]) {
    return dom.byTestId.get(testIdAttr[1]);
  }

  const testIdPrefix = TESTID_PREFIX_RE.exec(sel);
  if (testIdPrefix?.[1]) {
    return dom.byTestId.get(testIdPrefix[1].trim().replace(/^["']|["']$/g, ""));
  }

  const roleMatch = ROLE_SELECTOR_RE.exec(sel);
  if (roleMatch?.[1]) {
    const role = roleMatch[1].toLowerCase();
    const name = roleMatch[2]?.trim().toLowerCase();
    if (name) {
      return dom.byRoleAndName.get(`${role}:${name}`);
    }
    return dom.byRoleAndName.get(`${role}:*`);
  }

  return undefined;
}

/**
 * Checks whether a selector is brittle (deep positional XPath/nth-child chain)
 * or contains executable script syntax.
 */
export function inspectSelectorSafety(selector: string): {
  safe: boolean;
  reason?: string;
} {
  const trimmed = selector.trim();
  if (!trimmed) {
    return { safe: false, reason: "Selector is empty." };
  }
  if (UNSAFE_SELECTOR_RE.test(trimmed)) {
    return {
      safe: false,
      reason: `Selector '${trimmed}' contains an unsafe script scheme or HTML tag.`,
    };
  }
  if (BRITTLE_XPATH_RE.test(trimmed)) {
    return {
      safe: false,
      reason: `Selector '${trimmed}' is a brittle positional XPath that breaks on minor DOM changes; use data-testid or ARIA role selectors.`,
    };
  }
  if (hasBrittleNthChain(trimmed)) {
    return {
      safe: false,
      reason: `Selector '${trimmed}' chains multiple positional :nth-child() selectors; use stable semantic or test-id locators.`,
    };
  }
  return { safe: true };
}

