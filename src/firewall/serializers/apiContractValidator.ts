import { trimTrailingSlashes } from "../../util/trimTrailingSlashes.js";
import { z, type ZodTypeAny } from "zod";
import type {
  ApiEndpointContract,
  HttpMethod,
  JsonSchemaProperty,
} from "../../types/index.js";

export interface ContractMatchResult {
  matchedPathOnly: boolean;
  contract?: ApiEndpointContract;
  allowedMethodsForPath?: HttpMethod[];
  pathParams: Record<string, string>;
}

export interface SchemaValidationOutcome {
  valid: boolean;
  errors: string[];
}

const schemaCache = new WeakMap<Record<string, JsonSchemaProperty>, ZodTypeAny>();
const schemaFingerprintCache = new Map<string, ZodTypeAny>();
const pathRegexCache = new Map<string, { regex: RegExp; paramNames: string[] }>();

function isZodSchema(schema: unknown): schema is ZodTypeAny {
  return (
    typeof schema === "object" &&
    schema !== null &&
    "_def" in schema &&
    typeof (schema as ZodTypeAny).safeParse === "function"
  );
}

/**
 * Compiles a declarative `Record<string, JsonSchemaProperty>` into a cached Zod schema.
 * Uses a fast WeakMap for in-process object identity and a bounded fingerprint Map
 * for JSON-deserialized sidecar HTTP requests.
 */
export function compileDeclarativeSchema(
  definition: Record<string, JsonSchemaProperty>,
): ZodTypeAny {
  const cached = schemaCache.get(definition);
  if (cached) {
    return cached;
  }

  const fingerprint = JSON.stringify(definition);
  const byFingerprint = schemaFingerprintCache.get(fingerprint);
  if (byFingerprint) {
    schemaCache.set(definition, byFingerprint);
    return byFingerprint;
  }

  const shape: Record<string, ZodTypeAny> = {};
  for (const [key, prop] of Object.entries(definition)) {
    let fieldSchema: ZodTypeAny;

    if (prop.enum && prop.enum.length > 0) {
      const literals = prop.enum.map((val) => z.literal(val) as unknown as ZodTypeAny);
      fieldSchema = z.union(
        literals as unknown as [ZodTypeAny, ZodTypeAny, ...ZodTypeAny[]],
      );
    } else {
      switch (prop.type) {
        case "string": {
          let s = z.string();
          if (prop.minLength !== undefined) s = s.min(prop.minLength);
          if (prop.maxLength !== undefined) s = s.max(prop.maxLength);
          if (prop.pattern !== undefined) s = s.regex(new RegExp(prop.pattern));
          fieldSchema = s;
          break;
        }
        case "number":
        case "integer": {
          let n = prop.type === "integer" ? z.number().int() : z.number();
          if (prop.minimum !== undefined) n = n.min(prop.minimum);
          if (prop.maximum !== undefined) n = n.max(prop.maximum);
          fieldSchema = n;
          break;
        }
        case "boolean":
          fieldSchema = z.boolean();
          break;
        case "array":
          fieldSchema = z.array(z.unknown());
          break;
        case "object":
          fieldSchema = z.record(z.string(), z.unknown());
          break;
      }
    }

    shape[key] = prop.required === false ? fieldSchema.optional() : fieldSchema;
  }

  const compiled = z.object(shape).strict();
  schemaCache.set(definition, compiled);
  if (schemaFingerprintCache.size >= 512) {
    const oldestKey = schemaFingerprintCache.keys().next().value;
    if (oldestKey !== undefined) {
      schemaFingerprintCache.delete(oldestKey);
    }
  }
  schemaFingerprintCache.set(fingerprint, compiled);
  return compiled;
}

function compilePathTemplate(pattern: string): { regex: RegExp; paramNames: string[] } {
  const normalized = trimTrailingSlashes(pattern.trim()) || "/";
  const existing = pathRegexCache.get(normalized);
  if (existing) {
    return existing;
  }

  const paramNames: string[] = [];
  const regexSource = normalized
    .split("/")
    .map((segment) => {
      if (segment.startsWith(":") && segment.length > 1) {
        paramNames.push(segment.slice(1));
        return "([^/]+)";
      }
      if (segment.startsWith("{") && segment.endsWith("}") && segment.length > 2) {
        paramNames.push(segment.slice(1, -1));
        return "([^/]+)";
      }
      if (segment === "*") {
        return "(?:.*)";
      }
      return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("/");

  const compiled = {
    regex: new RegExp(`^${regexSource || "/"}$`, "i"),
    paramNames,
  };
  pathRegexCache.set(normalized, compiled);
  return compiled;
}

/**
 * Matches a request method and URL path against registered OpenAPI endpoint contracts.
 */
export function matchEndpointContract(
  contracts: readonly ApiEndpointContract[],
  method: HttpMethod,
  rawPathname: string,
): ContractMatchResult {
  const pathname = trimTrailingSlashes(rawPathname.trim()) || "/";
  const methodsMatchingPath: HttpMethod[] = [];
  let matchedParams: Record<string, string> = {};

  for (const contract of contracts) {
    const { regex, paramNames } = compilePathTemplate(contract.pathPattern);
    const match = regex.exec(pathname);
    if (!match) {
      continue;
    }

    const params: Record<string, string> = {};
    paramNames.forEach((name, idx) => {
      const val = match[idx + 1];
      if (val !== undefined) {
        params[name] = decodeURIComponent(val);
      }
    });

    if (contract.method.toUpperCase() === method.toUpperCase()) {
      return {
        matchedPathOnly: false,
        contract,
        pathParams: params,
      };
    }

    methodsMatchingPath.push(contract.method);
    matchedParams = params;
  }

  if (methodsMatchingPath.length > 0) {
    return {
      matchedPathOnly: true,
      allowedMethodsForPath: methodsMatchingPath,
      pathParams: matchedParams,
    };
  }

  return {
    matchedPathOnly: false,
    pathParams: {},
  };
}

/**
 * Validates an API payload or query object against a Zod schema or declarative schema map.
 */
export function validateContractPayload(
  schema: ZodTypeAny | Record<string, JsonSchemaProperty> | undefined,
  payload: unknown,
): SchemaValidationOutcome {
  if (!schema) {
    return { valid: true, errors: [] };
  }

  const zodSchema = isZodSchema(schema) ? schema : compileDeclarativeSchema(schema);
  const parsed = zodSchema.safeParse(payload ?? {});
  if (parsed.success) {
    return { valid: true, errors: [] };
  }

  const errors = parsed.error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join(".") : "<root>";
    return `${path}: ${issue.message}`;
  });
  return { valid: false, errors };
}

