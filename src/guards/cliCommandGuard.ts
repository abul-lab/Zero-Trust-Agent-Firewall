import { trimTrailingSlashes } from "../util/trimTrailingSlashes.js";
import path from "node:path";
import type {
  CliActionPayload,
  CliExecutionPolicy,
  PolicyViolation,
} from "../types/index.js";

const DEFAULT_ALLOWED_EXECUTABLES = [
  "git",
  "playwright",
  "vitest",
  "pytest",
  "tsc",
];

const NETWORK_OR_SHELL_BINARIES = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "cmd",
  "cmd.exe",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
  "curl",
  "wget",
  "nc",
  "ncat",
  "netcat",
  "socat",
  "ssh",
  "scp",
  "sftp",
  "ftp",
  "telnet",
]);

const SHELL_METACHAR_RE = /(?:[;&|`$><\r\n\0]|\$\(|\$\{)/;
const PATH_TRAVERSAL_RE = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
const SENSITIVE_PATH_RE =
  /(?:\/etc\/(?:passwd|shadow|sudoers|hosts)|\/proc\/self|\b\.env(?:\.[a-z0-9]+)?\b|[\\/]\.ssh[\\/]|\bid_(?:rsa|ed25519|ecdsa)\b|[\\/]\.aws[\\/]credentials|\\windows\\system32\b)/i;

const DANGEROUS_FLAGS = new Set([
  "-e",
  "--eval",
  "-c",
  "--command",
  "--upload-pack",
  "--receive-pack",
  "--exec",
  "-exec",
  "--checkpoint-action",
  "--to-command",
]);

const DANGEROUS_FLAG_PREFIXES = [
  "--upload-pack=",
  "--receive-pack=",
  "--checkpoint-action=",
  "--to-command=",
  "--eval=",
  "core.sshcommand=",
  "core.fsmonitor=",
  "protocol.ext.allow=",
];

export interface CliGuardOptions {
  taintedDomains?: ReadonlySet<string>;
}

function normalizePosixPath(p: string): string {
  return trimTrailingSlashes(p.replace(/\\/g, "/")).toLowerCase();
}

/**
 * Validates a CLI / child-process execution payload against allowlists,
 * shell metacharacter injection, flag injection, path traversal, and sandbox workdirs.
 */
export function evaluateCliCommand(
  action: CliActionPayload,
  policy: CliExecutionPolicy | undefined,
  options: CliGuardOptions = {},
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const rawExec = (action.executable ?? "").trim();
  const allowedList = (
    policy?.allowedExecutables ?? DEFAULT_ALLOWED_EXECUTABLES
  ).map((x) => x.trim().toLowerCase());
  const maxArgLen = policy?.maxArgLength ?? 2048;

  if (!rawExec) {
    violations.push({
      code: "CLI_EXECUTABLE_NOT_ALLOWLISTED",
      severity: "critical",
      surface: "cli",
      field: "executable",
      message: "CLI action is missing an executable name.",
      remediation: "Specify an allowlisted executable binary name.",
    });
    return violations;
  }

  // 1. Reject path-qualified binaries or shell metacharacters in executable name
  if (
    rawExec.includes("/") ||
    rawExec.includes("\\") ||
    SHELL_METACHAR_RE.test(rawExec) ||
    /\s/.test(rawExec)
  ) {
    violations.push({
      code: "CLI_EXECUTABLE_NOT_ALLOWLISTED",
      severity: "critical",
      surface: "cli",
      field: "executable",
      message: `Executable '${rawExec}' contains path separators, whitespace, or shell metacharacters.`,
      remediation: "Pass only the bare executable name (e.g. 'git' or 'playwright') and pass arguments in args[].",
    });
  }

  const lowerExec = rawExec.toLowerCase();
  if (
    NETWORK_OR_SHELL_BINARIES.has(lowerExec) &&
    !policy?.allowNetworkTools
  ) {
    violations.push({
      code: "CLI_EXECUTABLE_NOT_ALLOWLISTED",
      severity: "critical",
      surface: "cli",
      field: "executable",
      message: `Shell or network binary '${rawExec}' is forbidden by zero-trust CLI policy.`,
      remediation: "Invoke structured tools or allowlisted test runners directly instead of spawning a shell or network client.",
    });
  } else if (!allowedList.includes(lowerExec)) {
    violations.push({
      code: "CLI_EXECUTABLE_NOT_ALLOWLISTED",
      severity: "high",
      surface: "cli",
      field: "executable",
      message: `Executable '${rawExec}' is not in CliExecutionPolicy.allowedExecutables (${allowedList.join(", ")}).`,
      remediation: "Restrict agent CLI calls to executables declared in CliExecutionPolicy.allowedExecutables.",
    });
  }

  // 2. Inspect every argument for chaining, traversal, sensitive files, dangerous flags, and taint
  for (let i = 0; i < action.args.length; i++) {
    const arg = action.args[i] ?? "";
    const lowerArg = arg.trim().toLowerCase();

    if (arg.length > maxArgLen) {
      violations.push({
        code: "CLI_DANGEROUS_FLAG_INJECTION",
        severity: "high",
        surface: "cli",
        field: `args[${i}]`,
        message: `Argument at index ${i} exceeds maximum length (${arg.length} > ${maxArgLen}).`,
        remediation: "Keep CLI arguments concise and bounded.",
      });
    }

    if (SHELL_METACHAR_RE.test(arg)) {
      violations.push({
        code: "CLI_COMMAND_CHAINING_OR_SUBSHELL",
        severity: "critical",
        surface: "cli",
        field: `args[${i}]`,
        message: `Argument '${arg.slice(0, 60)}' contains shell command chaining, redirection, or subshell expansion syntax.`,
        remediation: "Remove shell metacharacters (; | & ` $() > <) from CLI arguments.",
      });
    }

    if (PATH_TRAVERSAL_RE.test(arg) || SENSITIVE_PATH_RE.test(arg)) {
      violations.push({
        code: "CLI_PATH_TRAVERSAL_OR_SENSITIVE_FILE",
        severity: "critical",
        surface: "cli",
        field: `args[${i}]`,
        message: `Argument '${arg.slice(0, 80)}' references a parent-directory traversal sequence or protected system/credential file.`,
        remediation: "Restrict CLI file paths to relative project paths inside the workspace sandbox.",
      });
    }

    if (
      DANGEROUS_FLAGS.has(lowerArg) ||
      DANGEROUS_FLAG_PREFIXES.some((prefix) => lowerArg.startsWith(prefix))
    ) {
      violations.push({
        code: "CLI_DANGEROUS_FLAG_INJECTION",
        severity: "critical",
        surface: "cli",
        field: `args[${i}]`,
        message: `Argument '${arg}' is a high-risk code-evaluation or protocol-override flag.`,
        remediation: "Disallow inline eval (-e/-c), git protocol overrides, and arbitrary command hooks.",
      });
    }

    if (options.taintedDomains && options.taintedDomains.size > 0) {
      for (const domain of options.taintedDomains) {
        if (lowerArg.includes(domain.toLowerCase())) {
          violations.push({
            code: "CLI_TAINTED_SINK_ARGUMENT",
            severity: "critical",
            surface: "cli",
            field: `args[${i}]`,
            message: `CLI argument '${arg.slice(0, 80)}' references tainted domain '${domain}' from untrusted context.`,
            remediation: "Never pass domains or URLs extracted from untrusted context into CLI arguments.",
          });
        }
      }
    }
  }

  // 3. Inspect environment variable overrides
  if (action.env) {
    const blockedEnvVars = new Set([
      "ld_preload",
      "ld_library_path",
      "dyld_insert_libraries",
      "node_options",
      "pythonstartup",
      "pythonpath",
      "git_ssh_command",
      "bash_env",
      "env",
    ]);
    for (const [k, v] of Object.entries(action.env)) {
      if (blockedEnvVars.has(k.trim().toLowerCase())) {
        violations.push({
          code: "CLI_DANGEROUS_FLAG_INJECTION",
          severity: "critical",
          surface: "cli",
          field: `env.${k}`,
          message: `Environment variable '${k}' can hijack dynamic linker or interpreter startup.`,
          remediation: `Remove '${k}' from CliActionPayload.env.`,
        });
      }
      if (SHELL_METACHAR_RE.test(v)) {
        violations.push({
          code: "CLI_COMMAND_CHAINING_OR_SUBSHELL",
          severity: "critical",
          surface: "cli",
          field: `env.${k}`,
          message: `Environment variable '${k}' value contains shell metacharacters or subshell syntax.`,
          remediation: "Sanitize environment variable values before process execution.",
        });
      }
    }
  }

  // 4. Working directory sandbox check
  if (action.cwd !== undefined) {
    if (PATH_TRAVERSAL_RE.test(action.cwd)) {
      violations.push({
        code: "CLI_WORKDIR_OUTSIDE_SANDBOX",
        severity: "critical",
        surface: "cli",
        field: "cwd",
        message: `Working directory '${action.cwd}' contains parent-directory traversal ('..').`,
        remediation: "Use a canonical path inside an allowed workspace directory.",
      });
    } else if (policy?.allowedWorkdirs && policy.allowedWorkdirs.length > 0) {
      const resolvedCwd = normalizePosixPath(path.resolve(action.cwd));
      const insideSandbox = policy.allowedWorkdirs.some((root) => {
        const resolvedRoot = normalizePosixPath(path.resolve(root));
        return (
          resolvedCwd === resolvedRoot ||
          resolvedCwd.startsWith(`${resolvedRoot}/`)
        );
      });
      if (!insideSandbox) {
        violations.push({
          code: "CLI_WORKDIR_OUTSIDE_SANDBOX",
          severity: "critical",
          surface: "cli",
          field: "cwd",
          message: `Working directory '${action.cwd}' is outside allowed sandbox roots (${policy.allowedWorkdirs.join(", ")}).`,
          remediation: "Execute CLI commands only inside directories listed in CliExecutionPolicy.allowedWorkdirs.",
        });
      }
    }
  }

  return violations;
}

