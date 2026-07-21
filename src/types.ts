// Shared types for StormForge.
//
// Design note: everything downstream of the network layer operates on plain
// `ProbeResult` objects. Detection checks are pure functions of a ProbeResult,
// which keeps them deterministic, side-effect free, and unit-testable without
// hitting the network.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** A single authorized scope: what the operator is permitted to test. */
export interface Scope {
  /** Bug-bounty program identifier, e.g. "acme-h1". Used for report formatting. */
  program: string;
  /** Reporting platform, drives the report template. */
  platform: 'hackerone' | 'bugcrowd' | 'immunefi' | 'intigriti' | 'generic';
  /**
   * In-scope host patterns. Supports exact hosts ("api.acme.com") and single
   * leading wildcard ("*.acme.com"). Anything not matching is refused.
   */
  inScope: string[];
  /** Explicit out-of-scope hosts that override an inScope wildcard. */
  outOfScope: string[];
  /** If false, the scan refuses to run at all. Forces a conscious opt-in. */
  authorized: boolean;
  /** Free-text note, e.g. link to the program's rules-of-engagement. */
  notes?: string;
}

/**
 * Structured body signals filled by the scanner for successful (2xx) probes.
 * Kept optional so unit tests can fabricate bare ProbeResults.
 */
export interface BodySignals {
  kind: 'json' | 'html' | 'yaml' | 'text' | 'empty';
  openApiPathCount: number;
  openApiVersion?: string;
  graphqlIntrospection: boolean;
  graphqlExplorer: boolean;
  swaggerUi: boolean;
  graphqlEndpointHint: boolean;
  preview: string;
}

/** Result of a single non-destructive HTTP probe. */
export interface ProbeResult {
  url: string;
  method: string;
  status: number;
  /** Lower-cased header name -> value. */
  headers: Record<string, string>;
  /** Response body, truncated to a safe cap. May be empty for large/binary bodies. */
  body: string;
  /** Final URL after redirects, if different. */
  finalUrl?: string;
  /** Wall-clock milliseconds for the request. */
  elapsedMs: number;
  /** Populated when the probe failed (DNS, TLS, timeout, refused-by-scope). */
  error?: string;
  /**
   * Parsed body signals for 2xx responses. Set by the scan engine before
   * detection checks run; checks may recompute via `parseBodySignals` if absent.
   */
  signals?: BodySignals;
}

/** A detection produced by a Check. */
export interface Finding {
  /** Stable id derived from check + target + evidence; used for dedupe. */
  id: string;
  checkId: string;
  title: string;
  severity: Severity;
  /** The affected URL/asset. */
  target: string;
  description: string;
  /** Human-verifiable evidence (headers seen, snippet, etc.). No exploitation. */
  evidence: string;
  /** Concrete, manual reproduction steps. */
  reproduction: string[];
  /** Remediation guidance for the report. */
  remediation: string;
  /** Optional CWE id, e.g. "CWE-16". */
  cwe?: string;
  /** References (docs, CVEs). */
  references: string[];
  /**
   * false = confirmed by the tool's own passive evidence.
   * true  = a *candidate* that requires human validation before submission.
   */
  needsManualReview: boolean;
  discoveredAt: string;
  /**
   * 0–1 confidence that the finding is real and submission-ready.
   * Filled by enrichFinding when absent.
   */
  confidence?: number;
  /** How the signal was obtained. */
  evidenceGrade?: 'canary' | 'fingerprint' | 'tool-confirmed' | 'heuristic';
  /** True when confidence + severity warrant a bounty draft (not auto-submit). */
  submitReady?: boolean;
  /** Originating detector: worker check id, nuclei, sqlmap, etc. */
  source?: string;
}

/** Interface every detection check implements. Pure and synchronous. */
export interface Check {
  id: string;
  title: string;
  /** CWE this check maps to, if any. */
  cwe?: string;
  /**
   * Inspect a probe result and emit zero or more findings. Must not perform
   * I/O or mutate the input. Never attempts exploitation.
   */
  run(probe: ProbeResult, ctx: CheckContext): Finding[];
}

export interface CheckContext {
  scope: Scope;
  /** Other probes gathered in the same scan, for cross-referencing. */
  siblings?: ProbeResult[];
}

/**
 * Optional authenticated session for dual-pass recon.
 * Values are merged into probe headers and must never be logged.
 */
export interface ScanSession {
  /** Cookie header value (e.g. "session=abc; other=1"). */
  cookie?: string;
  /** Authorization header (e.g. "Bearer eyJ…"). */
  authorization?: string;
  /** Extra request headers merged into every authenticated probe. */
  headers?: Record<string, string>;
}

export interface ScanRequest {
  scope: Scope;
  /** Seed URLs/hosts to probe (all must be in scope). */
  targets: string[];
  /** Extra paths to probe on each target host, beyond the default wordlist. */
  extraPaths?: string[];
  /** Authenticated session — enables dual-pass anon vs auth + horizontal IDOR. */
  session?: ScanSession;
  /**
   * Public base URL of this Worker for blind SSRF OAST canaries.
   * Injected from the incoming request origin when omitted.
   */
  canaryBaseUrl?: string;
  /** When set, this scan was spawned from an executor crawl (katana/ffuf). */
  parentScanId?: string;
  /** Tool that discovered the re-scan targets. */
  sourceTool?: string;
}

export interface ScanReport {
  scanId: string;
  program: string;
  startedAt: string;
  finishedAt: string;
  targetsProbed: number;
  findings: Finding[];
  /** Counts by severity for the dashboard. */
  summary: Record<Severity, number>;
}

// ─── TASK QUEUE: C2 ↔ Executor Communication ────────────────────────────────

export type ToolName =
  | 'nmap'
  | 'nuclei'
  | 'httpx'
  | 'subfinder'
  | 'katana'
  | 'ffuf'
  | 'sqlmap'
  | 'gobuster';

export type TaskStatus = 'pending' | 'running' | 'done' | 'error' | 'timeout';

/** A tool execution task dispatched by the C2 to a remote executor. */
export interface ToolTask {
  id: string;
  /** Which scan spawned this task. */
  scanId: string;
  tool: ToolName;
  /** Target host/URL — MUST be in-scope (validated before queuing). */
  target: string;
  /** Tool-specific arguments (e.g. ports, wordlist path, flags). */
  args: Record<string, string>;
  /** Scope context so the executor can double-check. */
  scope: Scope;
  status: TaskStatus;
  /** Max seconds the executor should allow before killing the process. */
  timeoutSec: number;
  createdAt: string;
  /** Populated by executor on completion. */
  result?: ToolTaskResult;
}

export interface ToolTaskResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  /** Parsed findings extracted from tool output. */
  findings: Finding[];
  durationMs: number;
  completedAt: string;
}

// ─── Environment bindings ────────────────────────────────────────────────────

export interface Env {
  SCAN_ORCHESTRATOR: DurableObjectNamespace;
  STORMFORGE_KV: KVNamespace;
  MAX_RPS: string;
  MAX_CONCURRENCY: string;
  SCAN_MODE: string;
  LLM_PLANNER_ENDPOINT: string;
  LLM_PLANNER_MODEL: string;
  LLM_PLANNER_API_KEY?: string;
  /** Shared secret between C2 and executor for auth. */
  EXECUTOR_SECRET?: string;
}
