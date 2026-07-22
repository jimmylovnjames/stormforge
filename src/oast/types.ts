// Out-of-band Application Security Testing (OAST) data model.

export type OastChannel = 'dns' | 'http' | 'https' | 'unknown';

/** A unique payload emitted during active testing, linked to its origin. */
export interface OastPayload {
  /** Unique per-execution token (DNS-label-safe); the correlation key. */
  token: string;
  /** Full injected callback URL (http://<token>.<collab>/<token>). */
  url: string;
  /** Callback hostname (<token>.<collab>). */
  host: string;
  /** Scan/swarm execution id that emitted this payload. */
  scanId: string;
  /** Bug-bounty program (for report/query scoping). */
  program: string;
  /** The in-scope endpoint the payload was injected into. */
  target: string;
  /** Injection vector, e.g. "param:url" or "header:Referer". */
  vector: string;
  createdAt: string;
  /** Set once an out-of-band interaction is correlated back. */
  hit?: boolean;
  firstHitAt?: string;
  hitCount?: number;
}

/** A recorded out-of-band interaction from the collaborator. */
export interface OastHit {
  token: string;
  channel: OastChannel;
  host: string;
  remoteAddress?: string;
  at: string;
  path?: string;
  raw?: string;
}

export interface OastResults {
  configured: boolean;
  callbackDomain: string | null;
  total: number;
  hitCount: number;
  confirmed: number;
  lastPollAt: string | null;
  payloads: OastPayload[];
  hits: OastHit[];
}

export interface OastPollSummary {
  configured: boolean;
  polled: number;
  newHits: number;
  confirmed: number;
  since: string;
  at: string;
  error?: string;
}
