// Blind SSRF / OAST canary tokens stored in KV.
// Worker canary endpoint records hits; scanner confirms SSRF when a hit appears.

export interface CanaryHit {
  token: string;
  hitAt: string;
  method: string;
  userAgent: string;
  cfConnectingIp?: string;
  path: string;
}

export interface CanaryPending {
  token: string;
  scanId: string;
  program: string;
  probeUrl: string;
  createdAt: string;
}

export function canaryHitKey(token: string): string {
  return `canary:hit:${token}`;
}

export function canaryPendingKey(token: string): string {
  return `canary:pending:${token}`;
}

/** Opaque token safe for URL path segments. */
export function newCanaryToken(): string {
  return crypto.randomUUID().replace(/-/g, '');
}

export function isCanaryToken(token: string): boolean {
  return /^[a-f0-9]{16,64}$/i.test(token);
}

export function buildCanaryUrl(baseUrl: string, token: string): string {
  const base = baseUrl.replace(/\/$/, '');
  return `${base}/api/canary/${token}`;
}

export function urlCarriesBlindCanary(url: string, token?: string): boolean {
  try {
    const values = [...new URL(url).searchParams.values()];
    if (token) return values.some((v) => v.includes(`/api/canary/${token}`));
    return values.some((v) => /\/api\/canary\/[a-f0-9]{16,}/i.test(v));
  } catch {
    return false;
  }
}

export async function recordCanaryHit(
  kv: KVNamespace,
  token: string,
  hit: Omit<CanaryHit, 'token'>,
): Promise<void> {
  const payload: CanaryHit = { token, ...hit };
  await kv.put(canaryHitKey(token), JSON.stringify(payload), { expirationTtl: 86_400 });
}

export async function getCanaryHit(kv: KVNamespace, token: string): Promise<CanaryHit | null> {
  const raw = await kv.get(canaryHitKey(token));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CanaryHit;
  } catch {
    return null;
  }
}

export async function putCanaryPending(kv: KVNamespace, pending: CanaryPending): Promise<void> {
  await kv.put(canaryPendingKey(pending.token), JSON.stringify(pending), { expirationTtl: 3600 });
}

export async function getCanaryPending(
  kv: KVNamespace,
  token: string,
): Promise<CanaryPending | null> {
  const raw = await kv.get(canaryPendingKey(token));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CanaryPending;
  } catch {
    return null;
  }
}
