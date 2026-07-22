// Findings persistence + dedupe on top of KV.
//
// Findings are keyed by their stable id, so re-scanning an asset updates rather
// than duplicates. Also maintains a per-program index for report assembly.

import type { Finding } from '../types.js';
import { enrichAndFilterFindings, type QualityContext } from './quality.js';
import { canonicalizeTarget } from './canonicalize.js';
import { makeFindingId } from './id.js';

const FINDING_PREFIX = 'finding:';
const INDEX_PREFIX = 'index:';

export class FindingsStore {
  constructor(private readonly kv: KVNamespace) {}

  private findingKey(program: string, id: string): string {
    return `${FINDING_PREFIX}${program}:${id}`;
  }

  private indexKey(program: string): string {
    return `${INDEX_PREFIX}${program}`;
  }

  /**
   * Upsert a batch after quality filtering. Returns new vs updated counts.
   * Prefer keeping the higher-confidence / higher-severity record on conflict.
   */
  async upsertMany(
    program: string,
    findings: Finding[],
    opts?: { ctx?: QualityContext; keepRecon?: boolean },
  ): Promise<{ added: number; updated: number; dropped: number }> {
    const filtered = enrichAndFilterFindings(findings, opts);
    const dropped = findings.length - filtered.length;
    const index = new Set(await this.getIndex(program));
    let added = 0;
    let updated = 0;

    for (const incoming of filtered) {
      // Re-key with canonical target when possible for cross-source stability.
      const id =
        incoming.id ||
        makeFindingId(incoming.checkId, incoming.target, incoming.title.slice(0, 80));
      const f: Finding = {
        ...incoming,
        id,
        canonicalTarget: incoming.canonicalTarget || canonicalizeTarget(incoming.target),
      };

      const existed = index.has(f.id);
      if (existed) {
        const prev = await this.get(program, f.id);
        const keep = preferFinding(prev, f);
        await this.kv.put(this.findingKey(program, f.id), JSON.stringify(keep));
        updated++;
      } else {
        await this.kv.put(this.findingKey(program, f.id), JSON.stringify(f));
        added++;
        index.add(f.id);
      }
    }
    await this.kv.put(this.indexKey(program), JSON.stringify([...index]));
    return { added, updated, dropped };
  }

  async getIndex(program: string): Promise<string[]> {
    const raw = await this.kv.get(this.indexKey(program));
    return raw ? (JSON.parse(raw) as string[]) : [];
  }

  async getAll(program: string): Promise<Finding[]> {
    const ids = await this.getIndex(program);
    const out: Finding[] = [];
    for (const id of ids) {
      const raw = await this.kv.get(this.findingKey(program, id));
      if (raw) out.push(JSON.parse(raw) as Finding);
    }
    return out;
  }

  async get(program: string, id: string): Promise<Finding | null> {
    const raw = await this.kv.get(this.findingKey(program, id));
    return raw ? (JSON.parse(raw) as Finding) : null;
  }
}

function preferFinding(prev: Finding | null, incoming: Finding): Finding {
  if (!prev) return incoming;
  const score = (f: Finding) =>
    (f.confidence ?? 0.5) * 10 +
    ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 }[f.severity] ?? 0);
  if (score(incoming) >= score(prev)) {
    return {
      ...incoming,
      discoveredAt: prev.discoveredAt || incoming.discoveredAt,
      evidence:
        incoming.evidence.length >= (prev.evidence?.length ?? 0) ? incoming.evidence : prev.evidence,
    };
  }
  return prev;
}
