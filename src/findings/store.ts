// Findings persistence + dedupe on top of KV.
//
// Findings are keyed by their stable id, so re-scanning an asset updates rather
// than duplicates. Also maintains a per-program index for report assembly.

import type { Finding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { compareSeverityDesc } from './severity.js';
import { enrichFinding } from './confidence.js';

const FINDING_PREFIX = 'finding:';
const INDEX_PREFIX = 'index:';

export interface FindingsQuery {
  checkId?: string;
  /** Minimum severity inclusive (e.g. 'high' → high + critical). */
  minSeverity?: Severity;
  /** Only findings marked submitReady after enrichment. */
  submitReadyOnly?: boolean;
}

export interface SecretFindingsSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  checkIds: string[];
}

export class FindingsStore {
  constructor(private readonly kv: KVNamespace) {}

  private findingKey(program: string, id: string): string {
    return `${FINDING_PREFIX}${program}:${id}`;
  }

  private indexKey(program: string): string {
    return `${INDEX_PREFIX}${program}`;
  }

  /** Upsert a batch, returning how many were new vs. already known. */
  async upsertMany(program: string, findings: Finding[]): Promise<{ added: number; updated: number }> {
    const index = new Set(await this.getIndex(program));
    let added = 0;
    let updated = 0;

    // Persist higher-severity first so interrupted writes still keep critical secrets.
    const ordered = [...findings].sort((a, b) => compareSeverityDesc(a.severity, b.severity));

    for (const f of ordered) {
      const enriched = enrichFinding(f);
      const existed = index.has(enriched.id);
      await this.kv.put(this.findingKey(program, enriched.id), JSON.stringify(enriched));
      if (existed) updated++;
      else {
        added++;
        index.add(enriched.id);
      }
    }
    await this.kv.put(this.indexKey(program), JSON.stringify([...index]));
    return { added, updated };
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
      if (raw) out.push(enrichFinding(JSON.parse(raw) as Finding));
    }
    return out.sort((a, b) => compareSeverityDesc(a.severity, b.severity));
  }

  async get(program: string, id: string): Promise<Finding | null> {
    const raw = await this.kv.get(this.findingKey(program, id));
    return raw ? (JSON.parse(raw) as Finding) : null;
  }

  /** Filter stored findings by check id and/or minimum severity. */
  async query(program: string, q: FindingsQuery = {}): Promise<Finding[]> {
    const all = await this.getAll(program);
    return all.filter((f) => {
      if (q.checkId && f.checkId !== q.checkId) return false;
      if (q.minSeverity && SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[q.minSeverity]) return false;
      if (q.submitReadyOnly && !f.submitReady) return false;
      return true;
    });
  }

  /** Replace one finding in-place (used when promoting candidates after tool confirm). */
  async put(program: string, finding: Finding): Promise<void> {
    const enriched = enrichFinding(finding);
    const index = new Set(await this.getIndex(program));
    index.add(enriched.id);
    await this.kv.put(this.findingKey(program, enriched.id), JSON.stringify(enriched));
    await this.kv.put(this.indexKey(program), JSON.stringify([...index]));
  }

  async getSecrets(program: string): Promise<Finding[]> {
    return this.query(program, { checkId: 'secret-exposure' });
  }
}

/** Summarize secret-exposure findings for report headers / API payloads. */
export function summarizeSecretFindings(findings: Finding[]): SecretFindingsSummary {
  const secrets = findings.filter((f) => f.checkId === 'secret-exposure');
  const bySeverity: Record<Severity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  for (const f of secrets) bySeverity[f.severity]++;
  return {
    total: secrets.length,
    bySeverity,
    checkIds: ['secret-exposure'],
  };
}
