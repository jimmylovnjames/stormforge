// Findings persistence + dedupe on top of KV.
//
// Findings are keyed by their stable id, so re-scanning an asset updates rather
// than duplicates. Also maintains a per-program index for report assembly.

import type { Finding } from '../types.js';

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

  /** Upsert a batch, returning how many were new vs. already known. */
  async upsertMany(program: string, findings: Finding[]): Promise<{ added: number; updated: number }> {
    const index = new Set(await this.getIndex(program));
    let added = 0;
    let updated = 0;

    for (const f of findings) {
      const existed = index.has(f.id);
      await this.kv.put(this.findingKey(program, f.id), JSON.stringify(f));
      if (existed) updated++;
      else {
        added++;
        index.add(f.id);
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
      if (raw) out.push(JSON.parse(raw) as Finding);
    }
    return out;
  }

  async get(program: string, id: string): Promise<Finding | null> {
    const raw = await this.kv.get(this.findingKey(program, id));
    return raw ? (JSON.parse(raw) as Finding) : null;
  }
}
