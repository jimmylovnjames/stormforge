/** In-memory KVNamespace for unit tests (no Cloudflare runtime). */

export function memoryKv(): KVNamespace {
  const map = new Map<string, string>();

  return {
    async get(key: string, type?: string): Promise<string | null | unknown> {
      const v = map.get(key);
      if (v === undefined) return null;
      if (type === 'json') {
        try {
          return JSON.parse(v);
        } catch {
          return null;
        }
      }
      return v;
    },
    async put(key: string, value: string): Promise<void> {
      map.set(key, value);
    },
    async delete(key: string): Promise<void> {
      map.delete(key);
    },
    async list(options?: { prefix?: string }): Promise<{
      keys: { name: string }[];
      list_complete: boolean;
      cacheStatus: null;
    }> {
      const prefix = options?.prefix ?? '';
      const keys = [...map.keys()]
        .filter((k) => k.startsWith(prefix))
        .map((name) => ({ name }));
      return { keys, list_complete: true, cacheStatus: null };
    },
  } as unknown as KVNamespace;
}
