// Minimal, dependency-free version comparison for dotted numeric versions.

/** Returns -1 if a<b, 0 if equal, 1 if a>b. Non-numeric parts compared lexically. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.\-+]/);
  const pb = b.split(/[.\-+]/);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const sa = pa[i] ?? '0';
    const sb = pb[i] ?? '0';
    const na = Number(sa);
    const nb = Number(sb);
    const bothNumeric = !Number.isNaN(na) && !Number.isNaN(nb);
    if (bothNumeric) {
      if (na < nb) return -1;
      if (na > nb) return 1;
    } else {
      if (sa < sb) return -1;
      if (sa > sb) return 1;
    }
  }
  return 0;
}
