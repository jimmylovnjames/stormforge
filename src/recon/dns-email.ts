// Pure analysis of a domain's email-auth DNS posture (SPF / DMARC).
//
// The scanner performs the DoH TXT lookups and hands the raw TXT strings here
// as a synthetic probe; this module is side-effect free and unit-testable.
// Weak SPF/DMARC enables email spoofing/phishing from the domain — a common
// accepted low/medium in bug-bounty programs.

/** Marker header the scanner sets on the synthetic email-DNS probe. */
export const EMAIL_DNS_MARKER = 'email-lookup';

export interface EmailDnsInput {
  domain: string;
  /** TXT records at the apex (SPF lives here). */
  spfTxts: string[];
  /** TXT records at _dmarc.<domain>. */
  dmarcTxts: string[];
}

export type SpfAll = '-all' | '~all' | '?all' | '+all' | 'none';
export type DmarcPolicy = 'none' | 'quarantine' | 'reject' | 'missing';

export interface EmailIssue {
  key: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  detail: string;
  record: string;
}

/** Extract TXT record strings from a Cloudflare DoH JSON answer. */
export function txtStringsFromDoh(json: {
  Answer?: Array<{ type: number; data: string }>;
}): string[] {
  return (json.Answer ?? [])
    .filter((a) => a.type === 16)
    // DoH returns TXT quoted, possibly as concatenated "chunk1" "chunk2".
    .map((a) => a.data.replace(/"\s+"/g, '').replace(/^"|"$/g, '').trim())
    .filter(Boolean);
}

export function classifySpf(txts: string[]): { record?: string; all: SpfAll } {
  const record = txts.find((t) => /^v=spf1\b/i.test(t.trim()));
  if (!record) return { all: 'none' };
  const m = /([-~?+])all\b/i.exec(record);
  if (!m) return { record, all: 'none' };
  return { record, all: `${m[1]}all` as SpfAll };
}

export function classifyDmarc(txts: string[]): { record?: string; policy: DmarcPolicy } {
  const record = txts.find((t) => /^v=DMARC1\b/i.test(t.trim()));
  if (!record) return { policy: 'missing' };
  const m = /\bp\s*=\s*(none|quarantine|reject)\b/i.exec(record);
  return { record, policy: (m ? m[1]!.toLowerCase() : 'none') as DmarcPolicy };
}

/**
 * Assess SPF + DMARC posture and return concrete issues. A domain is
 * "spoofable" when SPF is absent/weak AND DMARC does not enforce — that
 * combination is surfaced as a single medium rather than two low findings.
 */
export function analyzeEmailPosture(input: EmailDnsInput): EmailIssue[] {
  const spf = classifySpf(input.spfTxts);
  const dmarc = classifyDmarc(input.dmarcTxts);
  const issues: EmailIssue[] = [];

  const spfWeak = !spf.record || spf.all === '+all' || spf.all === '?all' || spf.all === 'none';
  const dmarcWeak = dmarc.policy === 'missing' || dmarc.policy === 'none';

  // Explicit +all is dangerous regardless of DMARC — anyone may send as the domain.
  if (spf.record && spf.all === '+all') {
    issues.push({
      key: 'spf-permissive',
      title: `SPF record allows any sender (+all) for ${input.domain}`,
      severity: 'high',
      detail: 'The SPF policy ends in `+all`, authorizing every host to send mail as this domain.',
      record: spf.record,
    });
  }

  if (spfWeak && dmarcWeak) {
    issues.push({
      key: 'email-spoofable',
      title: `Email spoofing possible for ${input.domain} (weak SPF + DMARC)`,
      severity: 'medium',
      detail: `SPF is ${spf.record ? `present but non-enforcing (${spf.all})` : 'absent'} and DMARC is ${
        dmarc.policy === 'missing' ? 'absent' : `p=none`
      }; mail can be spoofed from this domain and will pass or bypass alignment checks.`,
      record: `SPF: ${spf.record ?? '<none>'} | DMARC: ${dmarc.record ?? '<none>'}`,
    });
    return issues; // combined finding supersedes the individual low ones
  }

  if (!spf.record) {
    issues.push({
      key: 'spf-missing',
      title: `No SPF record for ${input.domain}`,
      severity: 'low',
      detail: 'No `v=spf1` TXT record was found; receivers cannot validate authorized senders.',
      record: '<none>',
    });
  } else if (spf.all === '?all' || spf.all === 'none') {
    issues.push({
      key: 'spf-weak',
      title: `Weak SPF policy (${spf.all}) for ${input.domain}`,
      severity: 'low',
      detail: 'The SPF policy does not end in `~all` or `-all`, so unauthorized senders are not soft/hard failed.',
      record: spf.record,
    });
  }

  if (dmarc.policy === 'missing') {
    issues.push({
      key: 'dmarc-missing',
      title: `No DMARC record for ${input.domain}`,
      severity: 'medium',
      detail: 'No DMARC record at `_dmarc` — receivers have no policy to reject/quarantine spoofed mail.',
      record: '<none>',
    });
  } else if (dmarc.policy === 'none') {
    issues.push({
      key: 'dmarc-none',
      title: `DMARC policy is p=none for ${input.domain}`,
      severity: 'low',
      detail: 'DMARC is monitor-only (`p=none`); spoofed mail is still delivered.',
      record: dmarc.record ?? '',
    });
  }

  return issues;
}
