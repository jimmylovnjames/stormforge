import { describe, it, expect } from 'vitest';
import { evaluateScope, hostMatches, partitionByScope, assertInScope, ScopeError } from '../src/scope/scope-guard.js';
import type { Scope } from '../src/types.js';

const scope: Scope = {
  program: 'acme',
  platform: 'hackerone',
  inScope: ['*.acme.com', 'api.other.com'],
  outOfScope: ['blog.acme.com'],
  authorized: true,
};

describe('hostMatches', () => {
  it('matches exact host', () => {
    expect(hostMatches('api.other.com', 'api.other.com')).toBe(true);
  });
  it('matches wildcard subdomain but not apex', () => {
    expect(hostMatches('a.acme.com', '*.acme.com')).toBe(true);
    expect(hostMatches('acme.com', '*.acme.com')).toBe(false);
  });
  it('does not match unrelated host', () => {
    expect(hostMatches('evil.com', '*.acme.com')).toBe(false);
  });
});

describe('evaluateScope', () => {
  it('allows in-scope subdomain', () => {
    expect(evaluateScope('https://x.acme.com/path', scope).allowed).toBe(true);
  });
  it('refuses out-of-scope override even under wildcard', () => {
    const d = evaluateScope('https://blog.acme.com', scope);
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('out-of-scope');
  });
  it('refuses host not listed', () => {
    expect(evaluateScope('https://evil.com', scope).allowed).toBe(false);
  });
  it('refuses everything when not authorized', () => {
    const d = evaluateScope('https://x.acme.com', { ...scope, authorized: false });
    expect(d.allowed).toBe(false);
  });
});

describe('partitionByScope', () => {
  it('splits allowed and refused', () => {
    const { allowed, refused } = partitionByScope(
      ['https://api.acme.com', 'https://evil.com', 'https://blog.acme.com'],
      scope,
    );
    expect(allowed).toEqual(['https://api.acme.com']);
    expect(refused.map((r) => r.target)).toEqual(['https://evil.com', 'https://blog.acme.com']);
  });
});

describe('assertInScope', () => {
  it('throws ScopeError for out-of-scope target', () => {
    expect(() => assertInScope('https://evil.com', scope)).toThrow(ScopeError);
  });
  it('does not throw for in-scope target', () => {
    expect(() => assertInScope('https://api.acme.com', scope)).not.toThrow();
  });
});
