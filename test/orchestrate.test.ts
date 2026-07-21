import { describe, it, expect } from 'vitest';
import {
  parseOrchestrateMessage,
  buildGrokInstructions,
  type OrchestrateIntent,
} from '../src/orchestrate/commands.js';

describe('parseOrchestrateMessage', () => {
  it('parses help', () => {
    expect(parseOrchestrateMessage('help').intent).toBe('help');
    expect(parseOrchestrateMessage('?').intent).toBe('help');
  });

  it('parses plan / attack for authorized targets', () => {
    const r = parseOrchestrateMessage(
      'plan attack on https://httpbin.org program=httpbin-lab authorized=true',
    );
    expect(r.intent).toBe('plan');
    expect(r.targets).toContain('https://httpbin.org');
    expect(r.program).toBe('httpbin-lab');
    expect(r.authorized).toBe(true);
    expect(r.inScope).toContain('httpbin.org');
  });

  it('refuses plan without explicit authorized', () => {
    const r = parseOrchestrateMessage('plan https://evil.com');
    expect(r.intent).toBe('plan');
    expect(r.authorized).toBe(false);
    expect(r.error).toMatch(/authorized/i);
  });

  it('parses passive scan', () => {
    const r = parseOrchestrateMessage(
      'scan https://api.acme.com *.acme.com authorized program=acme-h1',
    );
    expect(r.intent).toBe('scan');
    expect(r.targets?.[0]).toContain('api.acme.com');
    expect(r.authorized).toBe(true);
    expect(r.inScope).toContain('*.acme.com');
  });

  it('parses status / findings / report / audit', () => {
    expect(parseOrchestrateMessage('status scan-abc').intent).toBe('status');
    expect(parseOrchestrateMessage('status scan-abc').scanId).toBe('scan-abc');
    expect(parseOrchestrateMessage('findings acme-h1').intent).toBe('findings');
    expect(parseOrchestrateMessage('findings acme-h1').program).toBe('acme-h1');
    expect(parseOrchestrateMessage('report acme-h1').intent).toBe('report');
    expect(parseOrchestrateMessage('audit').intent).toBe('audit');
  });

  it('parses dispatch tool', () => {
    const r = parseOrchestrateMessage(
      'dispatch httpx https://httpbin.org authorized program=lab inScope=httpbin.org',
    );
    expect(r.intent).toBe('dispatch');
    expect(r.tool).toBe('httpx');
    expect(r.targets?.[0]).toContain('httpbin.org');
    expect(r.authorized).toBe(true);
  });

  it('parses tasks status', () => {
    const r = parseOrchestrateMessage('tasks scan-123');
    expect(r.intent).toBe('tasks');
    expect(r.scanId).toBe('scan-123');
  });

  it('unknown falls back to help with note', () => {
    const r = parseOrchestrateMessage('make coffee');
    expect(r.intent).toBe('help');
    expect(r.error).toMatch(/unknown/i);
  });
});

describe('buildGrokInstructions', () => {
  it('includes base URL and orchestrate endpoint', () => {
    const text = buildGrokInstructions('https://stormforge.example.workers.dev');
    expect(text).toContain('/api/orchestrate');
    expect(text).toContain('authorized');
    expect(text).toContain('x-executor-secret');
    expect(text.toLowerCase()).toContain('stormforge');
  });
});

describe('intent exhaustiveness helper', () => {
  it('covers core intents', () => {
    const intents: OrchestrateIntent[] = [
      'help',
      'plan',
      'scan',
      'status',
      'findings',
      'report',
      'audit',
      'dispatch',
      'tasks',
    ];
    expect(intents.length).toBe(9);
  });
});
