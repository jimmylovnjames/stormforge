// Exposed OpenAPI/Swagger specifications and interactive API docs.
// Confirms via body signatures (version field + info/paths).

import type { Check, Finding, ProbeResult } from '../../types.js';
import { makeFindingId } from '../../findings/id.js';
import { parseBodySignals } from '../../recon/body-parse.js';
import {
  extractOpenApiRoutes,
  idorishRoutes,
  materializeIdorUrls,
  formatIdorCandidates,
} from '../../recon/openapi-extract.js';

export const apiSchemaExposureCheck: Check = {
  id: 'api-schema-exposure',
  title: 'Exposed API schema / docs UI',
  cwe: 'CWE-200',
  run(probe: ProbeResult): Finding[] {
    if (probe.error || !probe.body) return [];
    if (probe.status < 200 || probe.status >= 300) return [];

    const signals = probe.signals ?? parseBodySignals(probe.body, probe.headers, probe.status);
    const findings: Finding[] = [];

    if (signals.openApiVersion) {
      const hasPaths = signals.openApiPathCount > 0;
      const label = signals.openApiVersion.startsWith('openapi') ? 'OpenAPI' : 'Swagger';
      const version = signals.openApiVersion.replace(/^(openapi|swagger)-/, '');
      const routes = extractOpenApiRoutes(probe.body);
      const idorRoutes = idorishRoutes(routes);
      let origin = probe.url;
      try {
        origin = new URL(probe.finalUrl ?? probe.url).origin;
      } catch {
        /* keep probe.url */
      }
      const candidates = materializeIdorUrls(origin, idorRoutes, 12);
      const idorBlock = candidates.length
        ? `\nIDOR-shaped path templates: ${idorRoutes.map((r) => r.path).slice(0, 8).join(', ')}\nCandidate GETs:\n${formatIdorCandidates(candidates)}`
        : '';

      findings.push({
        id: makeFindingId(this.id, probe.url, signals.openApiVersion),
        checkId: this.id,
        title: hasPaths
          ? `Exposed ${label} ${version} specification (${signals.openApiPathCount} paths${idorRoutes.length ? `, ${idorRoutes.length} IDOR-shaped` : ''})`
          : `Exposed ${label} ${version} specification`,
        severity: 'high',
        target: probe.url,
        description: hasPaths
          ? `A complete ${label} document with ${signals.openApiPathCount} path definition(s) is publicly reachable. This maps authenticated and unauthenticated endpoints, parameters, and often auth schemes for attackers.${idorRoutes.length ? ` ${idorRoutes.length} path(s) look like object-level (IDOR/BOLA) targets.` : ''}`
          : `An ${label} document is publicly reachable. Even without enumerated paths this discloses API surface metadata.`,
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nContent-Type: ${probe.headers['content-type'] ?? '<absent>'}\nSpec: ${signals.openApiVersion}\nPath count: ${signals.openApiPathCount}\nBody preview: ${signals.preview}${idorBlock}`,
        reproduction: [
          `Fetch ${probe.url}`,
          `Confirm openapi/swagger version field and ${hasPaths ? 'paths object' : 'info block'}`,
          candidates.length
            ? `Probe candidate object endpoints (GET-only, within RoE): ${candidates[0]}`
            : 'Manually assess whether the schema is intentionally public before reporting',
        ],
        remediation:
          'Serve OpenAPI/Swagger specs only to authenticated operators or internal networks; remove production copies from the web root; enforce object-level authorization on every `{id}` route.',
        cwe: 'CWE-200',
        references: [
          'https://cwe.mitre.org/data/definitions/200.html',
          'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
        ],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: hasPaths ? (idorRoutes.length ? 0.92 : 0.9) : 0.75,
        submitReady: hasPaths,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    if (signals.swaggerUi) {
      findings.push({
        id: makeFindingId(this.id, probe.url, 'swagger-ui'),
        checkId: this.id,
        title: 'Swagger UI / ReDoc API docs exposed',
        severity: 'high',
        target: probe.url,
        description:
          'Interactive API documentation (Swagger UI or ReDoc) is publicly reachable. Combined with a live Try-it-out backend this accelerates endpoint discovery and abuse.',
        evidence: `URL: ${probe.url}\nStatus: ${probe.status}\nSignature: swagger-ui\nBody preview: ${signals.preview}`,
        reproduction: [
          `Open ${probe.url} in a browser`,
          'Confirm Swagger UI or ReDoc renders and lists operations',
        ],
        remediation:
          'Restrict API documentation UIs to authenticated staff or non-production environments.',
        cwe: 'CWE-200',
        references: ['https://cwe.mitre.org/data/definitions/200.html'],
        needsManualReview: true,
        evidenceGrade: 'fingerprint',
        confidence: 0.85,
        submitReady: true,
        source: 'worker',
        discoveredAt: new Date().toISOString(),
      });
    }

    return findings;
  },
};
