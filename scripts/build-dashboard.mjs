// Regenerates src/dashboard-html.ts from dashboard/index.html so the Worker can
// serve the dashboard inline (no static-assets binding required).
//
//   node scripts/build-dashboard.mjs

import { readFileSync, writeFileSync } from 'node:fs';

const html = readFileSync('dashboard/index.html', 'utf8');
const escaped = html.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
const out =
  `// AUTO-GENERATED from dashboard/index.html — do not edit by hand.\n` +
  `// Regenerate: node scripts/build-dashboard.mjs\n` +
  `export const DASHBOARD_HTML = \`${escaped}\`;\n`;
writeFileSync('src/dashboard-html.ts', out);
console.log('wrote src/dashboard-html.ts');
