/** OpenAPI 3.1 document for Grok / xAI function-calling and mobile tooling. */

export function buildOpenApi(baseUrl: string): Record<string, unknown> {
  const base = baseUrl.replace(/\/$/, '');
  return {
    openapi: '3.1.0',
    info: {
      title: 'StormForge Orchestrate',
      version: '1.0.0',
      description:
        'Natural-language orchestration for authorized bug-bounty recon. Mutating commands require the word "authorized" in the message. Never auto-submits to bounty platforms.',
    },
    servers: [{ url: base }],
    paths: {
      '/api/orchestrate': {
        post: {
          operationId: 'stormforge_orchestrate',
          summary: 'Run a StormForge command from natural language',
          security: [{ ExecutorSecret: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['message'],
                  properties: {
                    message: {
                      type: 'string',
                      description:
                        'Operator command, e.g. "plan https://target authorized program=lab inScope=target.com"',
                    },
                  },
                },
              },
            },
          },
          responses: {
            '200': {
              description: 'Command result',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      ok: { type: 'boolean' },
                      text: { type: 'string' },
                      data: {},
                    },
                  },
                },
              },
            },
            '401': { description: 'Missing or invalid x-executor-secret' },
          },
        },
      },
      '/api/grok/instructions': {
        get: {
          operationId: 'stormforge_grok_instructions',
          summary: 'Fetch paste-ready Grok project / custom instructions',
          responses: {
            '200': {
              description: 'Plain-text instructions',
              content: { 'text/plain': { schema: { type: 'string' } } },
            },
          },
        },
      },
      '/m': {
        get: {
          operationId: 'stormforge_mobile_ui',
          summary: 'Mobile chat UI for orchestration',
          responses: { '200': { description: 'HTML' } },
        },
      },
    },
    components: {
      securitySchemes: {
        ExecutorSecret: {
          type: 'apiKey',
          in: 'header',
          name: 'x-executor-secret',
        },
      },
    },
  };
}
