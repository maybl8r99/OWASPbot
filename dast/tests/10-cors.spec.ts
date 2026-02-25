import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('CORS Misconfiguration Tests', () => {
  test('Check for overly permissive CORS', async ({ request }) => {
    const baseUrl = process.env.TARGET_ENDPOINT || 'http://localhost:3000';
    
    const testOrigins = [
      'https://evil.com',
      'https://attacker.com',
      'https://null',
      'null',
    ];

    const sensitiveEndpoints = [
      '/',
      '/api',
      '/api/user',
      '/api/users',
      '/api/session',
      '/api/account',
    ];

    for (const endpoint of sensitiveEndpoints) {
      for (const origin of testOrigins) {
        try {
          const response = await request.get(endpoint, {
            headers: {
              'Origin': origin,
            },
          });

          const acao = response.headers()['access-control-allow-origin'];
          const acac = response.headers()['access-control-allow-credentials'];

          if (acao === '*') {
            reporter.addFinding({
              severity: 'high',
              title: 'Overly Permissive CORS',
              description: 'Access-Control-Allow-Origin header is set to *',
              url: endpoint,
              evidence: 'Access-Control-Allow-Origin: *',
              cwe: 'CWE-942',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Restrict CORS to specific trusted origins',
            });
          }

          if (acao === origin && acac === 'true') {
            reporter.addFinding({
              severity: 'critical',
              title: 'CORS Allows Arbitrary Origin with Credentials',
              description: `Server reflects arbitrary origin with credentials enabled`,
              url: endpoint,
              evidence: `Origin: ${origin}, ACAO: ${acao}, ACAC: ${acac}`,
              cwe: 'CWE-942',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Validate origin against a whitelist and avoid reflecting arbitrary origins',
            });
          }

          if (acao === 'null') {
            reporter.addFinding({
              severity: 'high',
              title: 'CORS Allows Null Origin',
              description: 'Server allows null origin which can be exploited via sandboxed iframes',
              url: endpoint,
              evidence: 'Access-Control-Allow-Origin: null',
              cwe: 'CWE-942',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Block null origin in CORS policy',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for CORS preflight handling', async ({ request }) => {
    const endpoints = ['/api', '/api/user', '/api/data'];

    for (const endpoint of endpoints) {
      try {
        const response = await request.fetch(endpoint, {
          method: 'OPTIONS',
          headers: {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type, Authorization',
          },
        });

        const acao = response.headers()['access-control-allow-origin'];
        const acam = response.headers()['access-control-allow-methods'];
        const acah = response.headers()['access-control-allow-headers'];

        if (acao === '*' || acao === 'https://evil.com') {
          const methods = acam ? acam.split(',').map(m => m.trim()) : [];
          const dangerousMethods = ['PUT', 'DELETE', 'PATCH'];
          
          const hasDangerousMethods = methods.some(m => 
            dangerousMethods.includes(m.toUpperCase())
          );

          if (hasDangerousMethods) {
            reporter.addFinding({
              severity: 'medium',
              title: 'CORS Exposes Dangerous Methods',
              description: `Preflight response exposes dangerous HTTP methods`,
              url: endpoint,
              evidence: `Methods allowed: ${acam}`,
              cwe: 'CWE-942',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Only expose necessary HTTP methods in CORS policy',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
