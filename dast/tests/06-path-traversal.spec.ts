import { test, expect } from '@playwright/test';
import { pathTraversalPayloads } from '../fixtures/payloads';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Path Traversal Tests', () => {
  test('Check for path traversal in URL parameters', async ({ page, request }) => {
    const testUrls = [
      '/?file=',
      '/?path=',
      '/?page=',
      '/?template=',
      '/?include=',
      '/?load=',
      '/?read=',
      '/?doc=',
      '/?document=',
      '/?resource=',
      '/download?file=',
      '/static?path=',
      '/api/files?name=',
    ];

    const sensitiveFilePatterns = [
      /root:x:0:0:/,
      /daemon:x:1:1:/,
      /nobody:x:/,
      /\[boot loader\]/i,
      /\[operating systems\]/i,
      /<?xml/i,
      /<configuration>/i,
      /<connectionStrings>/i,
      /DEBUG/i,
      /LOG/,
    ];

    for (const baseUrl of testUrls) {
      for (const payload of pathTraversalPayloads.slice(0, 5)) {
        const testUrl = baseUrl + encodeURIComponent(payload);
        
        try {
          const response = await request.get(testUrl, { timeout: 10000 });
          const status = response.status();
          const body = await response.text().catch(() => '');
          
          if (status === 200 && body.length > 0) {
            for (const pattern of sensitiveFilePatterns) {
              if (pattern.test(body)) {
                reporter.addFinding({
                  severity: 'critical',
                  title: 'Path Traversal Vulnerability',
                  description: `Sensitive file content accessible via path traversal`,
                  url: testUrl,
                  payload,
                  evidence: `Sensitive content pattern matched: ${pattern}`,
                  cwe: 'CWE-22',
                  owasp: 'A01:2021 - Broken Access Control',
                  recommendation: 'Validate file paths against a whitelist and use safe file access methods',
                });
                break;
              }
            }
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for path traversal in API endpoints', async ({ request }) => {
    const endpoints = [
      '/api/files/',
      '/api/download/',
      '/api/documents/',
      '/files/',
      '/static/',
      '/uploads/',
    ];

    for (const endpoint of endpoints) {
      for (const payload of pathTraversalPayloads.slice(0, 3)) {
        const testUrl = endpoint + payload;
        
        try {
          const response = await request.get(testUrl, { timeout: 10000 });
          const status = response.status();
          
          if (status === 200) {
            const body = await response.text().catch(() => '');
            
            if (body.includes('root:') || body.includes('[boot loader]')) {
              reporter.addFinding({
                severity: 'critical',
                title: 'Path Traversal in API Endpoint',
                description: `Path traversal allows access to sensitive system files`,
                url: testUrl,
                payload,
                cwe: 'CWE-22',
                owasp: 'A01:2021 - Broken Access Control',
                recommendation: 'Sanitize file paths and restrict file access to approved directories',
              });
            }
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });
});
