import { test, expect } from '@playwright/test';
import { openRedirectPayloads } from '../fixtures/payloads';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Open Redirect Tests', () => {
  test('Check for open redirect in URL parameters', async ({ page, context }) => {
    test.setTimeout(120000);
    const redirectParams = ['url', 'redirect', 'next', 'return', 'returnUrl', 'return_url', 
                            'goto', 'target', 'dest', 'destination', 'redir', 'redirect_uri',
                            'continue', 'callback', 'forward', 'out', 'link'];

    for (const param of redirectParams) {
      for (const payload of openRedirectPayloads.slice(0, 5)) {
        const testUrl = `/?${param}=${encodeURIComponent(payload)}`;
        
        try {
          const response = await page.goto(testUrl, { waitUntil: 'commit', timeout: 10000 });
          
          if (!response) continue;

          await page.waitForTimeout(500);
          const currentUrl = page.url();
          const baseUrl = process.env.TARGET_ENDPOINT || 'http://localhost:3000';
          
          if (!currentUrl.startsWith(baseUrl) && !currentUrl.startsWith('about:')) {
            reporter.addFinding({
              severity: 'high',
              title: 'Open Redirect Vulnerability',
              description: `Application redirects to external URL via "${param}" parameter`,
              url: testUrl,
              payload,
              evidence: `Redirected to: ${currentUrl}`,
              cwe: 'CWE-601',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Implement a whitelist of allowed redirect URLs or use relative paths',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for open redirect via header injection', async ({ request }) => {
    const payloads = [
      'https://evil.com',
      '//evil.com',
      'https://evil.com%0d%0aSet-Cookie:malicious=true',
    ];

    for (const payload of payloads) {
      try {
        const response = await request.get('/', {
          headers: {
            'X-Forwarded-Host': 'evil.com',
            'X-Original-URL': payload,
            'X-Rewrite-URL': payload,
          },
          maxRedirects: 0,
        });

        const location = response.headers()['location'];
        if (location && location.includes('evil.com')) {
          reporter.addFinding({
            severity: 'medium',
            title: 'Potential Header-Based Redirect',
            description: 'Server may be vulnerable to redirect via header manipulation',
            url: '/',
            payload,
            evidence: `Location header: ${location}`,
            cwe: 'CWE-601',
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Validate and sanitize all headers used for redirects',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for meta refresh redirects', async ({ page }) => {
    const redirectParams = ['url', 'redirect', 'next', 'goto'];

    for (const param of redirectParams) {
      const payload = 'https://evil.com';
      const testUrl = `/?${param}=${encodeURIComponent(payload)}`;
      
      try {
        await page.goto(testUrl, { waitUntil: 'domcontentloaded' });
        
        const metaRefresh = await page.$('meta[http-equiv="refresh"]');
        if (metaRefresh) {
          const content = await metaRefresh.getAttribute('content');
          if (content && content.includes('evil.com')) {
            reporter.addFinding({
              severity: 'high',
              title: 'Open Redirect via Meta Refresh',
              description: 'Application uses meta refresh tag with user-controlled URL',
              url: testUrl,
              payload,
              evidence: `Meta refresh content: ${content}`,
              cwe: 'CWE-601',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Avoid using meta refresh with user-supplied URLs',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
