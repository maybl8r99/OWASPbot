import { test, expect } from '@playwright/test';
import { sqliPayloads, sqliErrorPatterns } from '../fixtures/payloads';
import { DASTReporter, findForms } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('SQL Injection Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('Check for SQL injection in URL parameters', async ({ page }) => {
    const testUrls = [
      '/?id=',
      '/?user=',
      '/?item=',
      '/?product=',
      '/?category=',
      '/?page=',
      '/?record=',
    ];

    for (const baseUrl of testUrls) {
      for (const payload of sqliPayloads.slice(0, 5)) {
        const testUrl = baseUrl + encodeURIComponent(payload);
        
        try {
          const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
          
          if (!response) continue;

          const pageContent = await page.content();
          
          for (const pattern of sqliErrorPatterns) {
            if (pattern.test(pageContent)) {
              reporter.addFinding({
                severity: 'critical',
                title: 'SQL Injection Vulnerability',
                description: `SQL error message detected in response, indicating potential SQLi vulnerability`,
                url: testUrl,
                payload,
                evidence: `Pattern matched: ${pattern}`,
                cwe: 'CWE-89',
                owasp: 'A03:2021 - Injection',
                recommendation: 'Use parameterized queries/prepared statements for all database operations',
              });
              break;
            }
          }
        } catch (e) {
          // Continue on error
        }
      }
    }
  });

  test('Check for SQL injection in forms', async ({ page }) => {
    const forms = await findForms(page);
    const testedParams = new Set<string>();

    for (const form of forms) {
      for (const inputName of form.inputs) {
        if (testedParams.has(inputName)) continue;
        testedParams.add(inputName);

        for (const payload of sqliPayloads.slice(0, 3)) {
          try {
            await page.goto('/');
            
            const input = page.locator(`[name="${inputName}"]`).first();
            if (await input.count() === 0) continue;

            await input.fill(payload);
            
            const submitButton = page.locator('button[type="submit"], input[type="submit"]').first();
            if (await submitButton.count() > 0) {
              await submitButton.click();
              await page.waitForTimeout(2000);

              const pageContent = await page.content();
              
              for (const pattern of sqliErrorPatterns) {
                if (pattern.test(pageContent)) {
                  reporter.addFinding({
                    severity: 'critical',
                    title: 'SQL Injection in Form',
                    description: `SQL error detected in form submission for field "${inputName}"`,
                    url: page.url(),
                    payload,
                    evidence: `Pattern matched: ${pattern}`,
                    cwe: 'CWE-89',
                    owasp: 'A03:2021 - Injection',
                    recommendation: 'Use parameterized queries and input validation',
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
    }
  });

  test('Check for blind SQL injection timing attacks', async ({ page, request }) => {
    const timingPayloads = [
      "'; WAITFOR DELAY '0:0:5'--",
      "'; SELECT SLEEP(5)--",
      "' OR SLEEP(5)--",
    ];

    const testEndpoints = [
      '/api/users',
      '/api/items',
      '/api/search',
    ];

    for (const endpoint of testEndpoints) {
      for (const payload of timingPayloads) {
        try {
          const startTime = Date.now();
          
          await request.get(endpoint, {
            params: { id: payload },
            timeout: 10000,
          }).catch(() => {});
          
          const elapsed = Date.now() - startTime;

          if (elapsed >= 4500) {
            reporter.addFinding({
              severity: 'high',
              title: 'Potential Blind SQL Injection (Timing)',
              description: `Response delay suggests possible time-based blind SQLi`,
              url: endpoint,
              payload,
              evidence: `Response time: ${elapsed}ms`,
              cwe: 'CWE-89',
              owasp: 'A03:2021 - Injection',
              recommendation: 'Use parameterized queries and implement request timeouts',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });
});
