import { test, expect } from '@playwright/test';
import { xssPayloads } from '../fixtures/payloads';
import { DASTReporter, findForms } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('XSS (Cross-Site Scripting) Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('Check for reflected XSS in URL parameters', async ({ page, context }) => {
    const testUrls = [
      '/?q=',
      '/?search=',
      '/?query=',
      '/?id=',
      '/?name=',
      '/?input=',
      '/?value=',
      '/?param=',
    ];

    for (const baseUrl of testUrls) {
      for (const payload of xssPayloads.slice(0, 5)) {
        const testUrl = baseUrl + encodeURIComponent(payload);
        
        try {
          const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
          
          if (!response) continue;

          const pageContent = await page.content();
          const bodyText = await page.locator('body').innerText().catch(() => '');
          
          if (pageContent.includes(payload) || bodyText.includes('XSS')) {
            reporter.addFinding({
              severity: 'high',
              title: 'Potential Reflected XSS',
              description: `XSS payload may be reflected in page without proper sanitization`,
              url: testUrl,
              payload,
              evidence: `Payload found in response`,
              cwe: 'CWE-79',
              owasp: 'A03:2021 - Injection',
              recommendation: 'Sanitize and encode all user input before rendering in HTML',
            });
          }

          const hasAlert = await page.evaluate(() => {
            return window.hasOwnProperty('__xss_triggered__');
          }).catch(() => false);

          if (hasAlert) {
            reporter.addFinding({
              severity: 'critical',
              title: 'Confirmed Reflected XSS',
              description: `XSS payload was executed`,
              url: testUrl,
              payload,
              cwe: 'CWE-79',
              owasp: 'A03:2021 - Injection',
              recommendation: 'Sanitize and encode all user input before rendering in HTML',
            });
          }
        } catch (e) {
          // Continue on error
        }
      }
    }
  });

  test('Check for XSS in form inputs', async ({ page }) => {
    await page.goto('/');
    const forms = await findForms(page);

    for (const form of forms) {
      for (const inputName of form.inputs) {
        for (const payload of xssPayloads.slice(0, 3)) {
          try {
            await page.goto('/');
            
            const input = page.locator(`[name="${inputName}"]`).first();
            if (await input.count() === 0) continue;

            await input.fill(payload);
            
            const submitButton = page.locator('button[type="submit"], input[type="submit"]').first();
            if (await submitButton.count() > 0) {
              await submitButton.click();
              await page.waitForTimeout(1000);

              const pageContent = await page.content();
              if (pageContent.includes(payload)) {
                reporter.addFinding({
                  severity: 'high',
                  title: 'Potential XSS in Form Input',
                  description: `XSS payload in form field "${inputName}" may be reflected`,
                  url: page.url(),
                  payload,
                  cwe: 'CWE-79',
                  owasp: 'A03:2021 - Injection',
                  recommendation: 'Sanitize all form inputs server-side and encode output',
                });
              }
            }
          } catch (e) {
            // Continue on error
          }
        }
      }
    }
  });

  test('Check for DOM-based XSS', async ({ page }) => {
    const domXssPayloads = [
      '#<script>alert("XSS")</script>',
      '#"><img src=x onerror=alert("XSS")>',
      '#javascript:alert("XSS")',
    ];

    for (const payload of domXssPayloads) {
      try {
        await page.goto(payload, { waitUntil: 'domcontentloaded' });
        await page.waitForTimeout(500);

        const pageContent = await page.content();
        if (pageContent.includes('alert') || pageContent.includes('XSS')) {
          reporter.addFinding({
            severity: 'high',
            title: 'Potential DOM-based XSS',
            description: 'Page may be vulnerable to DOM-based XSS via URL fragment',
            url: page.url(),
            payload,
            cwe: 'CWE-79',
            owasp: 'A03:2021 - Injection',
            recommendation: 'Avoid using unsafe client-side JavaScript that processes URL fragments',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
