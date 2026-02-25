import { test, expect } from '@playwright/test';
import { commandInjectionPayloads } from '../fixtures/payloads';
import { DASTReporter, findForms } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Command Injection Tests', () => {
  test('Check for command injection in URL parameters', async ({ page }) => {
    const testUrls = [
      '/?file=',
      '/?path=',
      '/?name=',
      '/?cmd=',
      '/?exec=',
      '/?command=',
      '/?run=',
      '/?ping=',
      '/?host=',
      '/?ip=',
    ];

    const errorPatterns = [
      /uid=\d+/,
      /gid=\d+/,
      /total \d+/,
      /drwx/,
      /-rw-/,
      /\/bin\/bash/,
      /\/bin\/sh/,
      /root:/,
      /nobody:/,
      /command not found/i,
      /syntax error/i,
    ];

    for (const baseUrl of testUrls) {
      for (const payload of commandInjectionPayloads.slice(0, 5)) {
        const testUrl = baseUrl + encodeURIComponent(payload);
        
        try {
          const response = await page.goto(testUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
          
          if (!response) continue;

          const pageContent = await page.content();
          
          for (const pattern of errorPatterns) {
            if (pattern.test(pageContent)) {
              reporter.addFinding({
                severity: 'critical',
                title: 'Command Injection Vulnerability',
                description: `Command output detected in response, indicating potential command injection`,
                url: testUrl,
                payload,
                evidence: `Pattern matched: ${pattern}`,
                cwe: 'CWE-78',
                owasp: 'A03:2021 - Injection',
                recommendation: 'Avoid shell commands with user input; use allowlists and input sanitization',
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

  test('Check for command injection in forms', async ({ page }) => {
    await page.goto('/');
    const forms = await findForms(page);

    const errorPatterns = [
      /uid=\d+/,
      /total \d+/,
      /drwx/,
      /\/bin\/bash/,
    ];

    for (const form of forms) {
      for (const inputName of form.inputs) {
        for (const payload of commandInjectionPayloads.slice(0, 2)) {
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
              
              for (const pattern of errorPatterns) {
                if (pattern.test(pageContent)) {
                  reporter.addFinding({
                    severity: 'critical',
                    title: 'Command Injection in Form',
                    description: `Command output detected in form submission`,
                    url: page.url(),
                    payload,
                    cwe: 'CWE-78',
                    owasp: 'A03:2021 - Injection',
                    recommendation: 'Use input validation and avoid shell command execution',
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
});
