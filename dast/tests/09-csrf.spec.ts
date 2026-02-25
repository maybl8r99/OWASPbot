import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('CSRF Tests', () => {
  test('Check for CSRF tokens in forms', async ({ page }) => {
    await page.goto('/');
    
    const forms = await page.$$('form');
    
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      const method = await form.getAttribute('method');
      
      if (method && method.toLowerCase() === 'post') {
        const csrfFields = await form.$$(
          'input[name*="csrf"], input[name*="token"], input[name*="_token"], ' +
          'input[name*="authenticity"], input[name*="__RequestVerificationToken"], ' +
          'input[type="hidden"][name]'
        );
        
        const formAction = await form.getAttribute('action') || 'current page';
        const formId = await form.getAttribute('id') || await form.getAttribute('name') || `form-${i}`;
        
        if (csrfFields.length === 0) {
          reporter.addFinding({
            severity: 'medium',
            title: 'Missing CSRF Protection',
            description: `POST form "${formId}" does not appear to have CSRF token protection`,
            url: page.url(),
            evidence: `Form action: ${formAction}`,
            cwe: 'CWE-352',
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Add CSRF tokens to all state-changing forms',
          });
        }
      }
    }
  });

  test('Check SameSite cookie attribute', async ({ page, context }) => {
    await page.goto('/');
    
    const cookies = await context.cookies();
    
    for (const cookie of cookies) {
      if (cookie.name.toLowerCase().includes('session') || 
          cookie.name.toLowerCase().includes('token') ||
          cookie.name.toLowerCase().includes('auth')) {
        
        if (!cookie.sameSite || cookie.sameSite === 'None') {
          reporter.addFinding({
            severity: 'medium',
            title: 'Cookie Missing SameSite Attribute',
            description: `Session cookie "${cookie.name}" has no or lax SameSite attribute`,
            url: page.url(),
            evidence: `SameSite: ${cookie.sameSite || 'not set'}`,
            cwe: 'CWE-352',
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Set SameSite=Strict or SameSite=Lax on session cookies',
          });
        }
      }
    }
  });

  test('Test cross-origin POST request', async ({ page, context, browser }) => {
    await page.goto('/');
    
    const forms = await page.$$('form[method="post"], form[method="POST"]');
    
    if (forms.length > 0) {
      const form = forms[0];
      const action = await form.getAttribute('action') || page.url();
      
      const newContext = await browser.newContext({
        origin: 'https://evil.com',
      });
      
      try {
        const response = await newContext.request.post(action, {
          form: { test: 'csrf-test' },
        });
        
        if (response.status() === 200 || response.status() === 302) {
          reporter.addFinding({
            severity: 'high',
            title: 'Potential CSRF Vulnerability',
            description: 'Cross-origin POST request was accepted',
            url: action,
            cwe: 'CWE-352',
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Verify CSRF token validation and implement origin checking',
          });
        }
      } catch (e) {
        // Request blocked - good
      } finally {
        await newContext.close();
      }
    }
  });
});
