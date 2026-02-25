import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Authentication & Authorization Tests', () => {
  test('Check for unauthenticated access to protected pages', async ({ page, context }) => {
    const protectedPaths = [
      '/admin',
      '/dashboard',
      '/profile',
      '/settings',
      '/account',
      '/api/users',
      '/api/admin',
      '/api/settings',
      '/user/profile',
      '/admin/settings',
    ];

    for (const path of protectedPaths) {
      try {
        const response = await page.goto(path, { waitUntil: 'domcontentloaded', timeout: 10000 });
        
        if (response && response.status() === 200) {
          const pageContent = await page.content();
          const hasLoginForm = pageContent.includes('type="password"') || 
                              pageContent.includes('login') ||
                              pageContent.includes('sign in');
          
          if (!hasLoginForm) {
            reporter.addFinding({
              severity: 'high',
              title: 'Potential Unauthenticated Access',
              description: `Path ${path} may be accessible without authentication`,
              url: path,
              cwe: 'CWE-284',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Ensure all sensitive endpoints require proper authentication',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for IDOR vulnerabilities', async ({ page }) => {
    const idorPatterns = [
      '/api/users/1',
      '/api/users/2',
      '/users/1',
      '/users/2',
      '/profile/1',
      '/profile/2',
      '/account/1',
      '/account/2',
      '/orders/1',
      '/orders/2',
      '/documents/1',
      '/documents/2',
    ];

    const responses: { [key: string]: { status: number; body: string } } = {};

    for (const path of idorPatterns) {
      try {
        const response = await page.goto(path, { waitUntil: 'domcontentloaded', timeout: 10000 });
        
        if (response) {
          const status = response.status();
          const body = await page.content();
          responses[path] = { status, body };
        }
      } catch (e) {
        // Continue
      }
    }

    const userPaths = Object.keys(responses).filter(p => p.includes('/users/') || p.includes('/profile/') || p.includes('/account/'));
    
    for (let i = 0; i < userPaths.length; i++) {
      for (let j = i + 1; j < userPaths.length; j++) {
        const path1 = userPaths[i];
        const path2 = userPaths[j];
        
        if (responses[path1].status === 200 && responses[path2].status === 200) {
          const similarity = calculateSimilarity(responses[path1].body, responses[path2].body);
          
          if (similarity > 0.9 && path1 !== path2) {
            reporter.addFinding({
              severity: 'high',
              title: 'Potential IDOR Vulnerability',
              description: `Similar responses for different user IDs suggest possible IDOR`,
              url: `${path1} vs ${path2}`,
              evidence: `Response similarity: ${(similarity * 100).toFixed(1)}%`,
              cwe: 'CWE-639',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Implement proper authorization checks for each resource access',
            });
          }
        }
      }
    }
  });

  test('Check for weak password policy', async ({ page }) => {
    const loginPath = '/login';
    
    try {
      await page.goto(loginPath, { waitUntil: 'domcontentloaded' });
      
      const passwordInput = page.locator('input[type="password"]').first();
      if (await passwordInput.count() > 0) {
        const minLength = await passwordInput.getAttribute('minlength');
        const pattern = await passwordInput.getAttribute('pattern');
        const maxLength = await passwordInput.getAttribute('maxlength');
        
        if (minLength && parseInt(minLength) < 8) {
          reporter.addFinding({
            severity: 'medium',
            title: 'Weak Password Policy',
            description: 'Password minimum length is less than 8 characters',
            url: loginPath,
            evidence: `minlength: ${minLength}`,
            cwe: 'CWE-521',
            owasp: 'A07:2021 - Identification and Authentication Failures',
            recommendation: 'Enforce minimum password length of at least 8 characters',
          });
        }

        if (maxLength && parseInt(maxLength) < 64) {
          reporter.addFinding({
            severity: 'low',
            title: 'Password Length Limitation',
            description: 'Password has a maximum length which may truncate strong passwords',
            url: loginPath,
            evidence: `maxlength: ${maxLength}`,
            cwe: 'CWE-521',
            owasp: 'A07:2021 - Identification and Authentication Failures',
            recommendation: 'Allow passwords up to at least 64 characters',
          });
        }
      }
    } catch (e) {
      // Continue
    }
  });

  test('Check for session fixation vulnerability', async ({ page, context }) => {
    try {
      await page.goto('/login');
      
      const cookiesBeforeLogin = await context.cookies();
      const sessionCookieBefore = cookiesBeforeLogin.find(c => 
        c.name.toLowerCase().includes('session') || 
        c.name.toLowerCase().includes('token') ||
        c.name.toLowerCase().includes('auth')
      );

      const passwordInput = page.locator('input[type="password"]').first();
      const usernameInput = page.locator('input[type="text"], input[type="email"]').first();
      
      if (await passwordInput.count() > 0 && await usernameInput.count() > 0) {
        await usernameInput.fill('test@example.com');
        await passwordInput.fill('testpassword123');
        
        const submitButton = page.locator('button[type="submit"], input[type="submit"]').first();
        if (await submitButton.count() > 0) {
          await submitButton.click();
          await page.waitForTimeout(2000);

          const cookiesAfterLogin = await context.cookies();
          const sessionCookieAfter = cookiesAfterLogin.find(c => 
            c.name.toLowerCase().includes('session') || 
            c.name.toLowerCase().includes('token') ||
            c.name.toLowerCase().includes('auth')
          );

          if (sessionCookieBefore && sessionCookieAfter && 
              sessionCookieBefore.value === sessionCookieAfter.value) {
            reporter.addFinding({
              severity: 'medium',
              title: 'Potential Session Fixation',
              description: 'Session cookie value did not change after login',
              url: '/login',
              evidence: `Cookie ${sessionCookieBefore.name} unchanged`,
              cwe: 'CWE-384',
              owasp: 'A07:2021 - Identification and Authentication Failures',
              recommendation: 'Regenerate session ID after successful authentication',
            });
          }
        }
      }
    } catch (e) {
      // Continue
    }
  });
});

function calculateSimilarity(str1: string, str2: string): number {
  const len1 = str1.length;
  const len2 = str2.length;
  
  if (len1 === 0 && len2 === 0) return 1;
  if (len1 === 0 || len2 === 0) return 0;

  const longer = len1 > len2 ? str1 : str2;
  const shorter = len1 > len2 ? str2 : str1;

  if (longer.includes(shorter)) {
    return shorter.length / longer.length;
  }

  let matches = 0;
  const minLen = Math.min(len1, len2);
  
  for (let i = 0; i < minLen; i++) {
    if (str1[i] === str2[i]) matches++;
  }

  return matches / Math.max(len1, len2);
}
