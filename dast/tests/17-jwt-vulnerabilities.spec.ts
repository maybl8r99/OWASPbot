import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('JWT Security Tests', () => {
  test('Check for weak JWT signature (none algorithm)', async ({ page, request }) => {
    // Common JWT patterns in localStorage/sessionStorage/cookies
    const jwtPattern = /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/;
    
    await page.goto('/');
    
    // Get JWT from localStorage
    const localStorage = await page.evaluate(() => {
      const items: Record<string, string> = {};
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (key) {
          items[key] = window.localStorage.getItem(key) || '';
        }
      }
      return items;
    });
    
    // Get JWT from cookies
    const cookies = await page.context().cookies();
    
    const potentialJwts: { source: string; value: string }[] = [];
    
    // Check localStorage
    for (const [key, value] of Object.entries(localStorage)) {
      if (jwtPattern.test(value)) {
        potentialJwts.push({ source: `localStorage.${key}`, value });
      }
    }
    
    // Check cookies
    for (const cookie of cookies) {
      if (jwtPattern.test(cookie.value)) {
        potentialJwts.push({ source: `cookie.${cookie.name}`, value: cookie.value });
      }
    }
    
    for (const { source, value } of potentialJwts) {
      try {
        // Parse the JWT header
        const parts = value.split('.');
        if (parts.length === 3) {
          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
          
          // Check for 'none' algorithm
          if (header.alg === 'none') {
            reporter.addFinding({
              severity: 'critical',
              title: 'JWT None Algorithm Vulnerability',
              description: `JWT from ${source} uses "none" algorithm which allows signature bypass`,
              url: page.url(),
              evidence: `Header: ${JSON.stringify(header)}`,
              cwe: 'CWE-327',
              owasp: 'A02:2021 - Cryptographic Failures',
              recommendation: 'Reject JWTs with "none" algorithm',
            });
          }
          
          // Check for weak algorithms
          if (header.alg === 'HS256' || header.alg === 'HS384' || header.alg === 'HS512') {
            // HMAC algorithms - try to test for weak secrets (we can't really brute force here)
            reporter.addFinding({
              severity: 'info',
              title: 'JWT Uses HMAC Algorithm',
              description: `JWT from ${source} uses HMAC. Ensure strong secret is used.`,
              url: page.url(),
              evidence: `Algorithm: ${header.alg}`,
              recommendation: 'Use strong secrets (256+ bits) for JWT HMAC signing',
            });
          }
          
          // Check for algorithm confusion (RS256/ES256 but might accept HS256)
          if (header.alg && (header.alg.startsWith('RS') || header.alg.startsWith('ES') || header.alg.startsWith('PS'))) {
            reporter.addFinding({
              severity: 'low',
              title: 'JWT Asymmetric Algorithm',
              description: `JWT uses ${header.alg}. Ensure algorithm confusion attacks are prevented.`,
              url: page.url(),
              evidence: `Algorithm: ${header.alg}`,
              recommendation: 'Explicitly specify allowed algorithms and reject unexpected ones',
            });
          }
        }
      } catch (e) {
        // Not a valid JWT or parsing error
      }
    }
  });

  test('Check for JWT in insecure storage', async ({ page }) => {
    await page.goto('/');
    
    // Check if JWT is stored without Secure/HttpOnly flags
    const cookies = await page.context().cookies();
    
    for (const cookie of cookies) {
      if (cookie.value.match(/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/)) {
        const issues: string[] = [];
        
        if (!cookie.httpOnly) {
          issues.push('missing HttpOnly flag');
        }
        if (!cookie.secure) {
          issues.push('missing Secure flag');
        }
        if (!cookie.sameSite || cookie.sameSite === 'None') {
          issues.push('missing/inadequate SameSite');
        }
        
        if (issues.length > 0) {
          reporter.addFinding({
            severity: 'medium',
            title: 'JWT Stored in Insecure Cookie',
            description: `JWT cookie "${cookie.name}" has security issues`,
            url: page.url(),
            evidence: issues.join(', '),
            cwe: 'CWE-522',
            owasp: 'A07:2021 - Identification and Authentication Failures',
            recommendation: 'Set HttpOnly, Secure, and SameSite=Strict flags on JWT cookies',
          });
        }
      }
    }
    
    // Check for JWT in localStorage (generally not recommended)
    const localStorage = await page.evaluate(() => {
      const items: Record<string, string> = {};
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        if (key) {
          items[key] = window.localStorage.getItem(key) || '';
        }
      }
      return items;
    });
    
    for (const [key, value] of Object.entries(localStorage)) {
      if (value.match(/eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/)) {
        reporter.addFinding({
          severity: 'low',
          title: 'JWT Stored in localStorage',
          description: `JWT found in localStorage key "${key}"`,
          url: page.url(),
          evidence: `Key: ${key}`,
          cwe: 'CWE-522',
          owasp: 'A07:2021 - Identification and Authentication Failures',
          recommendation: 'Consider using httpOnly cookies instead of localStorage for JWTs',
        });
      }
    }
  });

  test('Check for expired JWT acceptance', async ({ page, request }) => {
    // This test checks if the server properly validates JWT expiration
    // We'll try to detect by looking at the JWT payload
    
    await page.goto('/');
    
    const cookies = await page.context().cookies();
    
    for (const cookie of cookies) {
      const jwtMatch = cookie.value.match(/(eyJ[a-zA-Z0-9_-]*)\.(eyJ[a-zA-Z0-9_-]*)\.([a-zA-Z0-9_-]*)/);
      if (jwtMatch) {
        try {
          const payload = JSON.parse(Buffer.from(jwtMatch[2], 'base64url').toString());
          
          if (payload.exp) {
            const expDate = new Date(payload.exp * 1000);
            const now = new Date();
            
            if (expDate < now) {
              reporter.addFinding({
                severity: 'medium',
                title: 'Expired JWT Present',
                description: `JWT cookie "${cookie.name}" has expired but is still stored`,
                url: page.url(),
                evidence: `Expired: ${expDate.toISOString()}`,
                cwe: 'CWE-613',
                owasp: 'A07:2021 - Identification and Authentication Failures',
                recommendation: 'Remove expired tokens from storage',
              });
            }
          }
          
          if (!payload.exp && !payload.nbf) {
            reporter.addFinding({
              severity: 'low',
              title: 'JWT Missing Expiration',
              description: `JWT cookie "${cookie.name}" has no expiration claim`,
              url: page.url(),
              cwe: 'CWE-613',
              owasp: 'A07:2021 - Identification and Authentication Failures',
              recommendation: 'Always include exp claim in JWTs',
            });
          }
        } catch (e) {
          // Parsing error
        }
      }
    }
  });

  test('Check for JWT in URL parameters', async ({ page }) => {
    // Check common URLs that might have JWT in query params
    const urlsToCheck = [
      '/callback?token=',
      '/auth?jwt=',
      '/login?token=',
    ];
    
    for (const baseUrl of urlsToCheck) {
      try {
        const testJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCJ9.test';
        const response = await page.goto(`${baseUrl}${testJwt}`, { waitUntil: 'domcontentloaded' });
        
        // Check if the JWT appears in the page (leaked via referrer or logs)
        const pageContent = await page.content();
        const url = page.url();
        
        if (url.includes(testJwt)) {
          reporter.addFinding({
            severity: 'medium',
            title: 'JWT in URL Parameter',
            description: 'JWT token is being passed in URL query parameter',
            url: url,
            evidence: 'Token visible in URL',
            cwe: 'CWE-598',
            owasp: 'A07:2021 - Identification and Authentication Failures',
            recommendation: 'Pass JWTs in headers or cookies, not URL parameters',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
