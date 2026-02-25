import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Security Headers Tests', () => {
  test('Check for missing security headers', async ({ page, request }) => {
    const response = await request.get('/');
    const headers = response.headers();

    const securityHeaders = [
      { 
        name: 'x-frame-options', 
        severity: 'medium' as const, 
        cwe: 'CWE-1021',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
      },
      { 
        name: 'x-content-type-options', 
        severity: 'medium' as const, 
        cwe: 'CWE-116',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Add X-Content-Type-Options: nosniff to prevent MIME sniffing'
      },
      { 
        name: 'strict-transport-security', 
        severity: 'high' as const, 
        cwe: 'CWE-319',
        owasp: 'A02:2021 - Cryptographic Failures',
        recommendation: 'Add Strict-Transport-Security header (e.g., max-age=31536000; includeSubDomains)'
      },
      { 
        name: 'content-security-policy', 
        severity: 'high' as const, 
        cwe: 'CWE-1021',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Add Content-Security-Policy header with restrictive policies'
      },
      { 
        name: 'x-xss-protection', 
        severity: 'low' as const, 
        cwe: 'CWE-79',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Add X-XSS-Protection: 1; mode=block (deprecated but useful for older browsers)'
      },
      { 
        name: 'referrer-policy', 
        severity: 'low' as const, 
        cwe: 'CWE-200',
        owasp: 'A01:2021 - Broken Access Control',
        recommendation: 'Add Referrer-Policy header (e.g., strict-origin-when-cross-origin)'
      },
      { 
        name: 'permissions-policy', 
        severity: 'low' as const, 
        cwe: 'CWE-1021',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Add Permissions-Policy header to restrict browser features'
      },
      { 
        name: 'cross-origin-opener-policy', 
        severity: 'medium' as const, 
        cwe: 'CWE-1021',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Add Cross-Origin-Opener-Policy header (e.g., same-origin)'
      },
      { 
        name: 'cross-origin-resource-policy', 
        severity: 'medium' as const, 
        cwe: 'CWE-1021',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Add Cross-Origin-Resource-Policy header (e.g., same-origin)'
      },
    ];

    for (const header of securityHeaders) {
      if (!headers[header.name]) {
        reporter.addFinding({
          severity: header.severity,
          title: `Missing Security Header: ${header.name}`,
          description: `The ${header.name} header is not set on the response`,
          url: '/',
          cwe: header.cwe,
          owasp: header.owasp,
          recommendation: header.recommendation,
        });
      }
    }
  });

  test('Check for information disclosure headers', async ({ request }) => {
    const response = await request.get('/');
    const headers = response.headers();

    const infoHeaders = [
      { name: 'server', severity: 'low' as const },
      { name: 'x-powered-by', severity: 'low' as const },
      { name: 'x-aspnet-version', severity: 'low' as const },
      { name: 'x-aspnetmvc-version', severity: 'low' as const },
    ];

    for (const header of infoHeaders) {
      if (headers[header.name]) {
        reporter.addFinding({
          severity: header.severity,
          title: `Information Disclosure: ${header.name}`,
          description: `The ${header.name} header reveals technology information: ${headers[header.name]}`,
          url: '/',
          evidence: `${header.name}: ${headers[header.name]}`,
          cwe: 'CWE-200',
          owasp: 'A01:2021 - Broken Access Control',
          recommendation: `Remove or obfuscate the ${header.name} header to avoid revealing technology stack`,
        });
      }
    }
  });

  test('Check cookie security flags', async ({ page, context }) => {
    await page.goto('/');
    
    const cookies = await context.cookies();
    
    for (const cookie of cookies) {
      const issues: string[] = [];

      if (!cookie.secure && page.url().startsWith('https://')) {
        issues.push('Missing Secure flag');
      }
      
      if (!cookie.httpOnly && (cookie.name.toLowerCase().includes('session') || 
          cookie.name.toLowerCase().includes('token') ||
          cookie.name.toLowerCase().includes('auth'))) {
        issues.push('Missing HttpOnly flag on sensitive cookie');
      }
      
      if (!cookie.sameSite || cookie.sameSite === 'None') {
        issues.push('Missing or lax SameSite attribute');
      }

      if (issues.length > 0) {
        reporter.addFinding({
          severity: 'medium',
          title: `Insecure Cookie: ${cookie.name}`,
          description: `Cookie has security issues: ${issues.join(', ')}`,
          url: page.url(),
          evidence: issues.join('; '),
          cwe: 'CWE-614',
          owasp: 'A05:2021 - Security Misconfiguration',
          recommendation: 'Set Secure, HttpOnly, and SameSite=Strict/Lax flags on cookies',
        });
      }
    }
  });
});
