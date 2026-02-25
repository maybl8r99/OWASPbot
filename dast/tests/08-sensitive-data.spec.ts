import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Sensitive Data Exposure Tests', () => {
  test('Check for sensitive data in page source', async ({ page }) => {
    await page.goto('/');
    
    const pageContent = await page.content();
    
    const sensitivePatterns = [
      { pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, name: 'Credit Card Number', severity: 'critical' as const },
      { pattern: /\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g, name: 'SSN', severity: 'critical' as const },
      { pattern: /password\s*[=:]\s*['"][^'"]+['"]/gi, name: 'Password in Code', severity: 'critical' as const },
      { pattern: /api[_-]?key\s*[=:]\s*['"][^'"]+['"]/gi, name: 'API Key', severity: 'high' as const },
      { pattern: /secret[_-]?key\s*[=:]\s*['"][^'"]+['"]/gi, name: 'Secret Key', severity: 'high' as const },
      { pattern: /private[_-]?key\s*[=:]\s*['"][^'"]+['"]/gi, name: 'Private Key', severity: 'critical' as const },
      { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g, name: 'PEM Private Key', severity: 'critical' as const },
      { pattern: /aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*['"][A-Z0-9]{20}['"]/gi, name: 'AWS Access Key', severity: 'critical' as const },
      { pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]/gi, name: 'AWS Secret Key', severity: 'critical' as const },
      { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, name: 'Email Address', severity: 'low' as const },
      { pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, name: 'Phone Number', severity: 'info' as const },
    ];

    for (const { pattern, name, severity } of sensitivePatterns) {
      const matches = pageContent.match(pattern);
      
      if (matches && matches.length > 0) {
        const uniqueMatches = [...new Set(matches)].slice(0, 3);
        
        reporter.addFinding({
          severity,
          title: `Sensitive Data Exposed: ${name}`,
          description: `${name} pattern found in page source`,
          url: page.url(),
          evidence: `Found ${matches.length} instance(s)`,
          cwe: 'CWE-200',
          owasp: 'A02:2021 - Cryptographic Failures',
          recommendation: 'Remove sensitive data from client-side code and implement proper data protection',
        });
      }
    }
  });

  test('Check for sensitive data in JavaScript files', async ({ page, request }) => {
    await page.goto('/');
    
    const scriptUrls = await page.$$eval('script[src]', scripts => 
      scripts.map(s => s.getAttribute('src')).filter(Boolean) as string[]
    );

    for (const scriptUrl of scriptUrls) {
      try {
        const response = await request.get(scriptUrl);
        const content = await response.text();
        
        const sensitivePatterns = [
          /password\s*[=:]\s*['"][^'"]+['"]/gi,
          /api[_-]?key\s*[=:]\s*['"][^'"]+['"]/gi,
          /secret\s*[=:]\s*['"][^'"]+['"]/gi,
          /token\s*[=:]\s*['"][^'"]+['"]/gi,
        ];

        for (const pattern of sensitivePatterns) {
          if (pattern.test(content)) {
            reporter.addFinding({
              severity: 'high',
              title: 'Sensitive Data in JavaScript',
              description: 'JavaScript file contains potentially sensitive data',
              url: scriptUrl,
              evidence: `Pattern found: ${pattern}`,
              cwe: 'CWE-200',
              owasp: 'A02:2021 - Cryptographic Failures',
              recommendation: 'Remove sensitive data from JavaScript files',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for exposed debug information', async ({ page }) => {
    await page.goto('/');
    
    const pageContent = await page.content();
    
    const debugPatterns = [
      { pattern: /stack\s*trace/i, name: 'Stack Trace' },
      { pattern: /debug\s*mode/i, name: 'Debug Mode' },
      { pattern: /exception\s*details/i, name: 'Exception Details' },
      { pattern: /error\s*report/i, name: 'Error Report' },
      { pattern: /sql\s*error/i, name: 'SQL Error' },
      { pattern: /server\s*error\s*in\s*['"]\/application['"]/i, name: 'Server Error' },
      { pattern: /warning:\s*\w+\(\)/i, name: 'PHP Warning' },
      { pattern: /notice:\s*undefined/i, name: 'PHP Notice' },
    ];

    for (const { pattern, name } of debugPatterns) {
      if (pattern.test(pageContent)) {
        reporter.addFinding({
          severity: 'medium',
          title: 'Debug Information Exposed',
          description: `${name} information found in page`,
          url: page.url(),
          evidence: `Pattern: ${name}`,
          cwe: 'CWE-200',
          owasp: 'A05:2021 - Security Misconfiguration',
          recommendation: 'Disable debug mode and error detail exposure in production',
        });
      }
    }
  });

  test('Check for exposed API endpoints', async ({ page }) => {
    await page.goto('/');
    
    const pageContent = await page.content();
    
    const apiPatterns = [
      /["']\/api\/v?\d*\/?\w+["']/g,
      /["']\/graphql["']/g,
      /["']\/rest\/\w+["']/g,
    ];

    for (const pattern of apiPatterns) {
      const matches = pageContent.match(pattern);
      
      if (matches) {
        const endpoints = [...new Set(matches)].slice(0, 5);
        
        if (endpoints.length > 0) {
          reporter.addFinding({
            severity: 'info',
            title: 'API Endpoints Discovered',
            description: 'Potential API endpoints found in page source',
            url: page.url(),
            evidence: endpoints.join(', '),
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Review exposed API endpoints for proper authentication and authorization',
          });
        }
      }
    }
  });
});
