import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Cache Vulnerability Tests', () => {
  test('Check for cache poisoning via Host header', async ({ request }) => {
    const maliciousHosts = [
      'evil.com',
      'attacker.com',
      'localhost:1337',
    ];
    
    for (const host of maliciousHosts) {
      try {
        const response = await request.get('/', {
          headers: {
            'Host': host,
            'X-Forwarded-Host': host,
          },
          timeout: 10000,
        });
        
        const body = await response.text();
        
        // Check if the malicious host appears in the response
        if (body.includes(host) || body.includes(`//${host}`)) {
          const cacheHeaders = [
            response.headers()['cache-control'],
            response.headers()['x-cache'],
            response.headers()['cf-cache-status'],
            response.headers()['x-cache-status'],
          ];
          
          const isCached = cacheHeaders.some(h => 
            h && (h.includes('hit') || h.includes('HIT') || h.includes('public') || h.includes('max-age'))
          );
          
          if (isCached) {
            reporter.addFinding({
              severity: 'high',
              title: 'Web Cache Poisoning via Host Header',
              description: 'Host header value is reflected in cached response',
              url: '/',
              evidence: `Host: ${host} reflected in response`,
              cwe: 'CWE-444',
              owasp: 'A05:2021 - Security Misconfiguration',
              recommendation: 'Normalize Host header and exclude it from cache key if not needed',
            });
          } else {
            reporter.addFinding({
              severity: 'medium',
              title: 'Host Header Injection',
              description: 'Host header value is reflected in response',
              url: '/',
              evidence: `Host: ${host} reflected in response`,
              cwe: 'CWE-644',
              owasp: 'A05:2021 - Security Misconfiguration',
              recommendation: 'Validate Host header against allowlist',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for cache poisoning via X-Forwarded headers', async ({ request }) => {
    const poisoningHeaders = [
      { 'X-Forwarded-Proto': 'https' },
      { 'X-Forwarded-Port': '443' },
      { 'X-Forwarded-Host': 'evil.com' },
      { 'X-Original-URL': '/admin' },
      { 'X-Rewrite-URL': '/admin' },
    ];
    
    for (const headers of poisoningHeaders) {
      try {
        const response = await request.get('/', {
          headers,
          timeout: 10000,
        });
        
        const body = await response.text();
        const headerName = Object.keys(headers)[0];
        const headerValue = Object.values(headers)[0];
        
        // Check for cache headers
        const cacheControl = response.headers()['cache-control'];
        const xCache = response.headers()['x-cache'];
        
        const isCacheable = cacheControl?.includes('public') || 
                           cacheControl?.includes('max-age') ||
                           xCache?.includes('HIT') ||
                           xCache?.includes('hit');
        
        // Check if header affected the response
        if (isCacheable && (body.includes(headerValue) || body.includes(headerName))) {
          reporter.addFinding({
            severity: 'high',
            title: 'Web Cache Poisoning Risk',
            description: `Header "${headerName}" affects cached response`,
            url: '/',
            evidence: `${headerName}: ${headerValue}`,
            cwe: 'CWE-444',
            owasp: 'A05:2021 - Security Misconfiguration',
            recommendation: 'Configure cache to ignore unkeyed headers or normalize them',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for sensitive information caching', async ({ request }) => {
    const sensitivePaths = [
      '/api/users',
      '/api/user/profile',
      '/account',
      '/dashboard',
      '/admin',
    ];
    
    for (const path of sensitivePaths) {
      try {
        const response = await request.get(path, { timeout: 10000 });
        
        const cacheControl = response.headers()['cache-control'] || '';
        const pragma = response.headers()['pragma'] || '';
        const expires = response.headers()['expires'];
        const xCache = response.headers()['x-cache'];
        
        // Check if sensitive data might be cached
        const isCacheable = 
          cacheControl.includes('public') ||
          cacheControl.includes('max-age') && !cacheControl.includes('no-store') && !cacheControl.includes('private') ||
          xCache?.includes('HIT') ||
          xCache?.includes('hit');
        
        const missingProtection = 
          !cacheControl.includes('no-store') &&
          !cacheControl.includes('private') &&
          !cacheControl.includes('no-cache');
        
        if (isCacheable || missingProtection) {
          // Check if response contains sensitive data
          const body = await response.text();
          const sensitiveIndicators = [
            'password',
            'token',
            'email',
            'credit_card',
            'ssn',
            'phone',
            'address',
          ];
          
          const hasSensitiveData = sensitiveIndicators.some(indicator => 
            body.toLowerCase().includes(indicator)
          );
          
          if (hasSensitiveData && response.status() === 200) {
            reporter.addFinding({
              severity: 'high',
              title: 'Sensitive Data May Be Cached',
              description: `Path "${path}" returns sensitive data without proper cache control`,
              url: path,
              evidence: `Cache-Control: ${cacheControl}`,
              cwe: 'CWE-523',
              owasp: 'A05:2021 - Security Misconfiguration',
              recommendation: 'Add Cache-Control: no-store, no-cache, must-revalidate, private to sensitive responses',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for cache deception vulnerability', async ({ request }) => {
    // Cache deception: /profile.php/nonexistent.js might cache the profile page
    const deceptionPaths = [
      '/api/users/fake.js',
      '/api/users/fake.css',
      '/profile/test.jpg',
      '/settings/script.js',
    ];
    
    for (const path of deceptionPaths) {
      try {
        const response = await request.get(path, { timeout: 10000 });
        
        if (response.status() === 200) {
          const contentType = response.headers()['content-type'] || '';
          const cacheControl = response.headers()['cache-control'] || '';
          
          // If API returns HTML for a .js request, it might be cacheable as JS
          if (contentType.includes('text/html') && path.endsWith('.js')) {
            const isCacheable = 
              cacheControl.includes('public') ||
              cacheControl.includes('max-age');
            
            if (isCacheable) {
              reporter.addFinding({
                severity: 'medium',
                title: 'Potential Web Cache Deception',
                description: `Path "${path}" returns HTML but may be cached as static resource`,
                url: path,
                evidence: `Content-Type: ${contentType}, Cache-Control: ${cacheControl}`,
                cwe: 'CWE-444',
                owasp: 'A05:2021 - Security Misconfiguration',
                recommendation: 'Ensure dynamic content is not cached and path extensions match content type',
              });
            }
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for cache key normalization issues', async ({ request }) => {
    // Test if different representations of same path are treated differently
    const pathVariants = [
      '/api/users',
      '/api/users/',
      '/api/users?',
      '/api/users?utm_source=test',
      '/API/users',
    ];
    
    const responses: { path: string; status: number; cacheStatus: string | undefined }[] = [];
    
    for (const path of pathVariants) {
      try {
        const response = await request.get(path, { timeout: 10000 });
        
        responses.push({
          path,
          status: response.status(),
          cacheStatus: response.headers()['x-cache'] || response.headers()['cf-cache-status'],
        });
      } catch (e) {
        // Continue
      }
    }
    
    // If some variants are cached and others aren't, there might be normalization issues
    const cachedVariants = responses.filter(r => r.cacheStatus?.includes('HIT'));
    const uncachedVariants = responses.filter(r => !r.cacheStatus?.includes('HIT'));
    
    if (cachedVariants.length > 0 && uncachedVariants.length > 0) {
      reporter.addFinding({
        severity: 'low',
        title: 'Cache Key Normalization Inconsistency',
        description: 'Different path representations have different cache behavior',
        url: '/api/users',
        evidence: `Cached: ${cachedVariants.map(r => r.path).join(', ')}; Uncached: ${uncachedVariants.map(r => r.path).join(', ')}`,
        cwe: 'CWE-444',
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: 'Normalize URLs before cache lookup',
      });
    }
  });
});
