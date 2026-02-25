import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

const httpMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];

const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT'];

test.describe('HTTP Method Security Tests', () => {
  test('Check for dangerous HTTP methods enabled', async ({ request }) => {
    const testPaths = ['/', '/api', '/api/users', '/admin'];
    
    for (const path of testPaths) {
      for (const method of dangerousMethods) {
        try {
          let response;
          switch (method) {
            case 'PUT':
              response = await request.put(path, { data: { test: 'data' }, timeout: 10000 });
              break;
            case 'DELETE':
              response = await request.delete(path, { timeout: 10000 });
              break;
            case 'TRACE':
              // TRACE is usually handled differently
              response = await request.fetch(path, {
                method: 'TRACE',
                timeout: 10000,
              });
              break;
            case 'CONNECT':
              response = await request.fetch(path, {
                method: 'CONNECT',
                timeout: 10000,
              });
              break;
          }
          
          if (response && (response.status() === 200 || response.status() === 204)) {
            reporter.addFinding({
              severity: 'high',
              title: 'Dangerous HTTP Method Enabled',
              description: `HTTP ${method} method is enabled and may allow unauthorized actions`,
              url: path,
              evidence: `Method ${method} returned status ${response.status()}`,
              cwe: 'CWE-650',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Disable unnecessary HTTP methods in server configuration',
            });
          }
        } catch (e) {
          // Continue - method likely not supported or blocked
        }
      }
    }
  });

  test('Check for TRACE method (XST)', async ({ request }) => {
    try {
      const response = await request.fetch('/', {
        method: 'TRACE',
        headers: {
          'X-Custom-Header': 'test-value',
          'Cookie': 'test=cookie',
        },
        timeout: 10000,
      });
      
      if (response.status() === 200) {
        const body = await response.text();
        
        // Check if TRACE echoes back headers (indicates it's working)
        if (body.includes('TRACE') || body.includes('X-Custom-Header') || body.includes('test-value')) {
          reporter.addFinding({
            severity: 'medium',
            title: 'HTTP TRACE Method Enabled (XST)',
            description: 'TRACE method is enabled which can be used for Cross-Site Tracing attacks',
            url: '/',
            evidence: 'TRACE request was echoed back by server',
            cwe: 'CWE-693',
            owasp: 'A05:2021 - Security Misconfiguration',
            recommendation: 'Disable TRACE method in web server configuration',
          });
        }
      }
    } catch (e) {
      // TRACE likely not supported
    }
  });

  test('Check for method override vulnerabilities', async ({ request }) => {
    const overrideHeaders = [
      'X-HTTP-Method-Override',
      'X-HTTP-Method',
      'X-Method-Override',
      '_method',
    ];
    
    for (const header of overrideHeaders) {
      try {
        const response = await request.get('/api/users', {
          headers: {
            [header]: 'DELETE',
          },
          timeout: 10000,
        });
        
        if (response.status() === 200 || response.status() === 204) {
          const body = await response.text();
          
          // Check if the override was processed
          if (body.includes('deleted') || body.includes('removed') || response.status() === 204) {
            reporter.addFinding({
              severity: 'critical',
              title: 'HTTP Method Override Vulnerability',
              description: `Header "${header}" can override HTTP methods and bypass security controls`,
              url: '/api/users',
              evidence: `GET request with ${header}: DELETE was processed`,
              cwe: 'CWE-650',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Disable method override headers or validate against allowlist',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for PUT file upload vulnerability', async ({ request }) => {
    const putPayloads = [
      { path: '/test.txt', content: 'TEST FILE UPLOAD' },
      { path: '/shell.jsp', content: '<% out.println("VULNERABLE"); %>' },
      { path: '/test.php', content: '<?php echo "VULNERABLE"; ?>' },
    ];
    
    for (const payload of putPayloads) {
      try {
        const response = await request.put(payload.path, {
          data: payload.content,
          headers: {
            'Content-Type': 'text/plain',
          },
          timeout: 10000,
        });
        
        // If PUT succeeded, try to GET the file
        if (response.status() === 201 || response.status() === 200 || response.status() === 204) {
          const getResponse = await request.get(payload.path, { timeout: 10000 });
          
          if (getResponse.status() === 200) {
            const content = await getResponse.text();
            
            if (content.includes(payload.content.substring(0, 20))) {
              reporter.addFinding({
                severity: 'critical',
                title: 'PUT File Upload Vulnerability',
                description: `HTTP PUT method allows arbitrary file upload to "${payload.path}"`,
                url: payload.path,
                evidence: `File created and accessible via GET`,
                cwe: 'CWE-434',
                owasp: 'A01:2021 - Broken Access Control',
                recommendation: 'Disable PUT method or restrict to authenticated/authorized users only',
              });
            }
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for CORS preflight misconfiguration', async ({ request }) => {
    try {
      const response = await request.options('/', {
        headers: {
          'Origin': 'https://evil.com',
          'Access-Control-Request-Method': 'DELETE',
          'Access-Control-Request-Headers': 'X-Custom-Header',
        },
        timeout: 10000,
      });
      
      const acAllowOrigin = response.headers()['access-control-allow-origin'];
      const acAllowMethods = response.headers()['access-control-allow-methods'];
      const acAllowHeaders = response.headers()['access-control-allow-headers'];
      
      if (acAllowOrigin === '*' || acAllowOrigin === 'https://evil.com') {
        if (acAllowMethods?.includes('DELETE') || acAllowMethods?.includes('PUT')) {
          reporter.addFinding({
            severity: 'high',
            title: 'Dangerous CORS Preflight Configuration',
            description: 'CORS preflight allows dangerous methods from any origin',
            url: '/',
            evidence: `Allow-Origin: ${acAllowOrigin}, Allow-Methods: ${acAllowMethods}`,
            cwe: 'CWE-942',
            owasp: 'A05:2021 - Security Misconfiguration',
            recommendation: 'Restrict CORS to specific origins and limit allowed methods',
          });
        }
      }
    } catch (e) {
      // Continue
    }
  });

  test('Check for inconsistent method handling', async ({ request }) => {
    // Test if POST/GET to the same endpoint have different security postures
    const endpoints = ['/api/users', '/api/data', '/login', '/admin'];
    
    for (const endpoint of endpoints) {
      try {
        const getResponse = await request.get(endpoint, { timeout: 10000 });
        const postResponse = await request.post(endpoint, { 
          data: { test: 'data' },
          timeout: 10000 
        });
        
        // If POST succeeds but GET is blocked (or vice versa), note it
        if ((getResponse.status() === 200 && postResponse.status() === 405) ||
            (getResponse.status() === 405 && postResponse.status() === 200)) {
          reporter.addFinding({
            severity: 'info',
            title: 'HTTP Method Restriction Present',
            description: `Endpoint "${endpoint}" has method-specific restrictions`,
            url: endpoint,
            evidence: `GET: ${getResponse.status()}, POST: ${postResponse.status()}`,
            owasp: 'A01:2021 - Broken Access Control',
            recommendation: 'Ensure method restrictions are consistent with security policy',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
