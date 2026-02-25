import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

const noSqlPayloads = [
  '{ "$ne": null }',
  '{ "$gt": "" }',
  '{ "$exists": true }',
  '{ "$regex": ".*" }',
  '{ "$where": "this.password.length > 0" }',
  '{ "$or": [{}, { "password": { "$ne": "" } }] }',
  '{ "$and": [{}, { "password": { "$ne": "" } }] }',
  '{ "username": { "$ne": null }, "password": { "$ne": null } }',
  '{ "$gt": "" }',
  '[$ne]=1',
  '[$gt]=1',
  '[$exists]=true',
  '[$regex]=.*',
];

const noSqlErrorPatterns = [
  /MongoError/i,
  /MongoServerError/i,
  /mongod/i,
  /MongoDB/i,
  /CouchDB/i,
  /Cassandra/i,
  /DynamoDB/i,
  /Firebase/i,
];

test.describe('NoSQL Injection Tests', () => {
  test('Check for NoSQL injection in URL parameters', async ({ page, request }) => {
    const testParams = ['id', 'user', 'username', 'filter', 'query'];
    
    for (const param of testParams) {
      for (const payload of noSqlPayloads) {
        try {
          const url = `/?${param}=${encodeURIComponent(payload)}`;
          const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
          
          if (!response) continue;
          
          const pageContent = await page.content();
          const bodyText = await page.locator('body').innerText().catch(() => '');
          
          // Check for NoSQL error messages
          for (const pattern of noSqlErrorPatterns) {
            if (pattern.test(pageContent) || pattern.test(bodyText)) {
              reporter.addFinding({
                severity: 'high',
                title: 'NoSQL Injection Vulnerability',
                description: `NoSQL error returned for parameter "${param}"`,
                url: url,
                payload,
                evidence: `Error pattern matched: ${pattern}`,
                cwe: 'CWE-943',
                owasp: 'A03:2021 - Injection',
                recommendation: 'Use parameterized queries and validate all input',
              });
              break;
            }
          }
          
          // Check for unusual behavior that might indicate injection
          if (response.status() === 200 && (pageContent.includes('admin') || pageContent.includes('password'))) {
            reporter.addFinding({
              severity: 'medium',
              title: 'Potential NoSQL Injection',
              description: `Unexpected data returned for NoSQL payload in "${param}"`,
              url: url,
              payload,
              cwe: 'CWE-943',
              owasp: 'A03:2021 - Injection',
              recommendation: 'Validate and sanitize all user input',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for NoSQL injection in JSON endpoints', async ({ request }) => {
    const jsonPayloads = [
      { username: { $ne: null }, password: { $ne: null } },
      { username: { $gt: '' }, password: { $gt: '' } },
      { id: { $exists: true } },
      { query: { $regex: '.*' } },
    ];
    
    const endpoints = ['/api/login', '/api/auth', '/api/users', '/api/data'];
    
    for (const endpoint of endpoints) {
      for (const payload of jsonPayloads) {
        try {
          const response = await request.post(endpoint, {
            data: payload,
            headers: { 'Content-Type': 'application/json' },
            timeout: 10000,
          });
          
          const body = await response.text();
          
          // Check for successful authentication bypass indicators
          if (response.status() === 200) {
            const successIndicators = ['token', 'auth', 'success', 'session', 'user', 'id'];
            const hasSuccess = successIndicators.some(indicator => 
              body.toLowerCase().includes(indicator)
            );
            
            if (hasSuccess) {
              reporter.addFinding({
                severity: 'critical',
                title: 'NoSQL Injection Authentication Bypass',
                description: `JSON endpoint "${endpoint}" may be vulnerable to NoSQL injection`,
                url: endpoint,
                payload: JSON.stringify(payload),
                evidence: 'Successful response with auth indicators',
                cwe: 'CWE-943',
                owasp: 'A03:2021 - Injection',
                recommendation: 'Use parameterized queries and implement strict input validation',
              });
            }
          }
          
          // Check for NoSQL errors
          for (const pattern of noSqlErrorPatterns) {
            if (pattern.test(body)) {
              reporter.addFinding({
                severity: 'high',
                title: 'NoSQL Injection Vulnerability',
                description: `JSON endpoint "${endpoint}" returned NoSQL error`,
                url: endpoint,
                payload: JSON.stringify(payload),
                evidence: `Error: ${body.substring(0, 200)}`,
                cwe: 'CWE-943',
                owasp: 'A03:2021 - Injection',
                recommendation: 'Use parameterized queries and validate all input',
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
});
