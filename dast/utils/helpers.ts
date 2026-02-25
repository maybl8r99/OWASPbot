import { Page, APIRequestContext } from '@playwright/test';

export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  url: string;
  payload?: string;
  evidence?: string;
  cwe?: string;
  owasp?: string;
  recommendation: string;
}

export class DASTReporter {
  private findings: Finding[] = [];

  addFinding(finding: Finding) {
    this.findings.push(finding);
  }

  getFindings(): Finding[] {
    return this.findings;
  }

  getFindingsBySeverity(severity: Finding['severity']): Finding[] {
    return this.findings.filter(f => f.severity === severity);
  }

  hasFindings(): boolean {
    return this.findings.length > 0;
  }

  generateSummary(): string {
    const critical = this.getFindingsBySeverity('critical').length;
    const high = this.getFindingsBySeverity('high').length;
    const medium = this.getFindingsBySeverity('medium').length;
    const low = this.getFindingsBySeverity('low').length;
    const info = this.getFindingsBySeverity('info').length;

    return `
DAST Scan Summary
=================
Critical: ${critical}
High:     ${high}
Medium:   ${medium}
Low:      ${low}
Info:     ${info}
Total:    ${this.findings.length}
    `.trim();
  }
}

export async function checkSecurityHeaders(response: Response): Promise<Finding[]> {
  const findings: Finding[] = [];
  const headers = response.headers;

  const securityHeaders = {
    'x-frame-options': {
      severity: 'medium' as const,
      recommendation: 'Add X-Frame-Options header to prevent clickjacking attacks',
      cwe: 'CWE-1021',
    },
    'x-content-type-options': {
      severity: 'medium' as const,
      recommendation: 'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing',
      cwe: 'CWE-116',
    },
    'strict-transport-security': {
      severity: 'medium' as const,
      recommendation: 'Add HSTS header to enforce HTTPS connections',
      cwe: 'CWE-319',
    },
    'content-security-policy': {
      severity: 'high' as const,
      recommendation: 'Add Content-Security-Policy header to prevent XSS attacks',
      cwe: 'CWE-1021',
    },
    'x-xss-protection': {
      severity: 'low' as const,
      recommendation: 'Consider adding X-XSS-Protection header (deprecated but still useful)',
      cwe: 'CWE-79',
    },
    'referrer-policy': {
      severity: 'low' as const,
      recommendation: 'Add Referrer-Policy header to control referrer information',
      cwe: 'CWE-200',
    },
    'permissions-policy': {
      severity: 'low' as const,
      recommendation: 'Add Permissions-Policy header to restrict browser features',
      cwe: 'CWE-1021',
    },
  };

  for (const [header, config] of Object.entries(securityHeaders)) {
    if (!headers[header]) {
      findings.push({
        severity: config.severity,
        title: `Missing Security Header: ${header}`,
        description: `The ${header} header is not set`,
        url: response.url,
        cwe: config.cwe,
        owasp: 'A05:2021 - Security Misconfiguration',
        recommendation: config.recommendation,
      });
    }
  }

  return findings;
}

export async function findForms(page: Page): Promise<{ action: string; method: string; inputs: string[] }[]> {
  const forms = await page.$$('form');
  const formData: { action: string; method: string; inputs: string[] }[] = [];

  for (const form of forms) {
    const action = await form.getAttribute('action') || '';
    const method = (await form.getAttribute('method') || 'get').toLowerCase();
    const inputs = await form.$$('input, textarea, select');
    const inputNames: string[] = [];

    for (const input of inputs) {
      const name = await input.getAttribute('name');
      if (name) inputNames.push(name);
    }

    formData.push({ action, method, inputs: inputNames });
  }

  return formData;
}

export async function findLinks(page: Page): Promise<string[]> {
  const links = await page.$$('a[href]');
  const hrefs: string[] = [];

  for (const link of links) {
    const href = await link.getAttribute('href');
    if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
      hrefs.push(href);
    }
  }

  return [...new Set(hrefs)];
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
