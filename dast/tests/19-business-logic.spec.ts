import { test, expect } from '@playwright/test';
import { DASTReporter } from '../utils/helpers';

const reporter = new DASTReporter();

test.describe('Business Logic Vulnerability Tests', () => {
  test('Check for price manipulation vulnerabilities', async ({ request }) => {
    const checkoutEndpoints = [
      '/api/checkout',
      '/api/order',
      '/api/cart/checkout',
      '/api/payment',
    ];
    
    const priceManipulationPayloads = [
      { items: [{ id: 1, price: 0, quantity: 1 }], total: 0 },
      { items: [{ id: 1, price: -100, quantity: 1 }], total: -100 },
      { items: [{ id: 1, price: 0.01, quantity: 1000 }], total: 0.01 },
      { items: [{ id: 1, price: 999, quantity: 1, discount: 999 }], total: 0 },
    ];
    
    for (const endpoint of checkoutEndpoints) {
      for (const payload of priceManipulationPayloads) {
        try {
          const response = await request.post(endpoint, {
            data: payload,
            headers: { 'Content-Type': 'application/json' },
            timeout: 10000,
          });
          
          if (response.status() === 200) {
            const body = await response.text().catch(() => '');
            
            const successIndicators = ['success', 'confirmed', 'order', 'processed', 'payment'];
            if (successIndicators.some(ind => body.toLowerCase().includes(ind))) {
              reporter.addFinding({
                severity: 'critical',
                title: 'Price Manipulation Vulnerability',
                description: `Checkout endpoint "${endpoint}" accepts client-side price values`,
                url: endpoint,
                payload: JSON.stringify(payload),
                cwe: 'CWE-641',
                owasp: 'A04:2021 - Insecure Design',
                recommendation: 'Calculate prices server-side based on item IDs, never trust client-provided prices',
              });
            }
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for quantity manipulation', async ({ request }) => {
    const cartEndpoints = ['/api/cart', '/api/cart/update', '/api/basket'];
    
    const quantityPayloads = [
      { itemId: 1, quantity: -1 },
      { itemId: 1, quantity: 0 },
      { itemId: 1, quantity: 999999 },
      { itemId: 1, quantity: 1.5 },
      { itemId: 1, quantity: 'unlimited' },
    ];
    
    for (const endpoint of cartEndpoints) {
      for (const payload of quantityPayloads) {
        try {
          const response = await request.post(endpoint, {
            data: payload,
            headers: { 'Content-Type': 'application/json' },
            timeout: 10000,
          });
          
          if (response.status() === 200) {
            reporter.addFinding({
              severity: 'high',
              title: 'Quantity Validation Bypass',
              description: `Cart endpoint accepts invalid quantity: ${JSON.stringify(payload.quantity)}`,
              url: endpoint,
              payload: JSON.stringify(payload),
              cwe: 'CWE-20',
              owasp: 'A04:2021 - Insecure Design',
              recommendation: 'Validate quantity ranges server-side (minimum 1, maximum reasonable limit)',
            });
          }
        } catch (e) {
          // Continue
        }
      }
    }
  });

  test('Check for workflow bypass', async ({ request }) => {
    // Test if steps in a multi-step process can be skipped
    const workflowSteps = [
      { step: '/api/checkout/payment', method: 'POST', data: { card: '4111111111111111' } },
      { step: '/api/checkout/confirm', method: 'POST', data: { confirm: true } },
      { step: '/api/checkout/complete', method: 'POST', data: { complete: true } },
    ];
    
    // Try to skip to the final step
    try {
      const response = await request.post('/api/checkout/complete', {
        data: { orderId: 'test123', complete: true },
        timeout: 10000,
      });
      
      if (response.status() === 200) {
        const body = await response.text();
        
        if (body.includes('success') || body.includes('complete') || body.includes('order')) {
          reporter.addFinding({
            severity: 'critical',
            title: 'Workflow Step Bypass',
            description: 'Order completion can be triggered without proper payment/validation steps',
            url: '/api/checkout/complete',
            cwe: 'CWE-840',
            owasp: 'A04:2021 - Insecure Design',
            recommendation: 'Enforce workflow state machine on server-side',
          });
        }
      }
    } catch (e) {
      // Continue
    }
  });

  test('Check for race conditions in coupon/promo codes', async ({ request }) => {
    const promoEndpoints = ['/api/apply-promo', '/api/coupon', '/api/discount'];
    
    // Try to apply the same promo code multiple times rapidly
    for (const endpoint of promoEndpoints) {
      try {
        // Fire multiple requests simultaneously
        const promises = Array(5).fill(null).map(() => 
          request.post(endpoint, {
            data: { code: 'PROMO20' },
            timeout: 5000,
          })
        );
        
        const responses = await Promise.all(promises);
        const successCount = responses.filter(r => r.status() === 200).length;
        
        if (successCount > 1) {
          reporter.addFinding({
            severity: 'medium',
            title: 'Potential Race Condition',
            description: `Promo code endpoint "${endpoint}" may have race condition vulnerability`,
            url: endpoint,
            evidence: `${successCount}/5 requests succeeded simultaneously`,
            cwe: 'CWE-362',
            owasp: 'A04:2021 - Insecure Design',
            recommendation: 'Implement proper locking mechanism for sensitive operations',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for time-of-check to time-of-use (TOCTOU)', async ({ request }) => {
    // This tests for race conditions in balance/credit checks
    const balanceEndpoints = ['/api/transfer', '/api/purchase', '/api/redeem'];
    
    for (const endpoint of balanceEndpoints) {
      try {
        // Fire multiple simultaneous requests that might exceed balance
        const promises = Array(3).fill(null).map(() =>
          request.post(endpoint, {
            data: { amount: 100, from: 'account1', to: 'account2' },
            timeout: 5000,
          })
        );
        
        const responses = await Promise.all(promises);
        const successCount = responses.filter(r => r.status() === 200).length;
        
        if (successCount > 1) {
          reporter.addFinding({
            severity: 'high',
            title: 'TOCTOU Race Condition',
            description: `Endpoint "${endpoint}" may allow duplicate operations via race condition`,
            url: endpoint,
            evidence: `${successCount}/3 concurrent requests succeeded`,
            cwe: 'CWE-362',
            owasp: 'A04:2021 - Insecure Design',
            recommendation: 'Use database transactions and proper locking',
          });
        }
      } catch (e) {
        // Continue
      }
    }
  });

  test('Check for mass assignment vulnerabilities', async ({ request }) => {
    const endpoints = ['/api/users', '/api/profile', '/api/register', '/api/update'];
    
    const massAssignmentPayloads = [
      { username: 'test', password: 'test123', isAdmin: true },
      { username: 'test', password: 'test123', role: 'admin' },
      { username: 'test', password: 'test123', privileges: ['admin', 'moderator'] },
      { username: 'test', password: 'test123', admin: true, moderator: true },
      { email: 'test@test.com', verified: true, emailVerified: true },
    ];
    
    for (const endpoint of endpoints) {
      for (const payload of massAssignmentPayloads) {
        try {
          const response = await request.post(endpoint, {
            data: payload,
            headers: { 'Content-Type': 'application/json' },
            timeout: 10000,
          });
          
          if (response.status() === 201 || response.status() === 200) {
            const body = await response.text();
            
            // Check if the protected fields were accepted
            const protectedFields = ['isAdmin', 'role', 'privileges', 'admin', 'verified'];
            for (const field of protectedFields) {
              if (payload.hasOwnProperty(field) && body.includes(field)) {
                reporter.addFinding({
                  severity: 'critical',
                  title: 'Mass Assignment Vulnerability',
                  description: `Endpoint "${endpoint}" accepts protected field "${field}"`,
                  url: endpoint,
                  payload: JSON.stringify(payload),
                  cwe: 'CWE-915',
                  owasp: 'A04:2021 - Insecure Design',
                  recommendation: 'Use allowlists for accepted fields, never bind user input directly to model attributes',
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

  test('Check for discount code enumeration', async ({ request }) => {
    const discountEndpoints = ['/api/validate-coupon', '/api/apply-discount', '/api/promo'];
    
    const testCodes = ['INVALID', 'TEST', 'PROMO', 'DISCOUNT', 'SAVE20', 'FREE'];
    
    for (const endpoint of discountEndpoints) {
      const responses: { code: string; status: number; body: string }[] = [];
      
      for (const code of testCodes) {
        try {
          const response = await request.post(endpoint, {
            data: { code },
            timeout: 5000,
          });
          
          const body = await response.text();
          responses.push({ code, status: response.status(), body });
        } catch (e) {
          // Continue
        }
      }
      
      // Check if different responses indicate valid vs invalid codes
      const uniqueResponses = [...new Set(responses.map(r => r.status))];
      if (uniqueResponses.length > 1) {
        reporter.addFinding({
          severity: 'low',
          title: 'Discount Code Enumeration Possible',
          description: `Endpoint "${endpoint}" responds differently to valid vs invalid codes`,
          url: endpoint,
          evidence: `Different status codes: ${uniqueResponses.join(', ')}`,
          cwe: 'CWE-204',
          owasp: 'A04:2021 - Insecure Design',
          recommendation: 'Return identical responses for valid and invalid codes',
        });
      }
    }
  });

  test('Check for negative balance/deposit', async ({ request }) => {
    const transactionEndpoints = ['/api/deposit', '/api/credit', '/api/add-funds'];
    
    for (const endpoint of transactionEndpoints) {
      try {
        const response = await request.post(endpoint, {
          data: { amount: -100 },
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000,
        });
        
        if (response.status() === 200) {
          const body = await response.text();
          
          if (body.includes('success') || body.includes('complete')) {
            reporter.addFinding({
              severity: 'critical',
              title: 'Negative Transaction Amount Accepted',
              description: `Endpoint "${endpoint}" accepts negative amounts`,
              url: endpoint,
              cwe: 'CWE-682',
              owasp: 'A04:2021 - Insecure Design',
              recommendation: 'Validate that transaction amounts are positive numbers',
            });
          }
        }
      } catch (e) {
        // Continue
      }
    }
  });
});
