import { chromium } from 'playwright';
import { existsSync, statSync, mkdirSync } from 'fs';
import * as readline from 'readline';

const authFile = 'dast/.auth/user.json';
const authExpiryMs = 60 * 60 * 1000;

if (existsSync(authFile)) {
  const stats = statSync(authFile);
  const fileAge = Date.now() - stats.mtimeMs;
  
  if (fileAge < authExpiryMs) {
    console.log(`\n✓ Using stored authentication (age: ${Math.round(fileAge / 60000)} minutes)`);
    console.log('  To force re-authentication, delete: dast/.auth/user.json\n');
    process.exit(0);
  }
}

const targetEndpoint = process.env.TARGET_ENDPOINT || 'http://localhost:3000';

console.log('\n========================================');
console.log('MANUAL AUTHENTICATION REQUIRED');
console.log('========================================');
console.log(`Target: ${targetEndpoint}`);
console.log('\n1. Log in to the application in the browser window');
console.log('2. Complete any MFA/2FA if required');
console.log('3. Once authenticated, come back here and press Enter');
console.log('========================================\n');

const browser = await chromium.launch({ headless: false });
const context = await browser.newContext();
const page = await context.newPage();

await page.goto(targetEndpoint);

await new Promise((resolve) => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  rl.question('\nPress Enter after you have logged in...', () => {
    rl.close();
    resolve();
  });
});

await page.waitForTimeout(2000);

const cookies = await context.cookies();
console.log('\n✓ Authentication captured');
console.log(`  Cookies found: ${cookies.length}`);

const cookieNames = cookies.map(c => c.name);
if (cookieNames.length > 0) {
  console.log(`  Cookie names: ${cookieNames.join(', ')}`);
}

const jwtCookies = cookies.filter(c => 
  c.name.toLowerCase().includes('jwt') ||
  c.name.toLowerCase().includes('token') ||
  c.name.toLowerCase().includes('auth') ||
  c.name.toLowerCase().includes('session')
);

if (jwtCookies.length > 0) {
  console.log(`  Auth cookies: ${jwtCookies.map(c => c.name).join(', ')}`);
}

const localStorage = await page.evaluate(() => {
  const items = {};
  for (let i = 0; i < window.localStorage.length; i++) {
    const key = window.localStorage.key(i);
    if (key) {
      items[key] = window.localStorage.getItem(key) || '';
    }
  }
  return items;
});

const tokenKeys = Object.keys(localStorage).filter(k => 
  k.toLowerCase().includes('token') ||
  k.toLowerCase().includes('jwt') ||
  k.toLowerCase().includes('auth')
);

if (tokenKeys.length > 0) {
  console.log(`  localStorage tokens: ${tokenKeys.join(', ')}`);
}

mkdirSync('dast/.auth', { recursive: true });
await context.storageState({ path: authFile });

console.log(`\n✓ Authentication saved to: ${authFile}`);
console.log('  This will be reused for subsequent scans.\n');

await browser.close();
