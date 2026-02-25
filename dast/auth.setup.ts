import { test as setup } from '@playwright/test';
import { existsSync, statSync } from 'fs';

const authFile = 'dast/.auth/user.json';
const authExpiryMs = 60 * 60 * 1000;

setup('Verify authentication state', async () => {
  if (!existsSync(authFile)) {
    throw new Error('\n\nNo authentication found. Run: ./scripts/run-dast.sh auth\n');
  }
  
  const stats = statSync(authFile);
  const fileAge = Date.now() - stats.mtimeMs;
  
  if (fileAge >= authExpiryMs) {
    throw new Error('\n\nAuthentication expired. Run: ./scripts/run-dast.sh auth\n');
  }
  
  console.log(`\n✓ Using stored authentication (age: ${Math.round(fileAge / 60000)} minutes)`);
});
