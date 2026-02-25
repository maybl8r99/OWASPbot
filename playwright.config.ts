import { defineConfig, devices } from '@playwright/test';

const targetEndpoint = process.env.TARGET_ENDPOINT || 'http://localhost:3000';
const headless = process.env.HEADLESS !== 'false';

export default defineConfig({
  testDir: './dast/tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [
    ['html', { outputFolder: 'reports/dast-report', open: 'never' }],
    ['json', { outputFile: 'reports/dast-results.json' }],
    ['list']
  ],
  use: {
    baseURL: targetEndpoint,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    actionTimeout: 10000,
    navigationTimeout: 30000,
  },
  projects: [
    {
      name: 'setup',
      testDir: './dast',
      testMatch: /auth\.setup\.ts/,
      use: { 
        headless: false,
      },
    },
    {
      name: 'dast',
      use: { 
        ...devices['Desktop Chrome'],
        headless,
        storageState: 'dast/.auth/user.json',
      },
      dependencies: ['setup'],
    },
  ],
  timeout: 60000,
  expect: {
    timeout: 10000,
  },
});
