import { defineConfig, devices } from "@playwright/test";

// Testes de ponta a ponta contra o build de produção e um PostgreSQL real.
// Requer DATABASE_URL apontando para um banco vazio e `npm run build` antes.
// O scanner fica desligado: nenhum teste faz requisição a alvos externos.
const PORT = Number(process.env.E2E_PORT ?? 3100);
export const BASE_URL = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  forbidOnly: Boolean(process.env.CI),
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 60_000,
  use: { baseURL: BASE_URL, locale: "pt-BR", timezoneId: "America/Sao_Paulo", trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `npm run db:migrate && npm run db:seed && npx next start -p ${PORT}`,
    url: `${BASE_URL}/api/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      NODE_ENV: "production",
      SENTINELA_PUBLIC_ORIGIN: BASE_URL,
      SENTINELA_DEMO_PASSWORD: process.env.SENTINELA_DEMO_PASSWORD ?? "Demo-e2e-senha-forte-2026",
      SENTINELA_ENCRYPTION_KEY: process.env.SENTINELA_ENCRYPTION_KEY ?? "e2e0".repeat(16),
      SENTINELA_ENABLE_SCANNER: "0"
    }
  }
});
