import { expect, type Page } from "@playwright/test";
import { totpAt } from "../src/lib/auth/totp";

export const OWNER = { email: "admin@sentinela.local", password: process.env.SENTINELA_DEMO_PASSWORD ?? "Demo-e2e-senha-forte-2026" };
export const PASSWORD = "Senha-de-teste-e2e-2026";

/** Entra pela tela de login, como uma pessoa faria. */
export async function login(page: Page, email: string, password: string) {
  await page.goto("/login");
  await page.getByLabel("E-mail").fill(email);
  await page.getByLabel("Senha").fill(password);
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
}

export async function loginAndWait(page: Page, email: string, password: string) {
  await login(page, email, password);
  await expect(page.getByRole("heading", { name: "Visão geral" })).toBeVisible();
}

export async function logout(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Sair" }).click();
  await expect(page).toHaveURL(/\/login/);
}

/** Código TOTP atual para o segredo exibido na configuração de MFA. */
export const totpNow = (secret: string) => totpAt(secret.replace(/\s/g, ""), Math.floor(Date.now() / 30_000));

/** Nenhuma rolagem horizontal na página (layout de celular). */
export async function expectNoHorizontalScroll(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
}

export const unique = (prefix: string) => `${prefix}-${Date.now().toString(36)}`;
