import { expect, test } from "@playwright/test";
import { OWNER, login, loginAndWait, logout } from "./helpers";

test("rotas exigem login", async ({ page, request }) => {
  await page.goto("/achados");
  await expect(page).toHaveURL(/\/login/);
  expect((await request.get("/api/assets")).status()).toBe(401);
});

test("senha errada mostra erro e não entra", async ({ page }) => {
  await login(page, OWNER.email, "senha-errada-de-proposito");
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page).toHaveURL(/\/login/);
});

test("Owner entra, vê o painel com os dados de demonstração e sai", async ({ page }) => {
  await loginAndWait(page, OWNER.email, OWNER.password);
  await expect(page.getByText("Portal institucional", { exact: true })).toBeVisible();
  await expect(page.getByText("API de serviços", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Integrações" })).toBeVisible();
  await logout(page);
  await page.goto("/");
  await expect(page).toHaveURL(/\/login/);
});
