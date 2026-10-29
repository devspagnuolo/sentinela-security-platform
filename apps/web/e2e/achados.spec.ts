import { expect, test } from "@playwright/test";
import { OWNER, loginAndWait } from "./helpers";

test.beforeEach(async ({ page }) => { await loginAndWait(page, OWNER.email, OWNER.password); });

test("triagem de achado como falso positivo exige motivo e fica no histórico", async ({ page }) => {
  await page.goto("/achados");
  await page.getByText("Cookie sem atributo SameSite explícito").click();
  const detail = page.getByLabel("Detalhes do achado");
  await detail.getByRole("button", { name: "Falso positivo" }).click();
  await detail.getByLabel("Por que é um falso positivo?").fill("Cookie de terceiros fora do controle do cliente (E2E).");
  await detail.getByRole("button", { name: "Confirmar" }).click();
  await expect(page.getByRole("status")).toBeVisible();
  await expect(detail.locator(".history")).toContainText("Aberto → Falso positivo · Administrador demo: Cookie de terceiros fora do controle do cliente (E2E).");
});

test("relatórios e exportações saem nos formatos certos", async ({ page }) => {
  const assets = await (await page.request.get("/api/assets")).json() as { id: string; name: string }[];
  const portal = assets.find(a => a.name === "Portal institucional")!;

  const html = await page.request.get(`/api/reports/${portal.id}?format=html`);
  expect(html.ok()).toBe(true);
  const body = await html.text();
  expect(body).toContain("DEMO-2026-001");
  expect(body).toContain("Política de segurança de conteúdo ausente");

  const pdf = await page.request.get(`/api/reports/${portal.id}?format=pdf`);
  expect(pdf.headers()["content-type"]).toContain("application/pdf");
  expect((await pdf.body()).subarray(0, 5).toString()).toBe("%PDF-");

  await page.goto("/achados");
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "XLSX" }).click();
  const file = await download;
  expect(file.suggestedFilename()).toMatch(/\.xlsx$/);
});

test("inventário de tecnologias lista o que a avaliação observou", async ({ page }) => {
  await page.goto("/inventario");
  await expect(page.getByText("nginx").first()).toBeVisible();
  await expect(page.getByText("Let's Encrypt").first()).toBeVisible();
});
