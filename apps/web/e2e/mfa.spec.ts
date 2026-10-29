import { expect, test } from "@playwright/test";
import { OWNER, PASSWORD, login, loginAndWait, logout, totpNow, unique } from "./helpers";

test("pessoa ativa a verificação em duas etapas e entra com código de recuperação", async ({ page }) => {
  const email = `${unique("mfa")}@consultoria.example`;
  await loginAndWait(page, OWNER.email, OWNER.password);
  await page.goto("/usuarios");
  await page.getByPlaceholder("Nome", { exact: true }).fill("Marcos MFA");
  await page.getByPlaceholder("E-mail").fill(email);
  await page.locator("form select").selectOption({ label: "Analista" });
  await page.getByPlaceholder("Senha inicial (12+ caracteres)").fill(PASSWORD);
  await page.getByRole("button", { name: "Criar" }).click();
  await expect(page.getByText("Usuário criado.")).toBeVisible();
  await logout(page);

  await loginAndWait(page, email, PASSWORD);
  await page.goto("/conta");
  await page.getByRole("button", { name: "Configurar", exact: true }).click();
  const secret = (await page.locator("code.secret").textContent())!;
  await page.getByLabel(/Digite o código de 6 dígitos/).fill(totpNow(secret));
  await page.getByRole("button", { name: "Ativar", exact: true }).click();
  await expect(page.locator(".recovery-codes code").first()).toBeVisible();
  const codes = await page.locator(".recovery-codes code").allTextContents();
  expect(codes.length).toBeGreaterThanOrEqual(8);
  await page.getByRole("button", { name: "Já guardei os códigos" }).click();
  await expect(page.getByText(/Ativa\. Restam/)).toBeVisible();
  await logout(page);

  // A senha sozinha não basta; um código de recuperação entra e é consumido.
  await login(page, email, PASSWORD);
  await expect(page.getByRole("heading", { name: "Verificação em duas etapas" })).toBeVisible();
  await page.getByLabel("Código").fill("000000");
  await page.getByRole("button", { name: "Verificar" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await page.getByLabel("Código").fill(codes[0]);
  await page.getByRole("button", { name: "Verificar" }).click();
  await expect(page.getByRole("heading", { name: "Visão geral" })).toBeVisible();
  await page.goto("/conta");
  await expect(page.getByText(`Restam ${codes.length - 1} códigos`)).toBeVisible();
});
