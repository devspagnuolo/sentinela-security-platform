import { expect, test, type Page } from "@playwright/test";
import { OWNER, PASSWORD, loginAndWait, logout, unique } from "./helpers";

const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);

async function createUser(page: Page, name: string, email: string, role: string) {
  await page.goto("/usuarios");
  await page.getByPlaceholder("Nome", { exact: true }).fill(name);
  await page.getByPlaceholder("E-mail").fill(email);
  await page.locator("form select").selectOption({ label: role });
  await page.getByPlaceholder("Senha inicial (12+ caracteres)").fill(PASSWORD);
  await page.getByRole("button", { name: "Criar" }).click();
  await expect(page.getByText("Usuário criado.")).toBeVisible();
}

test("escopo precisa da aprovação de outra pessoa e bloqueia alvos fora da regra", async ({ page }) => {
  const admin = { name: "Ana Admin", email: `${unique("ana")}@consultoria.example` };
  const reference = unique("CT-E2E");

  // O Owner cadastra uma Admin.
  await loginAndWait(page, OWNER.email, OWNER.password);
  await createUser(page, admin.name, admin.email, "Admin");
  await logout(page);

  // A Admin cadastra o escopo, mas não pode aprovar o próprio cadastro.
  await loginAndWait(page, admin.email, PASSWORD);
  await page.goto("/escopos");
  await page.getByRole("button", { name: "Nova autorização" }).click();
  await page.getByLabel("Referência do documento").fill(reference);
  await page.getByLabel("Cliente").fill("Cliente E2E");
  await page.getByLabel("Fim da validade").fill(inDays(90));
  await page.getByLabel(/Hostnames autorizados/).fill("app.cliente-e2e.com.br\n*.api.cliente-e2e.com.br");
  await page.getByLabel("Contato de emergência").fill("soc@cliente-e2e.com.br");
  await page.getByRole("button", { name: "Cadastrar" }).click();
  await expect(page.getByRole("status")).toContainText("depois de aprovada");
  const card = page.locator("article", { hasText: reference });
  await expect(card.getByText("Aguardando aprovação de outra pessoa.")).toBeVisible();
  await expect(card.getByRole("button", { name: "Aprovar" })).toHaveCount(0);
  await logout(page);

  // O Owner aprova.
  await loginAndWait(page, OWNER.email, OWNER.password);
  await page.goto("/escopos");
  await card.getByRole("button", { name: "Aprovar" }).click();
  await expect(page.getByRole("status")).toContainText(`Autorização ${reference} aprovada.`);
  await expect(card.getByText(`aprovada por Administrador demo`)).toBeVisible();

  // Um IP literal não vira ativo, mesmo com escopo aprovado.
  await page.goto("/");
  await page.getByRole("button", { name: "Adicionar ativo" }).click();
  await page.getByLabel("Nome do ativo").fill("Alvo por IP");
  await page.getByLabel("URL HTTPS").fill("https://203.0.113.10");
  const scopeSelect = page.getByLabel("Autorização de escopo");
  await scopeSelect.selectOption({ label: (await scopeSelect.locator("option", { hasText: reference }).textContent())! });
  await page.getByRole("button", { name: "Cadastrar ativo" }).click();
  await expect(page.getByText("Cadastre um hostname DNS, não um IP literal.")).toBeVisible();
  await page.keyboard.press("Escape");

  // Revogar exige motivo e fica registrado no cartão.
  await page.goto("/escopos");
  page.once("dialog", dialog => void dialog.accept("Contrato encerrado (teste E2E)"));
  await card.getByRole("button", { name: "Revogar" }).click();
  await expect(page.getByRole("status")).toContainText("Autorização revogada.");
  await expect(card.getByText("Contrato encerrado (teste E2E)")).toBeVisible();

  // A trilha de auditoria registra as decisões.
  await page.goto("/auditoria");
  await expect(page.getByText(reference).first()).toBeVisible();
});
