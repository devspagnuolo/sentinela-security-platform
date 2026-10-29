import { expect, test } from "@playwright/test";
import { OWNER, expectNoHorizontalScroll, loginAndWait } from "./helpers";

test.use({ viewport: { width: 390, height: 844 } });

test("páginas principais cabem na tela do celular", async ({ page }) => {
  await loginAndWait(page, OWNER.email, OWNER.password);
  await expectNoHorizontalScroll(page);
  for (const [path, heading] of [
    ["/achados", "Achados"], ["/escopos", "Escopos e autorizações"], ["/inventario", "Inventário de tecnologias"],
    ["/descoberta", "Descoberta pela nuvem"], ["/integracoes", "Integrações"], ["/conta", "Minha conta"], ["/usuarios", "Usuários"], ["/auditoria", "Auditoria"]
  ]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expectNoHorizontalScroll(page);
  }
});
