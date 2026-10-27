import { describe, expect, it } from "vitest";
import { hashPassword, passwordPolicyError, verifyPassword } from "./password";

describe("password", () => {
  it("gera hash scrypt com salt único e verifica corretamente", async () => {
    const [a, b] = await Promise.all([hashPassword("uma senha longa e boa"), hashPassword("uma senha longa e boa")]);
    expect(a).toMatch(/^scrypt\$32768\$8\$3\$/);
    expect(a).not.toBe(b);
    expect(await verifyPassword("uma senha longa e boa", a)).toBe(true);
    expect(await verifyPassword("uma senha longa e ruim", a)).toBe(false);
  });

  it("rejeita hashes malformados sem lançar erro", async () => {
    expect(await verifyPassword("x", "")).toBe(false);
    expect(await verifyPassword("x", "bcrypt$abc")).toBe(false);
  });

  it("aplica a política mínima", () => {
    expect(passwordPolicyError("curta")).toContain("12");
    expect(passwordPolicyError("aaaaaaaaaaaaaaaa")).toContain("repetitiva");
    expect(passwordPolicyError("rafael.garcia-2026!", { email: "rafael.garcia@example.com" })).toContain("e-mail");
    expect(passwordPolicyError("correct-horse-battery-staple")).toBeUndefined();
  });
});
