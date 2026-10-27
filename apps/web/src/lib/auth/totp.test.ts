import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, generateRecoveryCodes, generateTotpSecret, otpauthUri, timeStep, totpAt, verifyTotp } from "./totp";

// Segredo e vetores do RFC 6238 (SHA1, "12345678901234567890"), truncados para 6 dígitos.
const rfcSecret = base32Encode(Buffer.from("12345678901234567890"));

describe("TOTP", () => {
  it.each([[59, "287082"], [1111111109, "081804"], [1234567890, "005924"], [2000000000, "279037"]])("vetor RFC 6238 em t=%i", (t, expected) => {
    expect(totpAt(rfcSecret, Math.floor(t / 30))).toBe(expected);
  });

  it("base32 faz ida e volta", () => {
    const buf = Buffer.from("qualquer coisa é válida");
    expect(base32Decode(base32Encode(buf)).equals(buf)).toBe(true);
    expect(generateTotpSecret()).toMatch(/^[A-Z2-7]{32}$/);
  });

  it("aceita ±1 passo e recusa códigos antigos ou reutilizados", () => {
    const secret = generateTotpSecret();
    const now = Date.now();
    const step = timeStep(now);
    expect(verifyTotp(secret, totpAt(secret, step), null, now)).toBe(step);
    expect(verifyTotp(secret, totpAt(secret, step - 1), null, now)).toBe(step - 1);
    expect(verifyTotp(secret, totpAt(secret, step - 3), null, now)).toBeNull();
    expect(verifyTotp(secret, totpAt(secret, step), step, now)).toBeNull();
    expect(verifyTotp(secret, "12345", null, now)).toBeNull();
    expect(verifyTotp(secret, "abcdef", null, now)).toBeNull();
  });

  it("gera URI otpauth e códigos de recuperação únicos", () => {
    expect(otpauthUri("ABC", "ana@example.com")).toBe("otpauth://totp/Sentinela%3Aana%40example.com?secret=ABC&issuer=Sentinela&algorithm=SHA1&digits=6&period=30");
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    expect(codes[0]).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
  });
});
