import { describe, expect, it } from "vitest";
import { authorizationSchema, createAssetSchema, findingStatusSchema } from "./validation";

const AUTH_ID = "6f1c2b8e-3d4a-4f5b-9c6d-7e8f9a0b1c2d";
const valid = { name: "Portal", url: "https://app.example.com", owner: "TI", kind: "API", authorizationId: AUTH_ID };
const inDays = (n: number) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);

describe("createAssetSchema", () => {
  it("aceita cadastro completo e aplica padrões", () => {
    expect(createAssetSchema.parse(valid).kind).toBe("API");
    expect(createAssetSchema.parse({ url: valid.url, authorizationId: AUTH_ID })).toMatchObject({ name: "", owner: "", kind: "Web application" });
  });

  it("exige a autorização de escopo", () => {
    expect(createAssetSchema.safeParse({ ...valid, authorizationId: undefined }).success).toBe(false);
    expect(createAssetSchema.safeParse({ ...valid, authorizationId: "AUT-1" }).success).toBe(false);
  });

  it("rejeita tipo desconhecido e campos longos", () => {
    expect(createAssetSchema.safeParse({ ...valid, kind: "Mainframe" }).success).toBe(false);
    expect(createAssetSchema.safeParse({ ...valid, name: "x".repeat(101) }).success).toBe(false);
  });
});

describe("authorizationSchema", () => {
  const base = { reference: "CT-2026-07", hostnames: ["App.Cliente.com", "*.api.cliente.com", ""], validUntil: inDays(30) };
  it("normaliza hostnames e converte datas para o fim do dia", () => {
    const parsed = authorizationSchema.parse(base);
    expect(parsed.hostnames).toEqual(["app.cliente.com", "*.api.cliente.com"]);
    expect(parsed.validUntil.toISOString()).toContain("T02:59:59.999Z");
    expect(parsed.validFrom).toBeNull();
  });
  it("recusa hostname inválido, lista vazia, janela invertida e validade longa", () => {
    expect(authorizationSchema.safeParse({ ...base, hostnames: ["10.0.0.1"] }).success).toBe(false);
    expect(authorizationSchema.safeParse({ ...base, hostnames: [] }).success).toBe(false);
    expect(authorizationSchema.safeParse({ ...base, validFrom: inDays(40) }).success).toBe(false);
    expect(authorizationSchema.safeParse({ ...base, validUntil: inDays(800) }).success).toBe(false);
  });
});

describe("findingStatusSchema", () => {
  it("exige justificativa para falso positivo e aceite, e prazo de até 1 ano no aceite", () => {
    expect(findingStatusSchema.safeParse({ status: "fixed" }).success).toBe(true);
    expect(findingStatusSchema.safeParse({ status: "false_positive", reason: "" }).success).toBe(false);
    expect(findingStatusSchema.safeParse({ status: "accepted", reason: "Mitigado por WAF", acceptedUntil: inDays(90) }).success).toBe(true);
    expect(findingStatusSchema.safeParse({ status: "accepted", reason: "Mitigado por WAF", acceptedUntil: inDays(400) }).success).toBe(false);
    expect(findingStatusSchema.safeParse({ status: "accepted", reason: "Mitigado por WAF" }).success).toBe(false);
    expect(findingStatusSchema.safeParse({ status: "deleted" }).success).toBe(false);
  });
});
