import { describe, expect, it } from "vitest";
import { createAssetSchema } from "./validation";

const valid = { name: "Portal", url: "https://app.example.com", owner: "TI", kind: "API", authorized: true, authorizationRef: "AUT-2026-01" };

describe("createAssetSchema", () => {
  it("aceita cadastro completo e aplica padrões", () => {
    expect(createAssetSchema.parse(valid).kind).toBe("API");
    expect(createAssetSchema.parse({ url: valid.url, authorized: true, authorizationRef: "AUT-1" })).toMatchObject({ name: "", owner: "", kind: "Web application" });
  });

  it("exige confirmação explícita da autorização", () => {
    expect(createAssetSchema.safeParse({ ...valid, authorized: "true" }).success).toBe(false);
    expect(createAssetSchema.safeParse({ ...valid, authorized: false }).success).toBe(false);
  });

  it("rejeita referência curta, tipo desconhecido e campos longos", () => {
    expect(createAssetSchema.safeParse({ ...valid, authorizationRef: " ab " }).success).toBe(false);
    expect(createAssetSchema.safeParse({ ...valid, kind: "Mainframe" }).success).toBe(false);
    expect(createAssetSchema.safeParse({ ...valid, name: "x".repeat(101) }).success).toBe(false);
  });
});
