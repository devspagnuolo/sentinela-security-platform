import { describe, expect, it } from "vitest";
import { evaluateScope, findingFingerprint, hostMatches, normalizeHostPattern, scopeState, type ScopeAuthorization } from "./scope";

const now = new Date("2026-06-15T12:00:00Z");
const auth = (over: Partial<ScopeAuthorization> = {}): ScopeAuthorization => ({ status: "approved", hostnames: ["app.cliente.com", "*.api.cliente.com"], excludedHostnames: ["legacy.api.cliente.com"], validFrom: new Date("2026-06-01T00:00:00Z"), validUntil: new Date("2026-06-30T23:59:59Z"), ...over });

describe("escopo", () => {
  it("normaliza padrões e recusa inválidos", () => {
    expect(normalizeHostPattern(" App.Cliente.com. ")).toBe("app.cliente.com");
    expect(normalizeHostPattern("*.cliente.com")).toBe("*.cliente.com");
    for (const bad of ["*", "*.com", "cliente", "https://a.com", "a.*.com", "10.0.0.1", "a b.com", "**.a.com"]) expect(normalizeHostPattern(bad)).toBeNull();
  });

  it("curinga cobre subdomínios, não o domínio raiz nem sufixos parecidos", () => {
    expect(hostMatches("*.cliente.com", "a.cliente.com")).toBe(true);
    expect(hostMatches("*.cliente.com", "a.b.cliente.com")).toBe(true);
    expect(hostMatches("*.cliente.com", "cliente.com")).toBe(false);
    expect(hostMatches("*.cliente.com", "outrocliente.com")).toBe(false);
    expect(hostMatches("app.cliente.com", "APP.cliente.com")).toBe(true);
  });

  it("só libera aprovada, dentro da janela, host no escopo e fora das exclusões", () => {
    expect(evaluateScope(auth(), "app.cliente.com", now)).toEqual({ ok: true });
    expect(evaluateScope(auth(), "v2.api.cliente.com", now)).toEqual({ ok: true });
    expect(evaluateScope(auth(), "legacy.api.cliente.com", now)).toEqual({ ok: false, reason: "host_excluded" });
    expect(evaluateScope(auth(), "outro.cliente.com", now)).toEqual({ ok: false, reason: "host_not_in_scope" });
    expect(evaluateScope(auth({ status: "pending" }), "app.cliente.com", now)).toEqual({ ok: false, reason: "not_approved" });
    expect(evaluateScope(auth({ status: "revoked" }), "app.cliente.com", now)).toEqual({ ok: false, reason: "revoked" });
    expect(evaluateScope(auth(), "app.cliente.com", new Date("2026-05-31T00:00:00Z"))).toEqual({ ok: false, reason: "not_started" });
    expect(evaluateScope(auth(), "app.cliente.com", new Date("2026-07-01T00:00:00Z"))).toEqual({ ok: false, reason: "expired" });
    expect(evaluateScope(auth({ validUntil: null }), "app.cliente.com", now)).toEqual({ ok: false, reason: "expired" });
  });

  it("situação para a interface", () => {
    expect(scopeState(auth(), now)).toBe("active");
    expect(scopeState(auth({ status: "pending" }), now)).toBe("pending");
    expect(scopeState(auth(), new Date("2026-05-01T00:00:00Z"))).toBe("scheduled");
    expect(scopeState(auth(), new Date("2026-08-01T00:00:00Z"))).toBe("expired");
  });

  it("impressão digital ignora caixa e espaços", () => {
    expect(findingFingerprint({ category: " HTTP Headers", title: "HSTS ausente " })).toBe(findingFingerprint({ category: "http headers", title: "hsts AUSENTE" }));
  });
});
