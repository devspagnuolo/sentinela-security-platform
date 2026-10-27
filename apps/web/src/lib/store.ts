import type { Asset, Assessment, Finding } from "./types";

const g = globalThis as typeof globalThis & { sentinelaStore?: { assets: Asset[]; findings: Finding[]; assessments: Assessment[] } };
export const store = g.sentinelaStore ??= {
  assets: [
    { id: "ast-001", name: "Portal institucional", url: "https://portal.example.com", kind: "Web application", owner: "Equipe Digital", approved: true, authorizationRef: "DEMO-2026-001", createdAt: new Date().toISOString() },
    { id: "ast-002", name: "API de serviços", url: "https://api.example.com", kind: "API", owner: "Plataforma", approved: true, authorizationRef: "DEMO-2026-002", createdAt: new Date().toISOString() }
  ],
  findings: [
    { id: "fnd-001", assetId: "ast-001", title: "Política de segurança de conteúdo ausente", severity: "medium", category: "HTTP Headers", description: "A resposta observada não incluiu Content-Security-Policy.", evidence: "Header ausente na resposta da raiz", recommendation: "Defina uma política CSP adequada ao inventário de recursos e monitore violações antes de aplicar bloqueio estrito.", references: ["OWASP Secure Headers"], discoveredAt: new Date().toISOString() },
    { id: "fnd-002", assetId: "ast-002", title: "HSTS ausente", severity: "low", category: "TLS / HTTP", description: "A resposta HTTPS observada não incluiu Strict-Transport-Security.", evidence: "Header ausente na resposta da raiz", recommendation: "Após confirmar suporte HTTPS em todo o domínio, habilite HSTS com max-age gradual.", references: ["OWASP Secure Headers"], discoveredAt: new Date().toISOString() },
    { id: "fnd-003", assetId: "ast-001", title: "Cookie sem atributo SameSite explícito", severity: "low", category: "Cookies", description: "Ao menos um cookie observado não declarou SameSite.", evidence: "Atributo SameSite ausente; valores de cookie foram omitidos", recommendation: "Configure SameSite=Lax ou Strict conforme o fluxo, além de Secure e HttpOnly quando aplicável.", references: ["OWASP Session Management Cheat Sheet"], discoveredAt: new Date().toISOString() }
  ],
  assessments: [
    { id: "run-001", assetId: "ast-001", status: "completed", startedAt: new Date().toISOString(), findingIds: ["fnd-001", "fnd-003"] },
    { id: "run-002", assetId: "ast-002", status: "completed", startedAt: new Date().toISOString(), findingIds: ["fnd-002"] }
  ]
};
