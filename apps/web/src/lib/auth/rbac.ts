export const ROLES = ["owner", "admin", "analyst", "viewer"] as const;
export type Role = (typeof ROLES)[number];

export const ROLE_LABELS: Record<Role, string> = { owner: "Owner", admin: "Admin", analyst: "Analista", viewer: "Leitor" };

export type Permission =
  | "asset:read" | "asset:write" | "assessment:run" | "report:read" | "export:download"
  | "audit:read" | "user:read" | "user:manage" | "org:manage"
  | "scope:write" | "scope:approve" | "finding:triage" | "finding:accept" | "integration:manage";

const viewer: Permission[] = ["asset:read", "report:read"];
// Analista cadastra escopos e faz a triagem técnica (falso positivo, corrigido, reabrir).
const analyst: Permission[] = [...viewer, "asset:write", "assessment:run", "export:download", "scope:write", "finding:triage"];
// Aprovar escopo e aceitar risco são decisões de gestão.
// Webhooks enviam dados da organização para fora: decisão de gestão.
const admin: Permission[] = [...analyst, "audit:read", "user:read", "user:manage", "scope:approve", "finding:accept", "integration:manage"];

const grants: Record<Role, ReadonlySet<Permission>> = {
  viewer: new Set(viewer),
  analyst: new Set(analyst),
  admin: new Set(admin),
  owner: new Set<Permission>([...admin, "org:manage"])
};

export function can(role: Role, permission: Permission): boolean {
  return grants[role].has(permission);
}

const rank: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2, owner: 3 };
export const rankOf = (role: Role) => rank[role];
/** O papel de menor permissão entre os dois. */
export const lowerRole = (a: Role, b: Role): Role => rank[a] <= rank[b] ? a : b;

/**
 * Quem pode atribuir (ou alterar) um papel: Owner gerencia todos;
 * Admin gerencia apenas Analista e Leitor; demais não gerenciam usuários.
 */
export function canManageRole(actor: Role, target: Role): boolean {
  if (!can(actor, "user:manage")) return false;
  return actor === "owner" || rank[target] < rank.admin;
}
