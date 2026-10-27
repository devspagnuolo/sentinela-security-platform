import { describe, expect, it } from "vitest";
import { can, canManageRole, type Permission, type Role } from "./rbac";

const matrix: Record<Permission, Role[]> = {
  "asset:read": ["owner", "admin", "analyst", "viewer"],
  "report:read": ["owner", "admin", "analyst", "viewer"],
  "asset:write": ["owner", "admin", "analyst"],
  "assessment:run": ["owner", "admin", "analyst"],
  "export:download": ["owner", "admin", "analyst"],
  "audit:read": ["owner", "admin"],
  "user:read": ["owner", "admin"],
  "user:manage": ["owner", "admin"],
  "org:manage": ["owner"],
  "scope:write": ["owner", "admin", "analyst"],
  "scope:approve": ["owner", "admin"],
  "finding:triage": ["owner", "admin", "analyst"],
  "finding:accept": ["owner", "admin"],
  "integration:manage": ["owner", "admin"]
};

describe("RBAC", () => {
  it.each(Object.entries(matrix))("%s é concedida exatamente a %j", (permission, roles) => {
    for (const role of ["owner", "admin", "analyst", "viewer"] as Role[]) expect(can(role, permission as Permission)).toBe(roles.includes(role));
  });

  it("Owner gerencia todos; Admin só Analista e Leitor; demais ninguém", () => {
    expect(["owner", "admin", "analyst", "viewer"].every(r => canManageRole("owner", r as Role))).toBe(true);
    expect(canManageRole("admin", "analyst") && canManageRole("admin", "viewer")).toBe(true);
    expect(canManageRole("admin", "admin") || canManageRole("admin", "owner")).toBe(false);
    expect(canManageRole("analyst", "viewer") || canManageRole("viewer", "viewer")).toBe(false);
  });
});
