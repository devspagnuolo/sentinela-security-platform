import { describe, expect, it } from "vitest";
import { request, signIn, TEST_PASSWORD } from "@/test/auth";
import { GET, POST } from "./route";
import { PATCH } from "./[id]/route";

const ctx = {} as never;
const params = (id: string) => ({ params: Promise.resolve({ id }) });
let n = 0;
const newUser = (role: string) => ({ email: `novo${++n}@example.com`, name: "Novo usuário", role, password: TEST_PASSWORD });
const create = (cookie: string, body: unknown) => POST(request("/api/users", { cookie, body }), ctx);
const patch = (cookie: string, id: string, body: unknown) => PATCH(request(`/api/users/${id}`, { cookie, body, method: "PATCH" }), params(id));

describe("/api/users", () => {
  it("Analista e Leitor não acessam a gestão de usuários", async () => {
    for (const role of ["analyst", "viewer"] as const) {
      const { cookie } = await signIn(role);
      expect((await GET(request("/api/users", { cookie }), ctx)).status).toBe(403);
      expect((await create(cookie, newUser("viewer"))).status).toBe(403);
    }
  });

  it("Admin cria Analista e Leitor, mas não Admin nem Owner", async () => {
    const { cookie } = await signIn("admin");
    expect((await create(cookie, newUser("analyst"))).status).toBe(201);
    expect((await create(cookie, newUser("viewer"))).status).toBe(201);
    expect((await create(cookie, newUser("admin"))).status).toBe(403);
    expect((await create(cookie, newUser("owner"))).status).toBe(403);
  });

  it("valida senha, e-mail e duplicidade", async () => {
    const { cookie } = await signIn("owner");
    expect((await create(cookie, { ...newUser("viewer"), password: "curta" })).status).toBe(400);
    expect((await create(cookie, { ...newUser("viewer"), email: "invalido" })).status).toBe(400);
    const dup = newUser("viewer");
    expect((await create(cookie, dup)).status).toBe(201);
    expect((await create(cookie, dup)).status).toBe(409);
  });

  it("Admin não promove ninguém a Admin nem altera Owner", async () => {
    const owner = await signIn("owner");
    const admin = await signIn("admin", owner.organizationId);
    const analyst = await (await create(owner.cookie, newUser("analyst"))).json();
    expect((await patch(admin.cookie, analyst.id, { role: "admin" })).status).toBe(403);
    expect((await patch(admin.cookie, owner.user.id, { disabled: true })).status).toBe(403);
    expect((await patch(admin.cookie, analyst.id, { role: "viewer" })).status).toBe(200);
  });

  it("mantém ao menos um Owner ativo e impede alterar a própria conta", async () => {
    const owner = await signIn("owner");
    expect((await patch(owner.cookie, owner.user.id, { role: "admin" })).status).toBe(403);
    const second = await signIn("owner", owner.organizationId);
    expect((await patch(second.cookie, owner.user.id, { role: "admin" })).status).toBe(200);
    expect((await patch(owner.cookie, second.user.id, { disabled: true })).status).toBe(401);
  });

  it("desativar ou redefinir senha encerra as sessões do usuário", async () => {
    const owner = await signIn("owner");
    const viewer = await signIn("viewer", owner.organizationId);
    expect((await GET(request("/api/users", { cookie: owner.cookie }), ctx)).status).toBe(200);
    expect((await patch(owner.cookie, viewer.user.id, { password: "outra-senha-bem-longa" })).status).toBe(200);
    const { GET: me } = await import("../auth/me/route");
    expect((await me(request("/api/auth/me", { cookie: viewer.cookie }), ctx)).status).toBe(401);
  });

  it("não enxerga nem altera usuários de outra organização", async () => {
    const a = await signIn("owner");
    const b = await signIn("owner");
    const list = await (await GET(request("/api/users", { cookie: a.cookie }), ctx)).json();
    expect(list.map((m: { id: string }) => m.id)).not.toContain(b.user.id);
    expect((await patch(a.cookie, b.user.id, { disabled: true })).status).toBe(404);
    expect((await patch(a.cookie, "nao-e-uuid", { disabled: true })).status).toBe(404);
  });
});
