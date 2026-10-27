import { describe, expect, it } from "vitest";
import { request, signIn, TEST_PASSWORD } from "@/test/auth";
import { POST as LOGIN } from "./login/route";
import { POST as LOGOUT } from "./logout/route";
import { GET as ME } from "./me/route";
import { POST as PASSWORD } from "./password/route";

const ctx = {} as never;
const cookieFrom = (res: Response) => res.headers.get("set-cookie")?.split(";")[0] ?? "";

describe("/api/auth", () => {
  it("login define cookie HttpOnly/SameSite e /me devolve o usuário", async () => {
    const { user } = await signIn("analyst");
    const res = await LOGIN(request("/api/auth/login", { body: { email: user.email, password: TEST_PASSWORD } }));
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/SameSite=lax/i);
    const me = await ME(request("/api/auth/me", { cookie: cookieFrom(res) }), ctx);
    expect(await me.json()).toMatchObject({ user: { id: user.id }, role: "analyst" });
  });

  it("login inválido devolve 401 genérico e sem cookie; login de outra origem é recusado", async () => {
    const res = await LOGIN(request("/api/auth/login", { body: { email: "x@example.com", password: "errada errada" } }));
    expect(res.status).toBe(401);
    expect(res.headers.get("set-cookie")).toBeNull();
    expect((await LOGIN(request("/api/auth/login", { body: { email: "x@example.com", password: "y" }, origin: "https://evil.example" }))).status).toBe(403);
  });

  it("logout revoga a sessão", async () => {
    const { cookie } = await signIn("viewer");
    expect((await LOGOUT(request("/api/auth/logout", { cookie, body: {} }))).status).toBe(200);
    expect((await ME(request("/api/auth/me", { cookie }), ctx)).status).toBe(401);
  });

  it("troca de senha exige a senha atual e encerra as outras sessões", async () => {
    const { user, cookie } = await signIn("viewer");
    const other = await LOGIN(request("/api/auth/login", { body: { email: user.email, password: TEST_PASSWORD } }));
    expect((await PASSWORD(request("/api/auth/password", { cookie, body: { currentPassword: "errada", newPassword: "nova-senha-bem-longa" } }), ctx)).status).toBe(400);
    expect((await PASSWORD(request("/api/auth/password", { cookie, body: { currentPassword: TEST_PASSWORD, newPassword: "nova-senha-bem-longa" } }), ctx)).status).toBe(200);
    expect((await ME(request("/api/auth/me", { cookie }), ctx)).status).toBe(200);
    expect((await ME(request("/api/auth/me", { cookie: cookieFrom(other) }), ctx)).status).toBe(401);
  });
});
