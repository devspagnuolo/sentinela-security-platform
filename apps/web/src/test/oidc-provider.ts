import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

type Grant = { nonce: string; challenge: string; claims: Record<string, unknown>; redirectUri: string };

/** Provedor OIDC mínimo para testes: descoberta, JWKS e token endpoint com PKCE. */
export async function startOidcProvider(clientId = "sentinela-test", clientSecret = "test-secret") {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const grants = new Map<string, Grant>();
  let issuer = "";
  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", issuer);
    const json = (status: number, body: unknown) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
    if (url.pathname === "/.well-known/openid-configuration") return json(200, {
      issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`,
      response_types_supported: ["code"], subject_types_supported: ["public"], id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]
    });
    if (url.pathname === "/jwks") return json(200, { keys: [jwk] });
    if (url.pathname === "/token" && req.method === "POST") {
      let body = ""; for await (const chunk of req) body += chunk;
      const form = new URLSearchParams(body);
      const auth = Buffer.from((req.headers.authorization ?? "").replace(/^Basic /, ""), "base64").toString();
      const basicOk = auth === `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
      const postOk = form.get("client_id") === clientId && form.get("client_secret") === clientSecret;
      if (!basicOk && !postOk) return json(401, { error: "invalid_client" });
      const grant = grants.get(form.get("code") ?? "");
      grants.delete(form.get("code") ?? "");
      const verifier = form.get("code_verifier") ?? "";
      if (!grant || createHash("sha256").update(verifier).digest("base64url") !== grant.challenge || form.get("redirect_uri") !== grant.redirectUri) return json(400, { error: "invalid_grant" });
      const idToken = await new SignJWT({ nonce: grant.nonce, ...grant.claims }).setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(issuer).setAudience(clientId).setIssuedAt().setExpirationTime("5m").sign(privateKey);
      return json(200, { access_token: randomBytes(16).toString("hex"), token_type: "Bearer", expires_in: 300, id_token: idToken });
    }
    json(404, { error: "not_found" });
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    issuer, clientId, clientSecret,
    /** Simula o usuário autenticando no provedor: devolve o code para a URL de autorização dada. */
    authorize(authorizationUrl: string, claims: Record<string, unknown>) {
      const params = new URL(authorizationUrl).searchParams;
      const code = randomBytes(12).toString("hex");
      grants.set(code, { nonce: params.get("nonce") ?? "", challenge: params.get("code_challenge") ?? "", claims, redirectUri: params.get("redirect_uri") ?? "" });
      return { code, state: params.get("state") ?? "" };
    },
    close: () => new Promise<void>(resolve => server.close(() => resolve()))
  };
}
