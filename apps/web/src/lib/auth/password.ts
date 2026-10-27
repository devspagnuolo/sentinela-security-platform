import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

// scrypt nativo do Node (sem dependência binária, funciona em x64 e ARM).
// Parâmetros da recomendação OWASP: N=2^15, r=8, p=3 (~32 MiB por cálculo).
const PARAMS = { N: 2 ** 15, r: 8, p: 3, keyLength: 64 };
const MAXMEM = 128 * 1024 * 1024;
export const MIN_PASSWORD_LENGTH = 12;

function derive(password: string, salt: Buffer, params: { N: number; r: number; p: number; keyLength: number }) {
  const options: ScryptOptions = { N: params.N, r: params.r, p: params.p, maxmem: MAXMEM };
  return new Promise<Buffer>((resolve, reject) => scrypt(password.normalize("NFKC"), salt, params.keyLength, options, (error, key) => error ? reject(error) : resolve(key)));
}

/** Formato: scrypt$N$r$p$salt$hash (base64url). */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt, PARAMS);
  return ["scrypt", PARAMS.N, PARAMS.r, PARAMS.p, salt.toString("base64url"), key.toString("base64url")].join("$");
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, n, r, p, salt, hash] = stored.split("$");
  if (scheme !== "scrypt" || !salt || !hash) return false;
  const expected = Buffer.from(hash, "base64url");
  const actual = await derive(password, Buffer.from(salt, "base64url"), { N: Number(n), r: Number(r), p: Number(p), keyLength: expected.length });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

let dummy: Promise<string> | undefined;
/** Executa uma verificação descartável para que e-mails inexistentes levem o mesmo tempo que senhas erradas. */
export async function burnVerification(password: string) {
  dummy ??= hashPassword(randomBytes(16).toString("hex"));
  await verifyPassword(password, await dummy);
}

export function passwordPolicyError(password: string, context: { email?: string; name?: string } = {}): string | undefined {
  if (password.length < MIN_PASSWORD_LENGTH) return `A senha precisa ter pelo menos ${MIN_PASSWORD_LENGTH} caracteres.`;
  if (password.length > 256) return "A senha pode ter no máximo 256 caracteres.";
  const lower = password.toLowerCase();
  const local = context.email?.split("@")[0]?.toLowerCase();
  if (local && local.length >= 4 && lower.includes(local)) return "A senha não pode conter o seu e-mail.";
  if (new Set(password).size < 5) return "A senha é repetitiva demais.";
  return undefined;
}
