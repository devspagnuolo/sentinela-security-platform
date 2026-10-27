import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";

/**
 * Criptografia de campos sensíveis (AES-256-GCM). A chave vem de
 * SENTINELA_ENCRYPTION_KEY (32 bytes em base64 ou hex). Fora de produção, sem
 * chave, usa uma chave fixa de desenvolvimento.
 */
function key(env: NodeJS.ProcessEnv = process.env): Buffer {
  const raw = env.SENTINELA_ENCRYPTION_KEY;
  if (raw) {
    const buf = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
    if (buf.length !== 32) throw new Error("SENTINELA_ENCRYPTION_KEY deve ter 32 bytes (base64 ou hex).");
    return buf;
  }
  if (env.NODE_ENV === "production") throw new Error("Defina SENTINELA_ENCRYPTION_KEY para usar recursos que guardam segredos.");
  return createHash("sha256").update("sentinela-dev-only-key").digest();
}

/** Formato: v1.iv.tag.ciphertext (base64url). */
export function encrypt(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const data = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), data.toString("base64url")].join(".");
}

export function decrypt(payload: string): string {
  const [version, iv, tag, data] = payload.split(".");
  if (version !== "v1" || !iv || !tag || !data) throw new Error("Segredo criptografado inválido.");
  const decipher = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}

/** HMAC-SHA256 com chave derivada da chave do servidor: um vazamento só do banco não permite testar valores offline. */
export function keyedHash(value: string): string {
  return createHmac("sha256", createHash("sha256").update(key()).update("keyed-hash").digest()).update(value).digest("hex");
}
