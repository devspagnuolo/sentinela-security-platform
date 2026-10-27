import { z } from "zod";

export const createAssetSchema = z.object({
  name: z.string().trim().max(100).optional().default(""),
  url: z.string().trim().min(1, "Informe a URL do ativo.").max(2048),
  owner: z.string().trim().max(100).optional().default(""),
  kind: z.enum(["Web application", "API"]).optional().default("Web application"),
  authorized: z.literal(true, { error: "Confirme a autorização formal do proprietário." }),
  authorizationRef: z.string().trim().min(4, "Informe a referência do documento de autorização.").max(120)
});

export type CreateAssetInput = z.infer<typeof createAssetSchema>;

export function firstIssue(error: z.ZodError): string {
  return error.issues[0]?.message ?? "Dados inválidos.";
}

const email = z.string().trim().toLowerCase().pipe(z.email("Informe um e-mail válido.")).pipe(z.string().max(254));
const role = z.enum(["owner", "admin", "analyst", "viewer"], { error: "Papel inválido." });

export const loginSchema = z.object({ email: z.string().trim().max(254), password: z.string().max(256) });

export const createUserSchema = z.object({
  email,
  name: z.string().trim().min(2, "Informe o nome.").max(100),
  role,
  password: z.string()
});

export const updateUserSchema = z.object({
  role: role.optional(),
  disabled: z.boolean().optional(),
  name: z.string().trim().min(2).max(100).optional(),
  password: z.string().optional(),
  resetMfa: z.literal(true).optional()
}).refine(v => Object.values(v).some(x => x !== undefined), "Nada para alterar.");

export const changePasswordSchema = z.object({ currentPassword: z.string().max(256), newPassword: z.string() });

export async function parseJson<T>(request: Request, schema: z.ZodType<T>): Promise<{ data: T } | { error: string }> {
  let body: unknown;
  try { body = await request.json(); } catch { return { error: "Corpo da requisição deve ser JSON válido." }; }
  const parsed = schema.safeParse(body);
  return parsed.success ? { data: parsed.data } : { error: firstIssue(parsed.error) };
}

export const mfaVerifySchema = z.object({ challenge: z.string().min(10).max(128), code: z.string().trim().min(6).max(20) });
export const mfaCodeSchema = z.object({ code: z.string().trim().min(6).max(20) });
export const passwordConfirmSchema = z.object({ password: z.string().max(256) });
export const organizationSchema = z.object({ requireMfa: z.boolean().optional(), name: z.string().trim().min(2).max(100).optional() }).refine(v => Object.values(v).some(x => x !== undefined), "Nada para alterar.");
