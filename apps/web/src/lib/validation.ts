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
