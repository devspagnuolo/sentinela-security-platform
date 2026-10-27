/** Categorias de evento de auditoria (prefixo da ação) e rótulos para a interface. */
export const AUDIT_CATEGORIES = { auth: "Acesso", user: "Usuários", sso: "SSO", organization: "Organização", asset: "Ativos", assessment: "Avaliações", report: "Relatórios", export: "Exportações" } as const;
export type AuditCategory = keyof typeof AUDIT_CATEGORIES;
export const isAuditCategory = (value: string): value is AuditCategory => Object.hasOwn(AUDIT_CATEGORIES, value);

const ACTION_LABELS: Record<string, string> = {
  "auth.login_succeeded": "Login",
  "auth.login_failed": "Senha incorreta",
  "auth.login_rejected": "Login recusado",
  "auth.account_locked": "Conta bloqueada",
  "auth.password_verified": "Senha confirmada (aguardando MFA)",
  "auth.mfa_failed": "Código MFA incorreto",
  "auth.logout": "Logout",
  "auth.forbidden": "Acesso negado",
  "auth.password_changed": "Senha alterada",
  "auth.mfa_enabled": "MFA ativado",
  "auth.mfa_disabled": "MFA desativado",
  "auth.recovery_codes_regenerated": "Códigos de recuperação gerados",
  "auth.sso_failed": "Falha no SSO",
  "auth.sso_rejected": "SSO recusado",
  "user.created": "Usuário criado",
  "user.updated": "Usuário alterado",
  "user.provisioned_sso": "Usuário criado via SSO",
  "sso.updated": "SSO configurado",
  "sso.deleted": "SSO removido",
  "organization.updated": "Organização alterada",
  "asset.created": "Ativo cadastrado",
  "assessment.failed": "Avaliação com falha",
  "report.generated": "Relatório gerado",
  "export.downloaded": "Achados exportados",
  "export.audit_downloaded": "Auditoria exportada"
};
export const actionLabel = (action: string) => ACTION_LABELS[action] ?? action;
