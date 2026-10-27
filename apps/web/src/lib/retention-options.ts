/**
 * Prazos de retenção que o Owner pode escolher (LGPD). Sem dependências de servidor:
 * usado também pela interface. A aplicação dos prazos fica em src/db/retention.ts.
 */
// Auditoria: mínimo de 6 meses (registros de acesso, Marco Civil art. 15).
export const AUDIT_RETENTION_OPTIONS = [180, 365, 730, 1825] as const;
// Avaliações e achados encerrados: null = manter.
export const DATA_RETENTION_OPTIONS = [90, 180, 365, 730, 1825] as const;
// Contato de emergência, contado do fim do escopo (revogado ou vencido).
export const CONTACT_RETENTION_OPTIONS = [30, 90, 180, 365] as const;

export type RetentionSettings = {
  auditRetentionDays: number; assessmentRetentionDays: number | null;
  closedFindingRetentionDays: number | null; scopeContactRetentionDays: number;
};

export function retentionLabel(days: number | null) {
  if (days === null) return "Manter";
  if (days % 365 === 0) return days === 365 ? "1 ano" : `${days / 365} anos`;
  if (days === 180) return "6 meses";
  return `${days} dias`;
}
