// Sem dependências de Node: usado também pela interface.

/** Eventos que um webhook pode assinar, com o rótulo da interface. */
export const WEBHOOK_EVENTS = {
  "assessment.completed": "Avaliação concluída",
  "assessment.failed": "Avaliação não concluída",
  "finding.status_changed": "Triagem de achado",
  "finding.acceptance_expired": "Aceite de risco vencido",
  "scope.pending": "Escopo aguardando aprovação",
  "scope.approved": "Escopo aprovado",
  "scope.revoked": "Escopo revogado",
  "scope.expiring": "Escopo perto do vencimento",
  "discovery.hosts_found": "Hostnames novos nos conectores de nuvem"
} as const;
export type WebhookEvent = keyof typeof WEBHOOK_EVENTS;
export const WEBHOOK_EVENT_TYPES = Object.keys(WEBHOOK_EVENTS) as WebhookEvent[];
/** Evento enviado só pelo botão "Testar"; não pode ser assinado. */
export const TEST_EVENT = "webhook.test";
