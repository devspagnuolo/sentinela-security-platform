# LGPD: dados pessoais no Sentinela

Este documento descreve quais dados pessoais o Sentinela guarda, para quê, por quanto tempo e como atender os pedidos dos titulares. Ele serve de base para o registro das operações de tratamento (art. 37) e para o relatório de impacto (art. 38) da organização que opera a plataforma. A organização é a **controladora** dos dados. O Sentinela é a ferramenta, e quem hospeda a instalação é o operador.

## Inventário

| Dado | Onde fica | Titular | Finalidade | Base legal sugerida | Retenção |
|---|---|---|---|---|---|
| Nome e e-mail | `users` | Pessoas da equipe | Identificar quem acessa e quem fez cada ação | Execução de contrato ou legítimo interesse (art. 7, V e IX) | Enquanto a pessoa tiver acesso. Depois, anonimização a pedido |
| Senha (hash scrypt), segredo TOTP (cifrado), códigos de recuperação (hash) | `users`, `recovery_codes` | Pessoas da equipe | Autenticação | Execução de contrato | Enquanto a conta existir |
| IP e navegador das sessões | `sessions` | Pessoas da equipe | Segurança da conta | Legítimo interesse, segurança (art. 46) | Até a sessão vencer (12 h) ou ser encerrada |
| IP de logins, falhas de login e SSO recusado | `audit_log.metadata` | Pessoas da equipe | Trilha de auditoria e investigação de incidentes | Cumprimento de obrigação legal (Marco Civil, art. 15) e legítimo interesse | Prazo da auditoria (padrão 2 anos, mínimo 6 meses) |
| Vínculo SSO (issuer e `sub`) | `sso_identities` | Pessoas da equipe | Login único | Execução de contrato | Enquanto a conta existir |
| Tokens de API (nome, prefixo, último IP) | `api_tokens` | Pessoas da equipe | Integrações | Execução de contrato | Revogados e vencidos saem da tela em 30 dias. Apagados na anonimização |
| Avisos (e e-mail enviado) | `notifications` | Pessoas da equipe | Alertas operacionais | Legítimo interesse | Lidos são apagados em 90 dias |
| Contato do cliente e contato de emergência | `clients`, `authorizations` | Pessoas do cliente | Avisar o cliente durante uma avaliação autorizada | Execução de contrato com o cliente | Contato de emergência: apagado após o fim do escopo (padrão 180 dias) |
| Evidências das avaliações | `assessments`, `assessment_findings`, `findings` | Em geral nenhum (cabeçalhos HTTP, TLS, DNS) | Relatório de segurança | Execução de contrato com o cliente | Configurável. Padrão: manter |

O scanner é passivo. Ele não lê o corpo das páginas e não guarda nomes nem valores de cookies dos alvos, então as evidências normalmente não têm dados pessoais. Se um alvo expuser dados pessoais em cabeçalhos, eles entram na evidência e seguem o prazo das avaliações.

## Prazos de retenção

O Owner define os prazos em **Minha conta → Retenção de dados**. O worker aplica de hora em hora e grava na auditoria `organization.retention_applied`, só com as contagens:

- **Trilha de auditoria**: 6 meses, 1, 2 (padrão) ou 5 anos.
- **Avaliações antigas**: 90 dias a 5 anos, ou manter (padrão). A última avaliação concluída de cada ativo é sempre mantida, porque é a base do relatório. Achados não são apagados junto com a execução que os encontrou.
- **Achados corrigidos ou falsos positivos**: 90 dias a 5 anos, ou manter (padrão), contados da triagem. Achados abertos ou com risco aceito não são apagados.
- **Contato de emergência**: 30, 90, 180 (padrão) ou 365 dias depois da revogação ou do vencimento do escopo.

Também são apagados sem configuração: sessões e desafios de MFA vencidos, logins SSO não concluídos, avisos lidos há 90 dias e entregas de webhook com mais de 30 dias.

**Backups** guardam uma cópia do banco por `BACKUP_RETENTION_DAYS` dias (padrão 14). Um dado apagado ou anonimizado só some de vez quando o último backup que o contém expira. Informe esse prazo no seu registro de tratamento.

## Pedidos dos titulares (art. 18)

| Direito | Como atender |
|---|---|
| Confirmação e acesso (I, II) | A própria pessoa baixa os dados em **Minha conta → Privacidade e dados → Baixar meus dados** (JSON). A exportação traz perfil, organizações, sessões com IP e navegador, tokens, vínculos SSO, avisos e até 5.000 eventos de auditoria em que ela é autora ou alvo. Senhas, segredos e tokens não saem, porque só existem como hash ou cifrados. |
| Correção (III) | Um Admin ou Owner corrige o nome em **Usuários**. O e-mail é o login; para trocar, crie a conta nova e anonimize a antiga. |
| Eliminação e anonimização (IV, VI) | Um Owner usa **Usuários → Anonimizar**, digitando o e-mail da pessoa para confirmar. |
| Portabilidade (V) | A exportação pessoal, e para a organização inteira **Minha conta → Exportar dados da organização** (só Owner). |
| Informação sobre compartilhamento (VII) | Os dados só saem da instalação por webhooks e e-mail configurados pela organização (veja **Integrações**). Nenhum dado vai para o desenvolvedor do Sentinela. |

### O que a anonimização faz

É irreversível. Na conta da pessoa:

- o e-mail vira `removido+<id>@anonimizado.invalid` e o nome vira "Pessoa removida";
- senha, MFA e códigos de recuperação são apagados, e a conta fica desativada sem poder ser reativada;
- sessões, tokens de API, vínculos SSO e avisos são apagados;
- na auditoria da organização, os campos `ip`, `email`, `name` e `userAgent` dos eventos ligados à pessoa são removidos, inclusive tentativas de SSO recusadas com o e-mail dela.

As ações que a pessoa fez continuam registradas (quem aprovou um escopo, quem fez uma triagem), agora atribuídas a "Pessoa removida". Isso mantém a trilha íntegra para fins de defesa em processo (art. 16, II e art. 7, VI) sem identificar a pessoa.

Proteções: ninguém anonimiza a própria conta, a organização mantém ao menos um Owner ativo, e uma pessoa que também participa de outra organização na mesma instalação precisa ser tratada pelo operador.

## Exportação da organização

`GET /api/organization/export` (Owner) devolve um JSON com organização e prazos, membros, clientes, escopos, ativos, avaliações, evidências, achados, histórico de triagem, até 50.000 eventos de auditoria, webhooks (sem o segredo), metadados de tokens (sem o hash) a configuração de SSO (sem o client secret), os conectores de nuvem (sem a credencial) e os hostnames descobertos. A exportação fica registrada na auditoria.

## Segurança (art. 46)

- Senhas com scrypt. Segredos TOTP, de SSO, de webhooks e credenciais dos conectores de nuvem cifrados com AES-256-GCM (`SENTINELA_ENCRYPTION_KEY`).
- Sessões e tokens guardados só como SHA-256.
- MFA por TOTP e SSO via OIDC, com política de MFA obrigatório por organização.
- Isolamento por organização em toda consulta (`organization_id`).
- Auditoria somente de inserção. Os únicos apagamentos são os da retenção e os campos removidos na anonimização.
- Logs do servidor sem senhas, tokens nem segredos (`src/lib/logger.ts`).
