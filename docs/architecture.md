# Arquitetura para uso individual

## Objetivo

Sentinela é uma estação de trabalho privada para um consultor de segurança. Cada projeto pertence a um cliente e guarda escopo autorizado, janelas de análise, contatos, ativos, execuções, achados revisados e relatórios. Multiempresa significa separação de projetos e dados, não um SaaS compartilhado nem gestão de usuários de clientes.

## Estado implementado

As rotas API persistem em PostgreSQL via Drizzle ORM (`apps/web/src/db`). O esquema já é multi-tenant: `organizations`, `users`, `memberships` (papéis owner, admin, analyst, viewer), `clients`, `authorizations`, `assets`, `assessments`, `findings` e `audit_log`, todas as tabelas de negócio com `organization_id`. O acesso a dados passa apenas por `tenantRepository(db, organizationId)`, que filtra toda consulta e escrita pela organização; testes verificam que uma organização não lê nem altera dados de outra. A trilha de auditoria é somente de inserção e ordenada por uma sequência monotônica.

Autenticação e autorização: login por e-mail e senha (scrypt N=2^15, r=8, p=3), sessão opaca em cookie com apenas o SHA-256 do token gravado em `sessions`, expiração absoluta de 12 h e por ociosidade de 2 h, bloqueio de 15 min após 5 falhas e mensagens de erro que não revelam se o e-mail existe. Toda rota de API passa por `withAuth(permissão, handler)` (`src/lib/auth/http.ts`), que valida sessão, papel e mesma origem antes de entregar um `tenantRepository` preso à organização da sessão e ao usuário (gravado como autor na auditoria). A matriz de permissões está em `src/lib/auth/rbac.ts`. Desativar um usuário, trocar seu papel ou redefinir sua senha encerra as sessões dele. MFA: com TOTP ativo (RFC 6238, SHA-1, 30 s, janela de ±1 passo), o login por senha devolve apenas um desafio (hash no banco, 5 minutos, até 5 tentativas) e a sessão só é criada em `/api/auth/mfa/verify`. O último passo TOTP aceito fica gravado para impedir reuso do mesmo código; códigos de recuperação são guardados como HMAC e marcados como usados. Códigos errados contam para o bloqueio da conta. O segredo TOTP é cifrado com AES-256-GCM (`src/lib/crypto.ts`); desativar o MFA ou gerar novos códigos exige a senha. Com `require_mfa` na organização, `withAuth` e `requireSession` só liberam a configuração de MFA, troca de senha e `/api/auth/me` até o usuário concluir o cadastro. SSO: cada organização pode ter um provedor OIDC (`sso_connections`, client secret cifrado). `/api/auth/sso/start` localiza o provedor pelo domínio do e-mail, grava state/nonce/PKCE em `sso_requests` (10 min) e põe o state num cookie HttpOnly; `/api/auth/sso/callback` exige o mesmo state no cookie (impede login CSRF), troca o código e valida o ID token com `openid-client`. A identidade fica vinculada por (issuer, sub) em `sso_identities`; no primeiro acesso, o vínculo é feito pelo e-mail (domínio permitido e `email_verified` diferente de false) ou, se configurado, o usuário é criado sem senha. Sessões guardam o método (`password`, `mfa`, `sso`), e as de SSO cumprem `require_mfa`. No Entra ID, use o issuer do tenant (`https://login.microsoftonline.com/<tenant>/v2.0`) e inclua o claim opcional `email`. O scanner faz uma requisição HTTPS GET para a URL raiz, sem redirecionamento, com timeout de 5 segundos, conectando ao endereço IP validado (DNS fixado) e lendo somente status e cabeçalhos. Verifica alguns cabeçalhos defensivos, política CORS observada, atributos de cookies e banner Server. Na mesma conexão, lê o certificado apresentado: a conexão não é abortada por certificado inválido, que vira achado. Depois consulta CAA, MX, SPF e DMARC no resolvedor (`src/lib/checks.ts`). As consultas sobem do hostname para os domínios acima e só acontecem se o resolvedor responder NS em algum nível, o que evita achados de "ausente" falsos em redes que filtram DNS. A execução grava a versão do método (`assessments.method`), e o relatório descreve exatamente aquela versão. O corpo da resposta não é persistido. O relatório por ativo apresenta método, evidências mínimas, limitações e recomendações em JSON ou HTML imprimível.

## Fluxo de dados proposto

```text
Navegador do operador -> aplicação privada -> banco de projetos
                                      -> fila de avaliações -> worker com saída restrita
                                      -> armazenamento criptografado de relatórios
```

O primeiro marco de produção deve exigir autenticação do operador, criptografia, backup, auditoria e segregação por cliente. Um banco PostgreSQL é suficiente para os registros. Redis e RabbitMQ são opcionais até haver tarefas assíncronas em escala. Kubernetes, Terraform e conectores cloud devem ser introduzidos apenas quando houver necessidade operacional concreta.

## Modelo de autorização

Cada autorização registra cliente, responsável, referência documental, hostnames exatos, janela de início e término, métodos permitidos, limites de taxa, exclusões e contato de emergência. O worker recebe um escopo assinado e expira a execução ao fim da janela. A configuração de hostnames no ambiente é um bloqueio adicional; não substitui a autorização formal.

Antes de cada conexão, o worker deve validar o hostname, resolver DNS, rejeitar IPs privados e fixar o endereço validado para a conexão TLS. Redirecionamentos ficam desabilitados por padrão. Timeouts, limite de bytes, concorrência baixa e cancelamento devem ser obrigatórios. Nenhum dado sensível da resposta deve ser guardado sem necessidade.

## Interpretação dos resultados

A ausência de cabeçalho ou um banner é um indicador de configuração, não prova de exploração. A severidade depende de contexto, exposição, compensações e impacto para o cliente. CVSS, CWE, OWASP, MITRE ATT&CK e CIS podem ser referências quando cabíveis; nunca atribua mapeamentos ou notas automáticas sem evidência. O operador revisa e aprova todos os achados antes da entrega.

## Limites atuais

Sem enumeração de cifras e versões TLS, DNSSEC, descoberta ampla, testes autenticados, cloud ou IA.

Relatórios: `src/lib/report.ts` monta o conteúdo uma vez (`buildReport`), e JSON, HTML (`renderHtml`) e PDF (`src/lib/pdf.ts`, pdf-lib com as fontes padrão Helvetica, sem recursos externos) saem desse mesmo objeto. Caracteres fora do WinAnsi viram equivalentes ou "?". A exportação XLSX (`src/lib/xlsx.ts`) não usa dependências: gera o pacote OOXML com zlib e grava todo texto como `inlineStr`, que o Excel nunca avalia como fórmula. O protótipo não deve receber dados reais de clientes nem ser exposto publicamente até que os controles essenciais estejam implementados.

## Escopos e ciclo de vida dos achados

`authorizations` guarda a autorização de escopo, com status `pending`, `approved` ou `revoked`, hostnames e exclusões (`text[]`) e a janela `valid_from`/`valid_until`. A decisão é tomada por funções puras em `src/lib/scope.ts` (`evaluateScope`): aprovada, dentro da janela, hostname coberto por um padrão exato ou `*.dominio` e fora das exclusões. Ela vale no cadastro do ativo (`assets.authorization_id`) e de novo imediatamente antes de cada avaliação. Uma tentativa bloqueada gera `assessment.blocked` na auditoria, sem nenhuma requisição ao alvo. A aprovação exige `scope:approve` e outra pessoa; o Owner pode aprovar a própria autorização, e isso fica auditado com `selfApproved`.

`findings` tem um registro por (organização, ativo, `fingerprint`), em que a impressão digital é `categoria|título` normalizados. `assessment_findings` liga cada execução aos achados que ela observou, com a evidência daquela execução. `recordAssessment` consolida tudo numa transação: cria os novos, atualiza os conhecidos, reabre os `fixed` que voltaram e marca como `fixed` os `open`/`accepted` que não apareceram. `false_positive` não muda automaticamente. Aceites de risco têm `accepted_until`; ao listar ou avaliar, os vencidos voltam a `open`. Toda transição gera uma linha em `finding_events` (somente inserção) e, quando é manual, também em `audit_log`. A migração `0004` consolida os achados duplicados de versões anteriores.

## Fila de avaliações, agenda e notificações

A tabela `assessments` é a fila e também o registro de cada execução. `queued` → `running` → `completed` | `failed`, com `trigger` (`manual` ou `scheduled`), `requested_by`, `attempts`, `run_after`, `locked_at` e `summary` (observados, novos, reabertos e corrigidos). Um índice único parcial garante no máximo uma execução pendente ou em andamento por ativo; pedir de novo devolve a existente.

O worker (`src/lib/worker.ts`) é iniciado por `src/instrumentation.ts` em cada processo Node e roda a cada `SENTINELA_WORKER_POLL_MS` (padrão 5 s). A rota de avaliação também o acorda na hora. A cada ciclo, ele faz o seguinte:

1. Devolve à fila jobs presos em `running` há mais de 10 minutos; depois de 3 tentativas, marca como falha.
2. Enfileira os ativos cuja `next_assessment_at` venceu e já grava a próxima data.
3. Uma vez por minuto, expira aceites de risco, avisa sobre escopos que vencem em até 14 dias (uma vez por autorização, `expiry_notified_at`) e apaga avisos lidos há mais de 90 dias.
4. Pega jobs com `UPDATE … WHERE id = (SELECT … FOR UPDATE SKIP LOCKED LIMIT 1)`. A subconsulta escalar é avaliada uma vez; com `IN`, o Postgres pode reavaliá-la por linha e marcar vários jobs de uma vez.

Ao executar, o worker carrega o ativo e avalia o escopo de novo. Se o escopo não libera, registra `assessment.blocked` e falha sem contatar o alvo. Erros de rede (`TransientAssessmentError`) voltam à fila com espera de 1, 2 e 4 minutos; os demais erros falham na hora.

`notifications` guarda um aviso por destinatário (`read_at` individual). `notify` escolhe os membros ativos por público. A operação (Owner, Admin e Analista) recebe achados altos ou críticos novos e reaberturas, e falhas de execuções agendadas. A gestão (Owner e Admin) recebe escopos pendentes (exceto quem cadastrou), escopos vencendo e aceites de risco vencidos. A falha de uma avaliação manual vai para quem a pediu.
