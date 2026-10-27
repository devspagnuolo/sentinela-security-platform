# Arquitetura para uso individual

## Objetivo

Sentinela é uma estação de trabalho privada para um consultor de segurança. Cada projeto pertence a um cliente e guarda escopo autorizado, janelas de análise, contatos, ativos, execuções, achados revisados e relatórios. Multiempresa significa separação de projetos e dados, não um SaaS compartilhado nem gestão de usuários de clientes.

## Estado implementado

As rotas API persistem em PostgreSQL via Drizzle ORM (`apps/web/src/db`). O esquema já é multi-tenant: `organizations`, `users`, `memberships` (papéis owner, admin, analyst, viewer), `clients`, `authorizations`, `assets`, `assessments`, `findings` e `audit_log`, todas as tabelas de negócio com `organization_id`. O acesso a dados passa apenas por `tenantRepository(db, organizationId)`, que filtra toda consulta e escrita pela organização; testes verificam que uma organização não lê nem altera dados de outra. A trilha de auditoria é somente de inserção e ordenada por uma sequência monotônica.

Autenticação e autorização: login por e-mail e senha (scrypt N=2^15, r=8, p=3), sessão opaca em cookie com apenas o SHA-256 do token gravado em `sessions`, expiração absoluta de 12 h e por ociosidade de 2 h, bloqueio de 15 min após 5 falhas e mensagens de erro que não revelam se o e-mail existe. Toda rota de API passa por `withAuth(permissão, handler)` (`src/lib/auth/http.ts`), que valida sessão, papel e mesma origem antes de entregar um `tenantRepository` preso à organização da sessão e ao usuário (gravado como autor na auditoria). A matriz de permissões está em `src/lib/auth/rbac.ts`. Desativar um usuário, trocar seu papel ou redefinir sua senha encerra as sessões dele. MFA: com TOTP ativo (RFC 6238, SHA-1, 30 s, janela de ±1 passo), o login por senha devolve apenas um desafio (hash no banco, 5 minutos, até 5 tentativas) e a sessão só é criada em `/api/auth/mfa/verify`. O último passo TOTP aceito fica gravado para impedir reuso do mesmo código; códigos de recuperação são guardados como HMAC e marcados como usados. Códigos errados contam para o bloqueio da conta. O segredo TOTP é cifrado com AES-256-GCM (`src/lib/crypto.ts`); desativar o MFA ou gerar novos códigos exige a senha. Com `require_mfa` na organização, `withAuth` e `requireSession` só liberam a configuração de MFA, troca de senha e `/api/auth/me` até o usuário concluir o cadastro. O scanner faz uma requisição HTTPS GET para a URL raiz, sem redirecionamento, com timeout de 5 segundos, conectando ao endereço IP validado (DNS fixado) e lendo somente status e cabeçalhos. Verifica alguns cabeçalhos defensivos, política CORS observada, atributos de cookies e banner Server. O corpo da resposta não é persistido. O relatório por ativo apresenta método, evidências mínimas, limitações e recomendações em JSON ou HTML imprimível.

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

Sem SSO, aprovação com validade aplicada pelo scanner, varredura TLS, descoberta ampla, testes autenticados, cloud, PDF gerado no servidor ou IA. O protótipo não deve receber dados reais de clientes nem ser exposto publicamente até que os controles essenciais estejam implementados.
