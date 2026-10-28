# Sentinela

Ferramenta de uso individual para avaliações defensivas de sites e APIs de empresas que autorizaram formalmente o trabalho. O objetivo é registrar o escopo, identificar sinais de fragilidade com verificações não intrusivas e produzir um relatório que explique o método, os riscos observados e as correções sugeridas.

## Estado atual

Este repositório contém uma aplicação Next.js com persistência em PostgreSQL (Drizzle ORM, migrações versionadas) e isolamento de dados por organização. Sem `DATABASE_URL`, o app usa um PostgreSQL embutido (PGlite) em memória com dados demonstrativos, que não representam clientes reais. Toda alteração relevante (cadastro, avaliação, relatório, exportação) é registrada numa trilha de auditoria consultável em `/api/audit`. O scanner faz apenas uma requisição HTTPS GET à raiz de um hostname aprovado, sem seguir redirecionamentos. Ele observa cabeçalhos HTTP, CORS, atributos de cookies e banners. Nessa mesma conexão, lê o certificado TLS (confiança, nome e vencimento). Além disso, consulta registros DNS públicos (CAA, SPF e DMARC) no resolvedor, sem tocar o alvo. Esses sinais são indicativos e precisam de análise contextual antes de serem apresentados como vulnerabilidades confirmadas.

O relatório individual por ativo está disponível em PDF (gerado no servidor), HTML imprimível e JSON, com escopo, referência de autorização, método, limitações, achados, evidências e recomendações. A organização pode exportar achados, ativos e avaliações em XLSX, CSV ou JSON. Na planilha, todo texto é gravado como texto literal, então conteúdo vindo de um alvo avaliado nunca vira fórmula. Cada avaliação também monta um **inventário passivo de tecnologias** (servidor, framework, CDN, hospedagem, autoridade certificadora, provedores de e-mail e DNS) a partir do que ela já observou, sem nenhuma requisição extra ao alvo. O inventário fica em **Inventário de tecnologias**, no relatório e na planilha. Consulte [a metodologia](docs/methodology.md) e [o modelo de relatório](docs/report-template.md).

## Autorização e limites

- Avalie somente ativos e janelas cobertos por autorização formal do proprietário.
- Cada ativo pertence a uma **autorização de escopo** registrada em **Escopos e autorizações**. Ela guarda a referência do documento, o cliente, os hostnames autorizados (`app.cliente.com` ou `*.cliente.com`), as exclusões, a janela de validade e o contato de emergência. A autorização nasce pendente e só vale depois de aprovada por um Admin ou Owner diferente de quem a cadastrou; o Owner pode aprovar a própria, e isso fica registrado. Antes de cada avaliação, o scanner confere se a autorização está aprovada, dentro da validade e cobre o hostname. Revogar ou vencer bloqueia na hora.
- Além disso, o operador do servidor mantém uma segunda trava: o scanner fica desabilitado por padrão; `SENTINELA_ENABLE_SCANNER=1` habilita a execução somente para os hostnames listados em `SENTINELA_ALLOWED_HOSTS`.
- Apenas URLs HTTPS com hostname DNS público são aceitas. IPs literais, redes privadas, loopback e portas alternativas são bloqueados.
- Não há exploração, autenticação forçada, varredura de portas, crawling, escrita no alvo ou persistência de corpos de resposta.
- A conexão usa o endereço IP validado na resolução DNS (sem nova consulta), o que impede DNS rebinding; apenas status e cabeçalhos são lidos, com limite de 16 KB, e o corpo nunca é baixado.
- Todo acesso exige login. Senhas usam scrypt; sessões ficam no banco (só o hash do token), expiram em 12 h ou após 2 h sem uso, e o cookie é HttpOnly, SameSite=Lax e, em produção, Secure com prefixo `__Host-`. Após 5 senhas erradas seguidas a conta fica bloqueada por 15 minutos. Requisições que alteram dados precisam vir da mesma origem (proteção CSRF).
- Verificação em duas etapas (TOTP, compatível com Google/Microsoft Authenticator, 1Password e similares) configurável em **Minha conta**, com 10 códigos de recuperação de uso único. O Owner pode torná-la obrigatória para toda a organização; quem ainda não configurou é levado à tela de configuração antes de acessar qualquer dado. Admins podem resetar o MFA de quem perdeu o celular. Os segredos TOTP ficam criptografados (AES-256-GCM) com `SENTINELA_ENCRYPTION_KEY`.
- Login via SSO (OpenID Connect) com Google Workspace, Microsoft Entra ID, Okta ou outro provedor OIDC, configurado pelo Owner em **Minha conta**. O fluxo usa PKCE, state amarrado ao navegador e nonce; o ID token é validado (assinatura, emissor, audiência, validade). Só entram e-mails dos domínios permitidos; usuários novos podem ser criados no primeiro acesso como Leitor ou Analista. Com o SSO obrigatório, apenas Owners mantêm o login por senha, para emergências. O login via SSO cumpre a exigência de MFA da organização.
- Papéis: **Owner** e **Admin** gerenciam usuários e leem a auditoria (Admin só gerencia Analistas e Leitores); **Analista** cadastra escopos e ativos, executa avaliações, faz a triagem técnica dos achados e exporta; aprovar escopos e aceitar riscos é exclusivo de Admin e Owner; **Leitor** só consulta ativos e relatórios. A organização sempre mantém ao menos um Owner ativo. Não o exponha na internet nem use dados reais de clientes até concluir esses controles.

## Fluxo previsto para a consultoria

1. Registrar cliente, responsável, autorização, janela, domínios e limitações do teste.
2. Revisar o escopo e ativar somente os hostnames aprovados.
3. Executar verificações de baixo impacto e registrar horário, método e evidência mínima.
4. Revisar manualmente cada achado, impacto e severidade; evitar classificar ausência de header como falha explorável por si só.
5. Entregar relatório executivo e técnico por cliente, com riscos, recomendações e plano de correção.
6. Reavaliar após as correções e registrar a mudança de status.

## Executar o protótipo

Requisitos: Node.js 22.12+ (LTS) e npm. Após obter o código do GitHub:

```powershell
npm ci
npm run dev
```

Com PostgreSQL real (por exemplo, `docker compose up -d postgres`):

```powershell
copy .env.example apps\web\.env.local   # ajuste DATABASE_URL
npm run db:migrate --workspace @sentinela/web
npm run db:seed --workspace @sentinela/web     # opcional: dados demonstrativos
npm run user:create-owner --workspace @sentinela/web -- voce@empresa.com "Seu Nome"
npm run dev
```

Alterações no esquema (`apps/web/src/db/schema.ts`) geram uma nova migração com `npm run db:generate --workspace @sentinela/web`.

Verificações de qualidade (as mesmas executadas no CI):

```powershell
npm run lint
npm run typecheck
npm test
npm run build
```

Abra http://localhost:3000 e entre com `admin@sentinela.local` / `sentinela-demo-2026` (somente no banco embutido de desenvolvimento). Os ativos novos só ficam aptos à avaliação quando o hostname consta na lista do operador e a autorização é confirmada no cadastro. Os dados e indicadores iniciais são apenas demonstrativos.

## Achados e triagem

Cada problema vira um único achado por ativo, identificado por categoria e título. Reavaliações atualizam a evidência, marcam como **corrigido** o que deixou de aparecer e reabrem o que voltou. Na tela **Achados**, Analistas marcam falso positivo (com justificativa) ou corrigido. Admins e Owners podem **aceitar o risco** com justificativa e prazo de até um ano; vencido o prazo, o achado volta a aberto. Toda mudança fica no histórico do achado e na auditoria. Relatórios mostram a situação e a justificativa de cada achado.

## Avaliações em segundo plano e notificações

Ao clicar em **Avaliar**, a avaliação entra numa fila no próprio PostgreSQL e um worker dentro da aplicação a executa em segundo plano. O escopo é conferido de novo na hora da execução, então uma autorização revogada ou vencida no meio do caminho bloqueia a avaliação. Falhas de rede são repetidas até 3 vezes com espera crescente. Cada ativo pode ter **reavaliação** diária, semanal ou mensal, e o andamento fica em **Histórico de análises**.

O sino do painel leva às **Notificações**. São avisos de achados altos ou críticos novos ou reabertos, avaliações não concluídas, escopos aguardando aprovação ou vencendo em até 14 dias e aceites de risco vencidos. Cada aviso vai para os papéis que podem agir sobre ele. `SENTINELA_WORKER=0` desliga o worker de um processo, e `SENTINELA_WORKER_CONCURRENCY` (padrão 2) limita as execuções simultâneas. Várias instâncias podem rodar o worker ao mesmo tempo, porque cada job é pego com `FOR UPDATE SKIP LOCKED`.

## API e integrações

Integrações autenticam com **tokens de API** pessoais, criados em **Minha conta**. Cada token tem papel Leitor ou Analista e validade de até um ano, e só acessa as rotas de negócio (ativos, avaliações, escopos, achados, relatórios e exportação). Em **Integrações**, Admins e Owners cadastram **webhooks** assinados com HMAC-SHA256 para avaliações concluídas ou com falha, triagem de achados, aceites vencidos e mudanças de escopo. Cada entrega tem novas tentativas com espera crescente, e o webhook é desligado depois de falhas seguidas. Rotas, eventos, formato e exemplos de validação da assinatura estão em [docs/api.md](docs/api.md).

Com SMTP configurado (`SENTINELA_SMTP_URL` e `SENTINELA_MAIL_FROM`), os avisos do sino também chegam por e-mail. Cada pessoa pode desligar os e-mails em **Minha conta**, e Admins enviam um e-mail de teste em **Integrações**. Sem essa configuração, os avisos ficam só na aplicação.

## LGPD

O Owner define em **Minha conta** por quanto tempo ficam a auditoria (mínimo de 6 meses), as avaliações antigas, os achados encerrados e o contato de emergência de escopos encerrados, e o worker apaga o que passou do prazo. Cada pessoa baixa os próprios dados em JSON, o Owner exporta a organização inteira e pode anonimizar quem saiu, mantendo as ações na auditoria sem identificar a pessoa. Inventário de dados, prazos e como atender cada direito do titular estão em [docs/lgpd.md](docs/lgpd.md).

## Produção

A imagem Docker (`Dockerfile`, compatível com x86 e ARM) e o compose de produção (`deploy/`) sobem PostgreSQL, aplicação, Caddy com HTTPS automático e backup diário. O passo a passo para uma VM gratuita do Oracle Cloud está em [docs/deploy-oracle-cloud.md](docs/deploy-oracle-cloud.md). A aplicação expõe `/api/health` (com `?ready=1` também verifica o banco), escreve logs estruturados em JSON e mantém uma trilha de auditoria consultável em **Auditoria**, com exportação CSV.

## Próximos marcos

O roadmap enterprise segue nesta ordem:

1. Controles de LGPD (retenção, exportação e exclusão de dados).
2. Inventário passivo de tecnologias e conectores cloud read-only.

## Licença

Uso interno e autorizado. Defina uma licença antes de distribuir o produto.
