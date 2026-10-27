# Sentinela

Plataforma SaaS de assessment de segurança autorizado. Este repositório contém o MVP: cadastro de ativos em escopo, execução manual de verificações HTTP/TLS não intrusivas, achados e exportação JSON/CSV. Nenhuma exploração ou tentativa de autenticação é implementada.

## Segurança e autorização

- Cadastre somente ativos para os quais sua organização tenha autorização formal.
- O MVP aceita apenas URLs HTTPS públicas, bloqueia loopback, redes privadas/link-local e IPs literais.
- Cada alvo precisa estar explicitamente cadastrado e aprovado antes da análise.
- As verificações são limitadas a uma requisição GET para a URL raiz, sem seguir redirects, com timeout e limite de resposta.
- Não há varredura de portas, força bruta, exploração, crawling, execução remota ou alteração de dados.
- O modo de desenvolvimento usa dados locais demonstrativos; não é adequado para produção nem multiempresa.

## Executar

Requisitos: Node.js 20+ e npm.

```powershell
npm install
npm run dev
```

Abra http://localhost:3000. Use o botão **Novo ativo** para cadastrar um endereço autorizado e **Executar avaliação** para iniciar a checagem segura.

## Estrutura

- `apps/web`: interface Next.js, painel e API de desenvolvimento.
- `apps/web/src/lib/scanner.ts`: checagens HTTP/TLS seguras e validação de escopo.
- `docs/architecture.md`: arquitetura-alvo e próximos marcos.
- `docker-compose.yml`: PostgreSQL e Redis para desenvolvimento local.

## Próximos passos

1. Persistência multiempresa, autenticação OIDC/MFA e RBAC no NestJS.
2. Fluxo de evidência e aprovação de autorização com trilha imutável de auditoria.
3. Fila de tarefas RabbitMQ com limites por tenant e worker isolado.
4. Integrações cloud somente por APIs oficiais read-only e credenciais federadas.
5. Relatórios PDF/XLSX e correlação assistida por IA com revisão humana.

## Licença

Uso interno e autorizado. Defina uma licença antes de distribuir o produto.
