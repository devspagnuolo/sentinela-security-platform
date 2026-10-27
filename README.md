# Sentinela

Ferramenta de uso individual para avaliações defensivas de sites e APIs de empresas que autorizaram formalmente o trabalho. O objetivo é registrar o escopo, identificar sinais de fragilidade com verificações não intrusivas e produzir um relatório que explique o método, os riscos observados e as correções sugeridas.

## Estado atual

Este repositório contém um protótipo Next.js. O painel usa dados demonstrativos em memória; eles não representam clientes reais. O scanner implementa apenas uma requisição HTTPS GET à raiz de um hostname aprovado, sem seguir redirecionamentos. Ele observa cabeçalhos HTTP, CORS, atributos de cookies e banners. Esses sinais são indicativos e precisam de análise contextual antes de serem apresentados como vulnerabilidades confirmadas.

O relatório individual por ativo está disponível em JSON e HTML imprimível, com escopo, referência de autorização, método, limitações, achados, evidências e recomendações. No navegador, a versão HTML pode ser salva como PDF. Consulte [a metodologia](docs/methodology.md) e [o modelo de relatório](docs/report-template.md).

## Autorização e limites

- Avalie somente ativos e janelas cobertos por autorização formal do proprietário.
- O operador deve registrar a referência da autorização e configurar explicitamente os hostnames permitidos em `SENTINELA_ALLOWED_HOSTS`.
- O scanner fica desabilitado por padrão; `SENTINELA_ENABLE_SCANNER=1` habilita a execução somente para os hostnames da lista.
- Apenas URLs HTTPS com hostname DNS público são aceitas. IPs literais, redes privadas, loopback e portas alternativas são bloqueados.
- Não há exploração, autenticação forçada, varredura de portas, crawling, escrita no alvo ou persistência de corpos de resposta.
- A conexão usa o endereço IP validado na resolução DNS (sem nova consulta), o que impede DNS rebinding; apenas status e cabeçalhos são lidos, com limite de 16 KB, e o corpo nunca é baixado.
- O protótipo ainda não tem autenticação de operador nem persistência confiável. Não o exponha na internet nem use dados reais de clientes até concluir esses controles.

## Fluxo previsto para a consultoria

1. Registrar cliente, responsável, autorização, janela, domínios e limitações do teste.
2. Revisar o escopo e ativar somente os hostnames aprovados.
3. Executar verificações de baixo impacto e registrar horário, método e evidência mínima.
4. Revisar manualmente cada achado, impacto e severidade; evitar classificar ausência de header como falha explorável por si só.
5. Entregar relatório executivo e técnico por cliente, com riscos, recomendações e plano de correção.
6. Reavaliar após as correções e registrar a mudança de status.

## Executar o protótipo

Requisitos: Node.js 20+ e npm. Após obter o código do GitHub:

```powershell
npm ci
npm run dev
```

Verificações de qualidade (as mesmas executadas no CI):

```powershell
npm run lint
npm run typecheck
npm test
npm run build
```

Abra http://localhost:3000. Os ativos novos só ficam aptos à avaliação quando o hostname consta na lista do operador e a autorização é confirmada no cadastro. Os dados e indicadores iniciais são apenas demonstrativos.

## Próximos marcos

O roadmap enterprise completo (multi-tenancy, RBAC, SSO, observabilidade e deploy) está em evolução; os marcos abaixo resumem a ordem.

1. Autenticação de operador e armazenamento seguro de clientes, autorizações, avaliações e relatórios.
2. Auditoria de execução e autorizações com janela de validade no banco.
3. Verificações TLS, inventário passivo de tecnologias e conectores cloud read-only.
4. Relatórios PDF/XLSX, revisão de achados e histórico de reavaliações.
5. Deploy privado e controle de acesso para uso individual.

## Licença

Uso interno e autorizado. Defina uma licença antes de distribuir o produto.
