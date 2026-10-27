# Arquitetura e limites do produto

## MVP implementado

Next.js entrega uma UI de painel e rotas API locais para inventário, execução de avaliação e exportação JSON/CSV. O scanner realiza uma única requisição HTTPS GET ao host cadastrado, sem seguir redirecionamentos. Avalia status da resposta, headers defensivos, política CORS observada, atributos de cookies, headers de resposta e alguns atributos de cookies. A evidência é limitada a valores de headers e metadados; o corpo não é persistido.

## Arquitetura SaaS proposta

```text
Next.js (web) -> NestJS API -> PostgreSQL
                           -> RabbitMQ -> workers isolados de assessment
                           -> Redis (limites/cache efêmero)
OIDC/MFA -> gateway de identidade; logs de auditoria -> armazenamento append-only
```

Cada entidade de negócio deve carregar `tenant_id`; políticas PostgreSQL RLS e autorização no serviço devem aplicar isolamento. Workers recebem somente alvos aprovados e capacidades allowlisted, sem credenciais por padrão. Para cloud, adotar papéis read-only e federação temporária, nunca chaves estáticas. Segredos ficam em secret manager; Terraform e Kubernetes devem aplicar rede de saída restrita e limites de recursos.

## Autorização e segurança do scanner

- Consentimento formal é um requisito de negócio para habilitar qualquer ativo.
- Aprovação registra responsável, escopo exato, janela, data de expiração e limites.
- Bloquear por padrão IPs privados, loopback, link-local, multicast e esquemas que não sejam HTTPS.
- Resolver DNS e validar todos os endereços antes da conexão; proteger contra DNS rebinding e redirects para fora do escopo.
- Aplicar quotas por tenant, concorrência baixa, timeout, tamanho máximo de resposta e kill switch.
- Auditar criação/aprovação do escopo, execução, cancelamento, acesso a evidências e exportações.
- Não armazenar tokens, cookies completos, corpos contendo dados pessoais ou segredos encontrados.

## Taxonomia

Achados devem manter referências versionadas a CVSS, CWE, OWASP Top 10, MITRE ATT&CK (quando aplicável) e CIS Controls. ATT&CK/CIS são contexto de mapeamento, não pontuação automática. Recomendações geradas por IA precisam apontar evidência e referência, com revisão humana; nunca enviar dados sensíveis a modelos sem política explícita.

## Fora do MVP

Autenticação corporativa real, multi-tenancy, descoberta recursiva de subdomínios, port scanning, crawling, testes autenticados, cloud connectors, RabbitMQ workers, PDF/XLSX, compliance automatizado e uso de IA. Esses componentes exigem projeto de segurança, controles de autorização e testes próprios antes de produção.
