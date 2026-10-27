# Arquitetura para uso individual

## Objetivo

Sentinela é uma estação de trabalho privada para um consultor de segurança. Cada projeto pertence a um cliente e guarda escopo autorizado, janelas de análise, contatos, ativos, execuções, achados revisados e relatórios. Multiempresa significa separação de projetos e dados, não um SaaS compartilhado nem gestão de usuários de clientes.

## Estado implementado

A interface Next.js e suas rotas API usam memória do processo para demonstração. O scanner faz uma requisição HTTPS GET para a URL raiz, sem redirecionamento, com timeout de 5 segundos, conectando ao endereço IP validado (DNS fixado) e lendo somente status e cabeçalhos. Verifica alguns cabeçalhos defensivos, política CORS observada, atributos de cookies e banner Server. O corpo da resposta não é persistido. O relatório por ativo apresenta método, evidências mínimas, limitações e recomendações em JSON ou HTML imprimível.

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

Sem autenticação, persistência, aprovação com validade, varredura TLS, descoberta ampla, testes autenticados, cloud, PDF gerado no servidor ou IA. O protótipo não deve receber dados reais de clientes nem ser exposto publicamente até que os controles essenciais estejam implementados.
