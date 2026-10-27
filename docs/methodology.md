# Método SENTINELA-WEB-002

Versão anterior: SENTINELA-HTTP-001 (somente cabeçalhos HTTP). O relatório informa a versão usada em cada execução.

## Pré-condições

O avaliador confirma autorização formal do proprietário, hostnames exatos, janela, exclusões e contato de emergência. O teste deve ser interrompido se qualquer condição deixar de ser válida. Ativos fora do escopo não são inferidos a partir de links ou redirecionamentos.

## Técnica implementada no protótipo

1. Validar URL HTTPS e hostname DNS público.
2. Conferir o hostname na lista explícita de alvos permitidos pelo operador.
3. Enviar uma requisição GET à URL raiz conectando ao IP validado no passo 1 (sem nova resolução DNS), com User-Agent identificável, timeout de 5 segundos, sem seguir redirecionamentos e encerrando a conexão após os cabeçalhos.
4. Observar cabeçalhos de resposta: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Access-Control-Allow-Origin, Set-Cookie, Server e X-Powered-By.
5. Na mesma conexão do passo 3, ler o certificado apresentado: se a cadeia é confiável e cobre o hostname, o emissor, o protocolo negociado e a data de vencimento. Um certificado inválido não interrompe a coleta; ele é registrado como achado. Nenhuma conexão adicional é aberta e não há enumeração de cifras ou versões.
6. Consultar o resolvedor DNS (nunca o alvo) por registros públicos. O CAA é buscado no hostname e nos domínios acima (RFC 8659). No primeiro domínio acima com MX, verificar SPF e DMARC. As verificações DNS só são feitas se o resolvedor responder registros NS em algum nível; erros e tempo limite omitem a verificação, sem acusar ausência.
7. Registrar apenas metadados necessários à evidência. Valores de cookies e corpo da resposta não entram no relatório.
8. Revisar manualmente se o indicador representa risco real para o contexto do cliente.

O método não descobre endpoints, não testa autenticação ou autorização, não executa payloads, não acessa diretórios e não confirma CVEs. A identificação de tecnologias por banners é indicativa: pode estar ausente, desatualizada ou deliberadamente alterada.

## Classificação

A severidade automática é preliminar. O relatório entregue ao cliente deve incluir justificativa contextual: exposição, probabilidade, impacto, dados afetados, controles compensatórios e possibilidade de exploração. Se a evidência não sustenta uma conclusão, classificar como observação ou solicitar validação adicional autorizada.

## Limitações técnicas atuais

A conexão é fixada no endereço validado e somente cabeçalhos (até 16 KB) são lidos; o corpo não é baixado. Ainda não há controle de taxa por cliente nem trilha de auditoria persistente. Por isso, o scanner permanece desabilitado por padrão e o protótipo não deve ser usado em produção.
