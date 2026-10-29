# API e webhooks

O Sentinela expõe a mesma API HTTP usada pela interface. Integrações (CI/CD, SIEM, abertura de chamados, scripts) autenticam com **tokens de API** e recebem eventos por **webhooks** assinados.

## Tokens de API

Cada pessoa cria os próprios tokens em **Minha conta → Tokens de API**:

- O token age em nome de quem o criou. A auditoria registra a ação com `via: "api_token"` e o id do token.
- O papel do token é **Leitor** ou **Analista**, nunca acima do papel da pessoa. Se a pessoa for rebaixada, o token passa a valer com o papel menor. Se for desativada, os tokens são revogados.
- A validade é de 7, 30, 90 ou 365 dias. Cada pessoa pode ter até 20 tokens ativos.
- O valor (`snt_…`) aparece uma única vez, na criação. O banco guarda só o SHA-256.
- Admins e Owners veem e revogam os tokens de toda a organização em **Integrações**.
- Se a organização exige verificação em duas etapas, só funcionam tokens de quem já a cadastrou.

Envie o token no cabeçalho `Authorization`:

```sh
curl -H "Authorization: Bearer $SENTINELA_TOKEN" https://sentinela.suaempresa.com.br/api/findings?status=open
```

Requisições com token não usam cookie, então não precisam do cabeçalho `Origin`. Token inválido, vencido ou revogado recebe `401`. Uma rota que não aceita token recebe `403`.

### Rotas que aceitam token

| Método e rota | Papel mínimo | Uso |
|---|---|---|
| `GET /api/auth/me` | Leitor | Confere a identidade e o papel efetivo do token |
| `GET /api/assets` | Leitor | Ativos com situação do escopo e última avaliação |
| `POST /api/assets` | Analista | Cadastra ativo sob um escopo aprovado |
| `PUT /api/assets/:id/schedule` | Analista | Reavaliação periódica: `{"intervalDays": 0 \| 1 \| 7 \| 30}` |
| `POST /api/assets/:id/assess` | Analista | Enfileira uma avaliação (`202`); acompanhe em `GET /api/assessments/:id` |
| `GET /api/assessments?assetId=&limit=` | Leitor | Histórico de execuções |
| `GET /api/assessments/:id` | Leitor | Uma execução (situação, resumo, achados observados) |
| `GET /api/scopes` | Leitor | Autorizações de escopo |
| `POST /api/scopes` | Analista | Cadastra autorização (nasce pendente; aprovar exige uma pessoa) |
| `GET /api/findings?status=open,accepted&assetId=` | Leitor | Achados |
| `PATCH /api/findings/:id` | Analista | Triagem: `open`, `fixed` ou `false_positive` (com `reason`) |
| `GET /api/findings/:id/events` | Leitor | Histórico de triagem |
| `GET /api/technologies?assetId=&includeStale=1` | Leitor | Inventário passivo de tecnologias (por padrão, só o que apareceu na última avaliação de cada ativo) |
| `GET /api/reports/:assetId?format=json\|html\|pdf` | Leitor | Relatório da última avaliação |
| `GET /api/export?format=json\|csv\|xlsx` | Analista | Exportação de achados |

As demais rotas (conta, MFA, usuários, organização, SSO, auditoria, notificações, tokens e webhooks) exigem uma pessoa logada na interface. As decisões de gestão também ficam fora do alcance dos tokens: aprovar ou revogar escopo, aceitar risco e administrar usuários.

### Exemplo: falhar o pipeline com achado crítico

```sh
open=$(curl -fsS -H "Authorization: Bearer $SENTINELA_TOKEN" "$SENTINELA_URL/api/findings?status=open")
if echo "$open" | jq -e 'any(.[]; .severity == "critical")' >/dev/null; then
  echo "Há achados críticos abertos no Sentinela"; exit 1
fi
```

## Webhooks

Admins e Owners cadastram webhooks em **Integrações**, com a URL HTTPS e os eventos que querem receber. Ao cadastrar, ou ao trocar o segredo, o Sentinela mostra uma única vez o **segredo de assinatura** (`whsec_…`). O botão **Testar** envia um `webhook.test` e mostra o resultado na hora.

### Eventos

| Evento | Quando |
|---|---|
| `assessment.completed` | Avaliação concluída. Traz o resumo e os achados novos (até 100). |
| `assessment.failed` | Avaliação não concluída: escopo bloqueado, erro do alvo ou tentativas esgotadas. |
| `finding.status_changed` | Triagem manual de um achado. |
| `finding.acceptance_expired` | Aceites de risco venceram e os achados voltaram a aberto. |
| `scope.pending` | Escopo cadastrado, aguardando aprovação. |
| `scope.approved` | Escopo aprovado. |
| `scope.revoked` | Escopo revogado, com o motivo. |
| `scope.expiring` | Escopo vence em até 14 dias. É enviado uma vez por autorização. |
| `webhook.test` | Só pelo botão **Testar**. |

### Formato

O corpo é sempre JSON. Exemplo:

```json
{
  "id": "6f1c…",
  "type": "assessment.completed",
  "createdAt": "2026-10-27T18:04:11.000Z",
  "organizationId": "1a2b…",
  "data": {
    "asset": { "id": "…", "name": "Portal", "url": "https://portal.cliente.com.br" },
    "assessment": { "id": "…", "trigger": "scheduled", "method": "SENTINELA-WEB-003", "summary": { "observed": 7, "created": 1, "reopened": 0, "resolved": 2 }, "link": "https://sentinela.suaempresa.com.br/avaliacoes" },
    "newFindings": [{ "id": "…", "title": "Certificado TLS perto do vencimento", "severity": "medium", "category": "TLS" }]
  }
}
```

Os links usam a primeira origem de `SENTINELA_PUBLIC_ORIGIN`; sem ela, vêm `null`. Os eventos de escopo não incluem o contato de emergência nem as observações internas.

Cada entrega também traz estes cabeçalhos:

- `Sentinela-Event`: o tipo do evento.
- `Sentinela-Event-Id`: o mesmo `id` do corpo. É igual para todos os webhooks e todas as tentativas, então use-o para descartar duplicatas.
- `Sentinela-Delivery`: o id da entrega para este webhook.
- `Sentinela-Signature`: `t=<unix>,v1=<hex>`, com `v1 = HMAC-SHA256(segredo, "<t>.<corpo>")`.

### Validar a assinatura

Calcule o HMAC sobre o corpo **bruto**, antes de qualquer parse. Compare em tempo constante e recuse timestamps com mais de 5 minutos.

Node.js:

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function isFromSentinela(secret, rawBody, header, toleranceSeconds = 300) {
  const parts = Object.fromEntries(header.split(",").map(p => p.split("=", 2)));
  const t = Number(parts.t);
  if (!t || Math.abs(Date.now() / 1000 - t) > toleranceSeconds) return false;
  const expected = createHmac("sha256", secret).update(`${t}.${rawBody}`).digest();
  const given = Buffer.from(parts.v1 ?? "", "hex");
  return given.length === expected.length && timingSafeEqual(given, expected);
}
```

Python:

```python
import hashlib, hmac, time

def is_from_sentinela(secret: str, raw_body: bytes, header: str, tolerance: int = 300) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    t = int(parts.get("t", "0"))
    if abs(time.time() - t) > tolerance:
        return False
    expected = hmac.new(secret.encode(), f"{t}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))
```

### Entrega, novas tentativas e desligamento

- Uma resposta `2xx` em até 10 segundos conta como entregue. O corpo da resposta não é lido e redirecionamentos não são seguidos.
- Qualquer outra resposta, ou falha de rede, é tentada de novo depois de 1 min, 5 min, 30 min, 2 h e 12 h. São 6 tentativas no total. Depois disso a entrega fica como **falhou**.
- Depois de 5 entregas seguidas que falharam, o webhook é **desligado**, e Admins e Owners recebem um aviso. Para religar, use **Integrações**. Religar zera o contador.
- O histórico das entregas fica em **Integrações → Entregas** por 30 dias.
- Os eventos entram numa fila no PostgreSQL (`webhook_deliveries`), que o mesmo worker das avaliações processa. Quem gera o evento nunca espera a rede.

### Destinos permitidos

A URL precisa ser HTTPS, com certificado válido e sem usuário e senha. O DNS é resolvido uma vez por envio, e a conexão vai ao endereço validado. Por padrão, só endereços públicos são aceitos, o que impede que um webhook seja usado para alcançar serviços internos da rede do servidor (SSRF). Se você precisa entregar a um coletor na rede interna, o operador pode liberar com `SENTINELA_WEBHOOK_ALLOW_PRIVATE=1`.

## Avisos por e-mail

Os avisos do sino também podem ser enviados por e-mail, por SMTP. Isso vale para achados altos ou críticos novos ou reabertos, avaliações não concluídas, escopos pendentes ou vencendo, aceites de risco vencidos e webhooks desligados. O operador configura no servidor:

```sh
SENTINELA_SMTP_URL=smtps://usuario:senha@smtp.provedor.com:465   # ou smtp://…:587, com STARTTLS obrigatório
SENTINELA_MAIL_FROM="Sentinela <alertas@suaempresa.com.br>"
```

Codifique caracteres especiais do usuário e da senha na URL (ex.: `@` vira `%40`). Sem essas variáveis, nada é enviado. Com `smtp://`, o servidor precisa aceitar STARTTLS; para um relay local sem TLS, use `SENTINELA_SMTP_ALLOW_PLAIN=1`.

- Cada pessoa liga ou desliga os e-mails em **Minha conta**. Por padrão, recebe.
- Os e-mails entram numa fila e são enviados pelo worker. Se o envio falhar, há novas tentativas depois de 1, 10 e 60 minutos.
- Se a pessoa desativar a preferência ou for desativada antes do envio, o e-mail não sai.
- Em **Integrações**, Admins e Owners veem o remetente e o servidor configurados (sem a senha) e podem mandar um e-mail de teste para si.

