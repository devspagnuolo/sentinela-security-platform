# Conectores de nuvem (somente leitura)

Os conectores leem as zonas DNS da organização no provedor e listam os hostnames que existem lá. Eles servem para responder uma pergunta: **há algo publicado que ainda não está no escopo?** A descoberta só informa. Um hostname encontrado não é avaliado automaticamente; ele só pode ser avaliado depois de cadastrado como ativo sob um escopo aprovado, como qualquer outro, e respeitando `SENTINELA_ALLOWED_HOSTS`.

Admins e Owners cadastram conectores em **Integrações → Conectores de nuvem**. Os hostnames aparecem em **Descoberta pela nuvem**.

## Provedores

| Provedor | O que é lido |
|---|---|
| Cloudflare (DNS) | Zonas ativas e registros A, AAAA e CNAME |
| AWS Route 53 | Zonas públicas e registros A, AAAA, CNAME e ALIAS. Zonas privadas são ignoradas |

Limites por sincronização: 200 zonas e 5.000 hostnames. Curingas (`*.exemplo.com`) não viram hostname.

## Permissões mínimas

Use uma credencial só para o Sentinela, com nada além disto.

### Cloudflare

Crie um **API Token** (não use a Global API Key) em *My Profile → API Tokens → Create Token → Custom token* com:

- **Zone → Zone → Read**
- **Zone → DNS → Read**
- *Zone Resources*: as zonas que fazem parte do contrato, ou todas da conta.

Se quiser, restrinja o token ao IP público da instalação em *Client IP Address Filtering*.

### AWS Route 53

Crie um usuário IAM só com chave de acesso programática e esta política:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["route53:ListHostedZones", "route53:ListResourceRecordSets"],
      "Resource": "*"
    }
  ]
}
```

Para limitar a zonas específicas, troque o `Resource` de `ListResourceRecordSets` por `arn:aws:route53:::hostedzone/<ID>` (o `ListHostedZones` continua precisando de `*`).

## Como funciona

- **Somente leitura.** O Sentinela faz apenas requisições `GET`, e só para `api.cloudflare.com` e `route53.amazonaws.com` por HTTPS, sem seguir redirecionamentos. Nenhuma chamada altera nada no provedor.
- **Credenciais cifradas** com AES-256-GCM (`SENTINELA_ENCRYPTION_KEY`). A interface mostra só uma dica (os últimos caracteres) e nunca devolve a credencial.
- **Validação no cadastro.** Ao cadastrar ou trocar a credencial, o Sentinela sincroniza na hora. Se o provedor recusar, o conector não é salvo e a mensagem explica qual permissão falta.
- **Sincronização diária.** O worker sincroniza cada conector ligado a cada 24 horas. O botão **Sincronizar** faz isso na hora.
- **Hostnames que somem** deixam de aparecer na lista (podem ser vistos com `?includeStale=1`) e são apagados 90 dias depois da última vez em que foram vistos.

Cada hostname recebe uma situação:

| Situação | Significado |
|---|---|
| Já é ativo | Existe um ativo com esse hostname |
| Coberto por escopo | Um escopo aprovado e vigente cobre o hostname. Quem tem papel Analista pode cadastrá-lo como ativo |
| Fora de escopo | Nenhum escopo vigente cobre. Confirme com o cliente antes de incluir no contrato |
| Interno | Só aponta para IPs privados |

Lembre que um escopo `*.exemplo.com` não cobre o próprio `exemplo.com`.

## Avisos e eventos

- Hostnames **novos e fora de escopo** geram um aviso para Admins e Owners.
- Uma falha de sincronização gera um aviso na primeira vez. Falhas seguidas não repetem o aviso.
- Hostnames novos disparam o webhook `discovery.hosts_found` (veja [api.md](api.md)).
- Cadastro, alteração, remoção e sincronização manual ficam na auditoria (categoria *Conectores de nuvem*).
