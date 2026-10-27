# Deploy no Oracle Cloud (Always Free)

Este guia sobe o Sentinela numa VM gratuita da Oracle Cloud (Ampere A1, ARM) com Docker Compose. A pilha tem quatro serviços: PostgreSQL, a aplicação, o Caddy (HTTPS automático com Let's Encrypt) e um backup diário do banco. O mesmo procedimento vale para qualquer VM Linux com Docker.

## 1. Criar a VM

1. No console da OCI: **Compute → Instances → Create instance**.
2. Imagem **Canonical Ubuntu 24.04**; shape **VM.Standard.A1.Flex** (Ampere). 2 OCPUs e 12 GB de RAM sobram para o Sentinela e ficam dentro do Always Free (limite de 4 OCPUs e 24 GB somando todas as VMs A1).
3. Em **Add SSH keys**, envie sua chave pública.
4. Depois de criada, anote o **IP público**.

Se aparecer "Out of capacity", tente outro *availability domain* ou repita mais tarde: é comum na camada gratuita.

## 2. Liberar as portas 80 e 443

São duas camadas de firewall:

- **Na OCI:** em *Networking → Virtual Cloud Networks → (sua VCN) → Security Lists → Default*, adicione *Ingress Rules* TCP para as portas 80 e 443 com origem `0.0.0.0/0`. Para restringir o acesso a um escritório ou VPN, use o IP/CIDR deles em vez de `0.0.0.0/0`.
- **Na VM:** as imagens Ubuntu da Oracle vêm com regras de iptables que bloqueiam tudo além do SSH:

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 443 -j ACCEPT
sudo netfilter-persistent save
```

## 3. Instalar o Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
```

## 4. Domínio

- **Com domínio próprio:** crie um registro DNS `A` apontando, por exemplo, `sentinela.suaempresa.com.br` para o IP público.
- **Sem domínio:** use o IP com sslip.io, por exemplo `129-146-10-20.sslip.io` para o IP `129.146.10.20`. Isso já gera um certificado HTTPS válido.

## 5. Configurar e subir

```bash
git clone https://github.com/devspagnuolo/sentinela-security-platform.git
cd sentinela-security-platform/deploy
cp .env.example .env
nano .env   # SENTINELA_DOMAIN, ACME_EMAIL, POSTGRES_PASSWORD, SENTINELA_ENCRYPTION_KEY
docker compose -f docker-compose.prod.yml up -d --build
```

Para gerar os segredos, use `openssl rand -base64 24` (senha do banco) e `openssl rand -base64 32` (chave de criptografia). O primeiro build na VM ARM leva alguns minutos. As migrações do banco são aplicadas automaticamente quando a aplicação inicia.

Para conferir:

```bash
docker compose -f docker-compose.prod.yml ps        # app e postgres "healthy"
curl https://SEU_DOMINIO/api/health?ready=1          # {"status":"ok","database":"ok"}
```

## 6. Criar o primeiro usuário (Owner)

```bash
docker compose -f docker-compose.prod.yml run --rm tools npm run user:create-owner -- voce@suaempresa.com.br "Seu Nome"
```

Sem `SENTINELA_OWNER_PASSWORD`, uma senha forte é gerada e exibida uma única vez. Depois do login:

1. Ative a verificação em duas etapas em **Minha conta**.
2. Se quiser, configure o SSO.
3. Crie os demais usuários.

## Backups

O serviço `backup` faz um `pg_dump` ao iniciar e depois uma vez por dia em `deploy/backups/`, mantendo `BACKUP_RETENTION_DAYS` dias.

- **Cópia fora da VM:** copie os backups para outro lugar, como o OCI Object Storage (o Always Free inclui 20 GB), outro servidor ou sua máquina.
- **Chave de criptografia:** guarde a `SENTINELA_ENCRYPTION_KEY` junto com os backups. Sem ela, os segredos de MFA e SSO restaurados não podem ser lidos.

Backup manual e restauração:

```bash
docker compose -f docker-compose.prod.yml exec backup backup.sh once
docker compose -f docker-compose.prod.yml stop app
docker compose -f docker-compose.prod.yml exec backup pg_restore --clean --if-exists -d sentinela /backups/sentinela-AAAAMMDDTHHMMSSZ.dump
docker compose -f docker-compose.prod.yml start app
```

## Atualizar

```bash
cd sentinela-security-platform && git pull
cd deploy && docker compose -f docker-compose.prod.yml up -d --build
```

## Logs e operação

- Logs estruturados em JSON: `docker compose -f docker-compose.prod.yml logs -f app`. Com rotação de 5 arquivos de 10 MB.
- `/api/health` responde sem login e serve para monitores externos, como o UptimeRobot. Com `?ready=1`, também verifica o banco.
- O banco não expõe porta para fora da rede interna do compose. A aplicação roda como usuário sem privilégios, com sistema de arquivos somente leitura.
- Para restringir o acesso por IP também no proxy, descomente o bloco `remote_ip` do `deploy/Caddyfile` e rode `docker compose -f docker-compose.prod.yml restart caddy`.
