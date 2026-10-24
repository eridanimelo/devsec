# DevSec Lab — SonarQube + Dependency-Track + OWASP ZAP

Laboratório local (Docker Compose) com as três ferramentas de segurança usadas no dia a dia:

| Serviço | Função | URL padrão | Credenciais iniciais |
|---|---|---|---|
| **SonarQube** (Community 26.10) | SAST / qualidade de código | http://localhost:9000 | `admin` / `admin` |
| **Dependency-Track** (frontend) | SCA / análise de SBOM | http://localhost:9080 | `admin` / `admin` |
| **Dependency-Track** (API) | API usada pelo frontend e pelo CI | http://localhost:9081 | — |
| **OWASP ZAP** (daemon) | DAST / scan de APIs | http://localhost:9082 | API key em `.env` |

> ⚠️ Use apenas em ambiente local/laboratório. Troque as senhas do `.env`, e só faça scan em alvos que você tem autorização para testar.

Versões validadas: **SonarQube 26.10.0 Community**, **Dependency-Track 4.14.5** e **ZAP 2.17.0**.

---

## 1. Pré-requisitos

- Docker + Docker Compose v2 (`docker compose version`)
- ~8 GB de RAM livres (SonarQube ~2 GB + Dependency-Track ~2 GB + ZAP ~1 GB)
- Portas livres: `9000`, `9080`, `9081`, `9082` (configuráveis no `.env`)

## 2. Subindo a stack

```bash
cp .env.example .env     # edite as senhas/chaves
docker compose up -d
docker compose ps
```

A primeira subida demora alguns minutos:

- **SonarQube**: 1–3 min (migração do banco + Elasticsearch)
- **Dependency-Track**: 2–5 min (migração do banco)
- **ZAP**: segundos

Acompanhe com `make logs` (ou `docker compose logs -f sonarqube`).

Para parar sem apagar dados: `make down`. Para apagar **tudo** (volumes): `make reset`.

---

## 3. SonarQube — como adicionar um projeto

### 3.1 Pela interface (primeira vez)

1. Acesse http://localhost:9000 e entre com `admin` / `admin`.
2. Troque a senha quando solicitado.
3. Vá em **Projects → Create Project → Manually**.
4. Informe:
   - **Project display name**: nome amigável (ex.: `Minha API`)
   - **Project key**: identificador único, sem espaços (ex.: `minha-api`)
   - **Main branch**: `main`
5. Clique em **Create**.
6. Na tela seguinte, escolha **Locally** (ou **With GitHub Actions**, se for o caso) e clique em **Generate a token**.
7. Copie o token **na hora** — ele não é exibido novamente. Guarde como `SONAR_TOKEN`.

### 3.2 Rodando a análise

Opção A — script deste repositório (recomendado para testes):

```bash
export SONAR_TOKEN=<token-gerado>
./scans/sonar-scan.sh /caminho/do/projeto minha-api
```

O script monta o projeto no container oficial `sonarsource/sonar-scanner-cli` e usa
`http://host.docker.internal:9000` como servidor.

Opção B — `sonar-project.properties` na raiz do projeto (veja `examples/sonar-project.properties`):

```properties
sonar.projectKey=minha-api
sonar.projectName=Minha API
sonar.projectVersion=1.0.0
sonar.sources=src
sonar.tests=test
sonar.sourceEncoding=UTF-8
sonar.exclusions=**/node_modules/**,**/dist/**,**/build/**
```

E execute:

```bash
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e SONAR_HOST_URL=http://host.docker.internal:9000 \
  -e SONAR_TOKEN=$SONAR_TOKEN \
  -v "$PWD:/usr/src" -w /usr/src \
  sonarsource/sonar-scanner-cli:latest
```

> O `projectKey` do arquivo precisa ser **igual** ao configurado no SonarQube, senão um novo projeto é criado.

### 3.3 No CI (exemplo)

```yaml
- uses: SonarSource/sonarqube-scan-action@v5
  env:
    SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

O resultado aparece em **Projects → seu projeto → Issues** (bugs, vulnerabilidades, code smells, cobertura e duplicação).

---

## 4. Dependency-Track — como adicionar um projeto

O Dependency-Track **não analisa o código**: ele recebe um **SBOM** (CycloneDX ou SPDX) e cruza os componentes com bases de vulnerabilidade (NVD, OSS Index, GitHub Advisories etc.).

### 4.1 Criando o projeto

1. Acesse http://localhost:9080 e entre com `admin` / `admin`.
2. Troque a senha quando solicitado.
3. Vá em **Projects → Create Project**.
4. Preencha:
   - **Project Name**: ex.: `minha-api`
   - **Version**: ex.: `1.0.0` (obrigatório — cada versão é um projeto separado)
   - **Classifier**: `APPLICATION` para sua aplicação, `LIBRARY` para bibliotecas
   - **Tags**: opcional (ex.: `producao`, `pagamentos`)
5. Clique em **Create**.

### 4.2 Criando a API key

1. **Administration → Access Management → Teams**.
2. Selecione o time (ex.: `Automation`) ou crie um novo.
3. Aba **API Keys → +** (Create API Key).
4. Dê um nome (ex.: `ci-upload`) e copie a chave. Guarde como `DTRACK_API_KEY`.
   A chave é exibida **uma única vez** (a partir da 4.13 ela é armazenada com hash).

> A API key herda as permissões do time. Para CI, mantenha o time apenas com acesso de upload.

### 4.3 Gerando o SBOM

Com o script deste repositório (usa Syft):

```bash
./scans/generate-sbom.sh /caminho/do/projeto minha-api
# saída: reports/sbom/minha-api.cdx.json
```

Ou direto pela stack do projeto:

```bash
# Node.js
npx @cyclonedx/cyclonedx-npm --output-file bom.json

# Maven (Java)
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom

# Python
cyclonedx-py environment -o bom.json

# Imagem Docker
./scans/generate-sbom.sh minha-imagem:1.0.0
```

### 4.4 Enviando o SBOM

Pela interface: **Projects → seu projeto → Components → Upload BOM** e selecione o arquivo.

Pela API (script):

```bash
export DTRACK_API_KEY=<chave>
./scans/dtrack-upload.sh reports/sbom/minha-api.cdx.json minha-api 1.0.0
```

Ou com `curl`:

```bash
curl -X POST http://localhost:9081/api/v1/bom \
  -H "X-Api-Key: $DTRACK_API_KEY" \
  -F "projectName=minha-api" \
  -F "projectVersion=1.0.0" \
  -F "autoCreate=true" \
  -F "bom=@bom.json"
```

O `autoCreate=true` cria o projeto/versão se ele não existir. O processamento é **assíncrono**;
acompanhe em **Projects → seu projeto → Components/Vulnerabilities**.

> **Primeira sincronização:** o Dependency-Track baixa o espelho da NVD, o que pode levar
> horas (ou dias, dependendo da rede). Vulnerabilidades só aparecem depois dessa carga.
> Acompanhe em **Administration → System → NVD Mirror** (ou pelos logs do apiserver).

---

## 5. OWASP ZAP — como adicionar um alvo

O container sobe em modo **daemon** (sem interface gráfica), com a API em http://localhost:9082.
Para explorar manualmente, use o **ZAP Desktop** no seu computador, ou execute
`docker exec -it devsec-zap zap-webswing.sh` (interface via navegador).

### 5.1 Scan passivo (baseline)

```bash
./scans/zap-baseline.sh https://minha-app.local minha-app
# relatórios: reports/zap/minha-app.{html,json,md}
```

O baseline **não ataca**: apenas navega e analisa passivamente. É seguro para rodar em CI.

### 5.2 Scan ativo (full)

```bash
./scans/zap-full-scan.sh https://minha-app.local minha-app
```

> Envia payloads de ataque. Use apenas em ambiente de teste/homologação com autorização.

### 5.3 Scan de API a partir de OpenAPI

```bash
./scans/zap-api-scan.sh https://minha-api.local ./openapi.json minha-api
```

### 5.4 Autenticação (resumido)

Para varrer áreas logadas, crie um **contexto** com o mecanismo de autenticação
(form-based, JSON, JWT etc.) e passe para o scan:

```bash
docker run --rm -v "$PWD/reports/zap:/zap/wrk:rw" -v "$PWD:/ctx:ro" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://minha-app.local -n /ctx/contexto.context \
  -U usuario -r autenticado.html
```

Referência: https://www.zaproxy.org/docs/docker/

### 5.5 No CI (exemplo)

```yaml
- uses: zaproxy/action-baseline@v0.14.0
  with:
    target: ${{ vars.STAGING_URL }}
    fail_action: false
```

---

## 6. Comandos úteis

```bash
make up            # sobe a stack
make down          # para (mantém dados)
make reset         # apaga volumes e sobe do zero
make ps            # status
make logs          # logs de todos
make sonar-logs    # logs do SonarQube
make dtrack-logs   # logs do Dependency-Track
make zap-logs      # logs do ZAP
```

Backup dos dados (exemplo):

```bash
docker run --rm -v devsec_sonarqube-data:/from -v "$PWD/backup:/to" alpine \
  tar czf /to/sonarqube-data.tgz -C /from .
```

Trocar portas: edite `SONAR_PORT`, `DTRACK_WEB_PORT`, `DTRACK_API_PORT` e `ZAP_PORT` no `.env`.
Se mudar `DTRACK_API_PORT`, ajuste também `DTRACK_API_BASE_URL` (é a URL que o **navegador** usa).

---

## 7. Solução de problemas

| Sintoma | Causa / solução |
|---|---|
| SonarQube reinicia em loop no Linux | `sudo sysctl -w vm.max_map_count=524288` (Docker Desktop já configura) |
| Containers morrem por falta de memória | Feche outros apps ou aumente a RAM do Docker Desktop (≥ 8 GB) |
| `port is already allocated` | Outra aplicação usa a porta; altere no `.env` |
| Frontend do Dependency-Track mostra erro de API | `DTRACK_API_BASE_URL` precisa ser acessível pelo navegador (ex.: `http://localhost:9081`) |
| Vulnerabilidades não aparecem no Dependency-Track | A sincronização inicial da NVD ainda não terminou. Opcionalmente configure uma API key da NVD em **Administration** para acelerar (sem ela o rate limit é agressivo) |
| ZAP retorna `400 Bad Request` | Use a API key do `.env`; a API exige `apikey` em todas as chamadas |
| ZAP retorna erro de conexão na API | A porta interna e a externa do ZAP precisam ser iguais (o compose já sincroniza via `ZAP_PORT`) |
| Token do SonarQube inválido | Gere outro em **My Account → Security**; tokens expiram se configurado |
| Mudou senha no `.env` e o banco não conecta | O volume já foi criado com a senha antiga: `make reset` |

---

## 8. Estrutura do repositório

```
.
├── docker-compose.yml              # SonarQube, Dependency-Track e ZAP
├── .env.example                    # variáveis (copie para .env)
├── Makefile                        # atalhos
├── examples/
│   ├── sonar-project.properties    # exemplo de config do scanner
│   └── github-actions.yml          # exemplo de pipeline CI
├── scans/
│   ├── sonar-scan.sh               # análise SAST
│   ├── generate-sbom.sh            # gera SBOM com Syft
│   ├── dtrack-upload.sh            # envia SBOM ao Dependency-Track
│   ├── zap-baseline.sh             # DAST passivo
│   ├── zap-full-scan.sh            # DAST ativo
│   └── zap-api-scan.sh             # DAST em API via OpenAPI
└── reports/                        # relatórios gerados (ignorado no git)
```
# devsec
