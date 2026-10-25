# Automação de segurança — `devsec`

Pipeline local que recebe **paths de código + URL de acesso + credenciais de
teste** e devolve um relatório único, normalizado e reproduzível.

```text
perfil (.env)
   │
   ├── bin/devsec scan
   │      ├── preflight (paths, alvo, autorização)
   │      ├── stack    (Docker Compose + healthcheck)
   │      ├── sast     (Semgrep + SonarQube)
   │      ├── sca      (Syft + Grype + Dependency-Track)
   │      ├── secrets  (Gitleaks)
   │      └── dast     (ZAP: baseline, autenticado, API, ativo)
   │
   └── reports/runs/<run-id>/
          ├── report.html     ← humano
          ├── findings.json   ← máquina
          ├── summary.json    ← gate + delta
          └── context.md      ← IA (achernar_ia)
```

O CLI é **determinístico**: não usa LLM, não decide prioridade e não corrige
nada. A camada de IA (`achernar_ia`, intenção `APPSEC`) lê os artefatos,
tria, explica e propõe/executa correções.

---

## Entrada pelo agente: “Analise meu projeto”

O `AGENTS.md` da raiz direciona o pedido para `.agents/skills/security-scan/`.
As skills são locais ao repositório. O agente deve estar trabalhando neste projeto
para carregar essas instruções; elas não configuram agentes em outros repositórios.

```bash
./bin/devsec analyze
# ou uma aplicação específica:
./bin/devsec analyze --profile profiles/meu-projeto.env --open
```

`config/default-profile` contém o caminho do perfil padrão, inicialmente
`profiles/achernar-identity.env`. Edite esse arquivo para mudar a aplicação padrão.
Não há LLM embutido no CLI: a interpretação da frase e a revisão contextual são do
agente; a execução e o relatório são reproduzíveis pelo CLI.

### Docker da aplicação e credenciais de teste

```dotenv
APP_STACK_UP=1
APP_COMPOSE_FILE=../minha-aplicacao/docker/compose.yml
# Opcional: arquivo de ambiente já usado pela aplicação
APP_COMPOSE_ENV_FILE=../minha-aplicacao/docker/.env
APP_START_TIMEOUT=180
```

Paths são relativos à raiz do devsec ou absolutos. O CLI executa
`docker compose up -d --build` com o diretório do Compose como project-directory,
antes de verificar APP_URL e API_URL. O perfil Achernar já aponta para o Compose
existente em `../ACHERNAR/achernar_identity/docker/docker-compose.yml`; ele exige
as variáveis próprias da aplicação, como DATABASE_PASSWORD e ADMIN_EMAIL, em seu
ambiente/.env. Essas configurações não são criadas nem sobrescritas pelo pipeline.
O daemon Docker precisa estar disponível. Serviços e volumes são preservados ao final.
Para não subir a aplicação, use APP_STACK_UP=0. `--no-stack` controla apenas a stack
de ferramentas de segurança.

Para autenticação, configure AUTH_MODE e endpoints no perfil público e guarde
AUTH_USERNAME/AUTH_PASSWORD em `<perfil>.secrets.env`. Para header estático,
AUTH_HEADER também deve ficar no arquivo de segredos; não exige usuário/senha.
Os arquivos de autenticação temporários são removidos após o DAST e na saída do CLI.
Os relatórios/logs brutos podem conter dados sensíveis do alvo: mantenha-os locais.

Se um alvo não responder após a espera, o CLI registra DAST como failed, continua
as análises de código e gera o dashboard. Falhas de Compose aparecem na cobertura.
AUTH_REQUIRED=1 impede continuar sem autenticação após erro no login. Obter cookie
ou token não comprova que as áreas protegidas foram cobertas: essa limitação aparece
no dashboard e precisa de validação contextual.

### Dashboard e plano

Cada execução gera `index.html` autossuficiente, com filtros por severidade,
categoria e ferramenta e busca por texto, além de `remediation-plan.json` e
`remediation-plan.md`. O plano é preliminar e traz evidência, ação proposta,
prioridade, validação e critério de aceite. O agente pode contextualizá-lo com o
código; nenhuma correção da aplicação é aplicada pelo pedido de análise.
`report.html` é mantido por compatibilidade. Todos os dados do dashboard vêm da
execução: o exemplo de interface não é evidência de um scan real.

### Playwright MCP

A skill `.agents/skills/playwright-validation/SKILL.md` orienta o agente a descobrir
e usar o MCP quando solicitado. O servidor precisa estar configurado no cliente;
estas mudanças não instalam nem conectam um MCP. `AUTH_MODE=playwright` executa um
script Node de login e funciona independentemente do MCP.

## 1. Pré-requisitos

- Docker + Docker Compose v2;
- `jq`, `python3`, `curl`;
- ~8 GB de RAM livres para a stack;
- Semgrep local é opcional (usa container como fallback).

Valide com:

```bash
./bin/devsec doctor
```

---

## 2. Início rápido

```bash
cp profiles/example.env profiles/meu-projeto.env
# edite BACKEND_PATH, FRONTEND_PATH, APP_URL, API_URL e AUTH_MODE

cp profiles/example.secrets.env.example profiles/meu-projeto.secrets.env
# preencha AUTH_USERNAME / AUTH_PASSWORD (e tokens, se houver)

./bin/devsec scan --profile profiles/meu-projeto.env
./bin/devsec report --run last --open
```

Ou via Make:

```bash
make doctor
make scan PROFILE=profiles/meu-projeto.env
make report
make runs
```

---

## 3. Perfil de execução

O perfil é um arquivo shell (`.env`) carregado pelo CLI. Segredos ficam em
`<perfil>.secrets.env`, que é ignorado pelo Git.

| Variável | Função |
|---|---|
| `RUN_NAME` | nome do projeto/execução |
| `BACKEND_PATH` / `FRONTEND_PATH` | código local (relativo à raiz do devsec ou absoluto) |
| `APP_URL` | URL local da aplicação (DAST) |
| `API_URL` | URL da API, quando separada |
| `OPENAPI_SPEC` | especificação OpenAPI para scan de API |
| `AUTH_MODE` | `none`, `header`, `login`, `form` ou `playwright` |
| `AUTH_USERNAME` / `AUTH_PASSWORD` | credenciais de teste (via secrets) |
| `ENABLE_SAST/SCA/SECRETS/DAST` | liga/desliga estágios |
| `ENABLE_SONAR/DTRACK/GRYPE` | liga/desliga ferramentas específicas |
| `ZAP_ACTIVE` | DAST ativo (exige flag na linha de comando) |
| `GATE_FAIL_ON` | severidades que reprovam o gate (padrão `critical,high`) |
| `SEMGREP_CONFIG` | `p/owasp-top-ten`, `p/default`, `p/secrets`, `auto` ou path local (lista separada por espaço) |

Paths relativos são resolvidos a partir da **raiz do devsec**, para que o
perfil funcione de qualquer diretório.

---

## 4. Autenticação do DAST

### `header` — header estático

```env
AUTH_MODE=header
AUTH_HEADER=Authorization: Bearer eyJ...
```

### `login` — login via HTTP (recomendado para JWT/API)

```env
AUTH_MODE=login
AUTH_LOGIN_URL=http://localhost:8080/api/auth/token
AUTH_LOGIN_BODY='{"email":"__USERNAME__","password":"__PASSWORD__"}'
AUTH_TOKEN_JSON_PATH=.accessToken
AUTH_TOKEN_HEADER=Authorization
AUTH_TOKEN_PREFIX=Bearer
```

O CLI faz o POST, extrai o token com `jq` e injeta o header no ZAP via Replacer.

### `login` + cookie + CSRF (sessão de navegador)

```env
AUTH_MODE=login
AUTH_LOGIN_URL=http://localhost:4200/api/auth/login
AUTH_LOGIN_BODY='{"email":"__USERNAME__","password":"__PASSWORD__"}'
AUTH_CSRF_URL=http://localhost:4200/api/csrf
AUTH_USE_COOKIE=1
AUTH_COOKIE_NAME=IDENTITY_SESSION
AUTH_REQUIRED=1
```

Faz `GET` no CSRF, envia o header no login e repassa os cookies de sessão
para o ZAP.

### `form` — formulário clássico (experimental)

Gera um contexto ZAP form-based. Útil para login server-side; para SPA com
XHR/JSON prefira `login` ou `playwright`.

### `playwright` — login real de navegador

Informe `AUTH_PLAYWRIGHT_SCRIPT`. O script roda com Node e deve escrever um
JSON `{"headers": {"Authorization": "Bearer ...", "Cookie": "..."}}` no caminho
indicado por `$OUT`.

> Credenciais nunca são gravadas no relatório. Gitleaks roda com `--redact`.

---

## 5. Estágios e ferramentas

| Estágio | Ferramenta | O que cobre | Limitação |
|---|---|---|---|
| SAST | Semgrep | padrões de código, secrets em código | regras genéricas |
| SAST | SonarQube | fluxo de dados, qualidade, hotspots | precisa da stack e token |
| SCA | Syft | inventário de componentes (SBOM) | depende de resolução de dependências |
| SCA | Grype | CVEs no SBOM | base local, sem contexto de negócio |
| SCA | Dependency-Track | CVEs + políticas + histórico | NVD pode estar sincronizando |
| Segredos | Gitleaks | credenciais no código/histórico | falso positivo em exemplos |
| DAST | ZAP baseline | cabeçalhos, cookies, exposição passiva | não ataca |
| DAST | ZAP API | contrato OpenAPI | precisa de spec |
| DAST | ZAP full | injeção, XSS, etc. | **ativo**: só com autorização |

---

## 6. Saída

Cada execução fica em `reports/runs/<run-id>/`:

| Arquivo | Uso |
|---|---|
| `index.html` | dashboard com JavaScript e filtros |
| `remediation-plan.json` / `.md` | plano preliminar com validação |
| `report.html` | leitura humana |
| `report.md` | versionar/colar em issue |
| `findings.json` | automação, Jira, IA |
| `summary.json` | gate, contagens, delta, cobertura |
| `context.md` | contexto compacto para a IA |
| `raw/` | saída bruta por ferramenta (auditoria) |
| `logs/` | diagnóstico de falha |

### Delta

```bash
./bin/devsec scan --profile profiles/meu-projeto.env --baseline last
```

Compara por `fingerprint` e informa `new`, `fixed` e `persisting`. `fixed` é
compatibilidade de schema e significa “não observado novamente”, não correção
comprovada. `last` seleciona o mesmo projeto/escopo; projeto, escopo, modo DAST ou
cobertura incompatível impedem a comparação.

### Gate

- `FAIL` — existe achado nas severidades de `GATE_FAIL_ON`;
- `REQUIRES_REVIEW` — estágio falhou/ficou parcial;
- `PASS` — nada acima do limiar e estágios concluídos.

Para usar em CI, defina `FAIL_ON_GATE=1`: código 2 em `FAIL` e código 3 em
`REQUIRES_REVIEW`. Etapas ausentes ou desabilitadas impedem um PASS de cobertura
completa. Um scan parcial continua útil, mas não atesta a execução dos quatro estágios.

---

## 7. Integração com a IA (`achernar_ia`)

A intenção `APPSEC` do motor usa três Skills:

| Skill | Papel |
|---|---|
| `security-scan` | executa o CLI e devolve o run |
| `security-triage` | valida evidência, separa falso positivo e prioriza |
| `security-remediation` | monta plano, corrige via intenção própria e verifica |

O elo é `config/appsec.yaml` no motor (caminho do CLI, perfil e relatórios).
O `context.md` é o ponto de entrada barato: a IA começa por ele, não por
`findings.json` inteiro.

Fluxo de follow-up:

```text
"explica o F-0012"        → triagem lê 1 achado + código apontado
"corrige o F-0012"        → intenção BACKEND/FRONTEND com o ID no escopo
"roda só o DAST de novo"  → devsec scan --only dast --baseline last
"gera plano de correção"  → security-remediation
"abre Jira"               → intenção JIRA existente
```

---

## 8. Segurança e limites

- use somente em ambiente local/teste/homologação;
- DAST ativo exige `--active --i-have-authorization` e alvo dedicado;
- não aponte para produção nem para alvo de terceiros;
- credenciais apenas em `*.secrets.env` ou ambiente;
- relatório de ferramenta não substitui revisão humana de exploitabilidade.

---

## 9. Estrutura

```text
bin/devsec              # CLI
lib/common.sh           # utilidades, perfil, run
lib/preflight.sh        # doctor e validações
lib/stack.sh            # compose + healthcheck
lib/sast.sh             # Semgrep + SonarQube
lib/sca.sh              # Syft + Grype + Dependency-Track
lib/secrets.sh          # Gitleaks
lib/dast.sh             # ZAP + autenticação
lib/scan.sh             # comandos scan/report/list/clean
lib/report.py           # normalização, gate, delta, relatórios
profiles/               # perfis por projeto (segredos ignorados)
reports/runs/           # execuções (ignorado no Git)
```

---

## 10. Solução de problemas

| Sintoma | Causa / ação |
|---|---|
| `alvo inacessível` | aplicação fora do ar; suba ou use `ALLOW_UNREACHABLE_TARGET=1` |
| SonarQube sem token | admin/senha padrão alterados; gere `SONAR_TOKEN` em My Account → Security |
| Dependency-Track sem achados | espelho da NVD incompleto; o Grype cobre o intervalo |
| login 401/403 | credenciais, CSRF ou URL do proxy; confira `AUTH_CSRF_URL` |
| ZAP não cobre área logada | contexto/auth insuficiente; revise `AUTH_MODE` |
| Semgrep falha offline | use `SEMGREP_CONFIG=/caminho/regras` |
| porta ocupada | ajuste `SONAR_PORT`, `DTRACK_API_PORT`, `ZAP_PORT` no `.env` |

## Integração Achernar Identity: aplicação somente leitura

O perfil usa o frontend e o backend em `../ACHERNAR/achernar_identity`, os comandos
do README e o Compose existente. O arquivo de ambiente é passado explicitamente
por APP_COMPOSE_ENV_FILE. Se ainda não existir ambiente da aplicação, crie um
`*.secrets.env` em `devsec/profiles`, sem escrever no diretório da aplicação.
Credenciais existentes do perfil são preservadas; o administrador de teste do
README pode preencher campos ausentes. Não substitua uma senha existente pelo
exemplo do README: um banco persistente pode ter credenciais diferentes.

APP_HEALTH_URL aponta para `/api/health` e exige resposta HTTP de sucesso.
AUTH_VERIFY_URL aponta para `/api/auth/session`: o login só é validado se a rota
retornar 401/403 sem sessão e 2xx com a sessão obtida. Isso comprova acesso à rota,
não cobertura de todas as áreas autenticadas.

Os scanners usam código somente leitura; o diretório de trabalho do Sonar fica
em `/tmp` dentro do container. Scripts, relatórios e ajustes ficam em devsec.
Não execute npm install, builds, testes ou correções dentro da aplicação durante
a análise. O build Docker previsto no README compila dentro das imagens.
Contas extras de teste podem ser criadas pela API/interface se necessárias para
validar permissões, preservando contas e dados existentes.
