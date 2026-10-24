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

cp profiles/example.secrets.env profiles/meu-projeto.secrets.env
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

Compara por `fingerprint` estável e informa `new`, `fixed` e `persisting`.

### Gate

- `FAIL` — existe achado nas severidades de `GATE_FAIL_ON`;
- `REQUIRES_REVIEW` — estágio falhou/ficou parcial;
- `PASS` — nada acima do limiar e estágios concluídos.

Para usar em CI, defina `FAIL_ON_GATE=1` para sair com código 2 em `FAIL`.

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
