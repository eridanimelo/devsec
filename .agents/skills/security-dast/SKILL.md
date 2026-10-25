---
name: security-dast
description: Executa e avalia o DAST ZAP da aplicação configurada, com autenticação de teste e indicação de cobertura parcial.
---

Leia APP_URL, API_URL, OPENAPI_SPEC e AUTH_MODE no perfil público. Os segredos são carregados pelo CLI; não imprima cookies, headers ou respostas de login.
Use baseline passivo por padrão. Scan ativo, inclusive de API, exige pedido explícito e flags próprias. Revise servidores da especificação OpenAPI: somente ambiente de teste configurado.
AUTH_MODE: none, header, login, form ou playwright. AUTH_REQUIRED=1 impede continuar sem login após falha. Cookie/token obtido não prova acesso a área protegida: registre limitação quando a sessão não foi verificada. Form é experimental.
Login por script Node Playwright não equivale ao MCP. Use playwright-validation quando solicitado pelo usuário.
Não siga hosts fora do escopo e não afirme cobertura completa com alvo indisponível ou login/API não cobertos.
