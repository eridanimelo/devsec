---
name: security-remediation
description: Produz plano de correção rastreável e define testes de validação para os achados.
---

O CLI gera remediation-plan.json e remediation-plan.md preliminares. Contextualize as recomendações com o código, sem apresentá-las como patches validados.
Indique ID/fingerprint, evidência, arquivo/endpoint/pacote, alteração proposta, dependências e teste de regressão. Se faltar contexto, registre investigação; não invente arquivos/versões.
Indique versão corrigida apenas quando comprovada por ferramenta ou advisory oficial. Priorize rotação de segredos e exposição conforme evidência.
Analisar autoriza gerar plano; editar a aplicação depende de pedido de correção. Se autorizado, faça mudança pequena, teste regressão e repita o scan relevante. Informe riscos remanescentes.
O dashboard incorpora o plano no momento da geração. Preserve resultados brutos e não altere evidência para representar recomendações como fatos.
