---
name: security-scan
description: Executa a análise de segurança da aplicação com o CLI Achernar Security e entrega dashboard e plano quando o usuário pede para analisar o projeto.
---

Use a raiz deste repositório como diretório de trabalho.
1. Execute ./bin/devsec analyze; o perfil padrão está em config/default-profile. Se o usuário nomear outra aplicação, use --profile profiles/<projeto>.env. Pergunte apenas se a seleção for ambígua.
2. Leia somente o perfil público. O CLI carrega <perfil>.secrets.env automaticamente. Não imprima segredos; solicite somente configuração ausente.
3. O CLI sobe a stack de ferramentas e o Compose da aplicação quando APP_COMPOSE_FILE e APP_STACK_UP=1 estão configurados. Pode construir imagens necessárias. Não use down/reset nem remova volumes.
4. Acompanhe até terminar e informe progresso. Não esconda falha desabilitando estágio. DAST ativo exige pedido explícito e --active --i-have-authorization.
5. Leia context.md, summary.json, remediation-plan.json e achados relevantes. Leia security-triage e security-remediation para contextualizar recomendações com evidência do código.
6. Entregue links absolutos para index.html e remediation-plan.md, gate e limitações. Abra o HTML no painel disponível. Regenerar relatório não equivale a executar scan.
Use o mesmo perfil ao repetir. Não compare execuções de projetos/escopos diferentes. Resultados gerados pelo CLI são preliminares e não comprovam exploitabilidade.
