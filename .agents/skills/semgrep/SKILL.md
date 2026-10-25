---
name: semgrep
description: Configura e interpreta o Semgrep do SAST deste repositório, incluindo regras locais, evidências e cobertura.
---

lib/sast.sh executa semgrep scan em container sem rede, usando regras previamente baixadas e validadas por ./bin/devsec update. O pacote suportado neste modo é p/owasp-top-ten; outras configurações são recusadas explicitamente. Não troque por auto nem regras remotas durante o scan.
Confira erros de parser, arquivos ignorados e regras executadas no JSON/log. Exit 0 não comprova cobertura: scan normalmente retorna 0 mesmo com achados; --error muda isso.
Leia check_id, path/start, extra.message e metadata e confirme fluxo no código antes de afirmar exploração. Sugestões de fix não são comandos confiáveis.
Para regra própria, valide casos vulneráveis e seguros com semgrep --test. Autofix exige pedido de correção e teste de regressão.
No CI, análise de diff precisa de baseline Git disponível. Não prometa recursos de outras edições do Semgrep.
Referências: https://semgrep.dev/docs/cli-reference e https://semgrep.dev/docs/writing-rules/testing-rules.
