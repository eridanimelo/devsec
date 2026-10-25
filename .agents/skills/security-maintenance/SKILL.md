---
name: security-maintenance
description: Atualiza e verifica regras e bases públicas do Achernar Security sem enviar código, SBOMs, dependências ou relatórios a serviços externos.
---

Execute `./bin/devsec update` para atualizar o cache público, ou `update --force`
para forçar nova checagem. Esse comando não carrega perfil nem monta código ou
SBOMs nos processos de download. Imagens ausentes são baixadas; imagens existentes
não são atualizadas silenciosamente. IDs ficam no manifesto do cache.
Verifique `./bin/devsec data-status`: validade por 24h, hash das regras, data da
base Grype e IDs das imagens. O status Grype também é validado pelo scanner,
inclusive idade da base. Erro de atualização deve ficar visível; não declare sucesso
nem desative validação para conseguir um resultado.

A análise com dados do projeto usa Semgrep, Grype, Syft e Gitleaks em containers
sem rede e código somente leitura. Regras públicas e a base são baixadas antes.
Semgrep tem métricas e checagem de versão off; o Grype não atualiza a base no scan.
Não use consultas remotas de advisories por nome/versão de pacote como fallback.

DTrack baixa espelhos OSV completos de Maven/npm automaticamente. Antes de uploads,
o pipeline aplica lib/dtrack_privacy.py, desativando analisadores externos e
repositórios não internos. Não reative OSS Index/NPM Audit para preencher contadores.
Aguarde os logs de conclusão do espelho e só então reenvie SBOMs ao serviço local.
Download completo de bases públicas é permitido; envio de dados de projeto não é.

Não envie código, SBOM, nomes de dependências, credenciais ou relatórios em buscas,
requisições a fornecedores ou modelos externos. Se esta IA não for aprovada para
processar dados corporativos, limite-se a executar o CLI e apresentar links locais.
Sonar/ZAP/DTrack/aplicação ainda precisam de política de saída em firewall/proxy;
o modo local não equivale a auditoria de tráfego global. Não altere a aplicação.
