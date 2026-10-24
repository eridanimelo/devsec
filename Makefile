.PHONY: help up down restart ps logs pull reset sonar-logs dtrack-logs zap-logs doctor scan report runs

PROFILE ?= profiles/example.env

help: ## Lista os comandos disponíveis
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Sobe toda a stack
	docker compose up -d

down: ## Para a stack (mantém os dados)
	docker compose down

restart: ## Reinicia a stack
	docker compose restart

ps: ## Mostra o status dos containers
	docker compose ps

logs: ## Acompanha logs de todos os serviços
	docker compose logs -f --tail=100

pull: ## Atualiza as imagens
	docker compose pull

reset: ## APAGA TODOS OS DADOS (volumes) e sobe do zero
	docker compose down -v
	docker compose up -d

sonar-logs: ## Logs do SonarQube
	docker compose logs -f --tail=200 sonarqube

dtrack-logs: ## Logs do Dependency-Track
	docker compose logs -f --tail=200 dtrack-apiserver

zap-logs: ## Logs do OWASP ZAP
	docker compose logs -f --tail=200 zap

doctor: ## Verifica pré-requisitos e saúde da stack
	./bin/devsec doctor

scan: ## Executa o pipeline (PROFILE=profiles/arquivo.env)
	./bin/devsec scan --profile $(PROFILE)

report: ## Abre o relatório da última execução
	./bin/devsec report --run last --open

runs: ## Lista execuções e resultados
	./bin/devsec list
