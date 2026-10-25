---
name: security-triage
description: Faz triagem de achados SAST, SCA, segredos e DAST com evidência do código e cobertura.
---

Comece por context.md e summary.json; leia findings.json e código conforme necessário. Preserve ID e fingerprint.
Separe achado de scanner, confirmação por revisão, falso positivo justificado e inconclusivo. Severidade não comprova exploração.
SAST: verifique origem, validação e destino. SCA: confira pacote/versão, uso e versão corrigida. Segredos: nunca reproduza valor; rotação precede remoção. DAST: diferencie alerta passivo de exploração e confira autenticação.
Priorize exposição, sensibilidade, confiança e correção disponível. Não invente CVSS, EPSS, KEV ou exploitabilidade.
Falhas devem ficar visíveis. Ausência no scan seguinte não prova correção sem cobertura equivalente.
