"""Dashboard offline: dados incorporados, renderização por textContent, sem CDN."""
import json


def build_plan(findings):
    validation = {
        'sast': 'Criar teste de regressão do fluxo vulnerável e repetir SAST sobre o mesmo código.',
        'sca': 'Atualizar manifesto/lockfile, executar testes e gerar novo SBOM e scan SCA.',
        'secret': 'Revogar/rotacionar a credencial, remover exposição e repetir detecção sem divulgar o valor.',
        'dast': 'Repetir a requisição na mesma rota e sessão de teste, validar comportamento funcional e repetir DAST.',
    }
    return {
        'status': 'preliminary',
        'notice': 'Plano preliminar baseado nos scanners. Requer revisão do código e confirmação de contexto antes da correção.',
        'items': [{
            'finding_id': f['id'], 'fingerprint': f['fingerprint'],
            'priority': {'critical': 'P0', 'high': 'P1', 'medium': 'P2'}.get(f['severity'], 'P3'),
            'title': f['title'], 'category': f['category'], 'source': f['source'],
            'severity': f['severity'], 'location': f['location'],
            'evidence': f.get('evidence', ''),
            'action': f.get('remediation') or 'Revisar o fluxo e a evidência no código para definir a mudança adequada.',
            'validation': validation.get(f['category'], 'Repetir análise equivalente e verificar regressão funcional.'),
            'acceptance': 'Correção confirmada por revisão e teste; achado reavaliado com escopo e cobertura equivalentes.',
            'status': 'needs_review',
        } for f in findings],
    }


def plan_markdown(plan):
    # Blocos de código mantêm evidências como texto, inclusive payloads HTML.
    def literal(value):
        return str(value).replace('`', '\u02cb')
    lines = ['# Plano de correção', '', plan['notice'], '']
    if not plan['items']:
        lines += ['Nenhum item identificado. Consulte a cobertura no dashboard antes de concluir a análise.', '']
    for item in plan['items']:
        lines += [f"## {item['priority']} · {item['finding_id']}", '', '```text',
                  literal(item['title']), 'Local: ' + literal(json.dumps(item['location'], ensure_ascii=False)),
                  'Evidência: ' + literal(item['evidence'] or 'Consultar saída da ferramenta.'),
                  'Ação: ' + literal(item['action']), 'Validação: ' + item['validation'],
                  'Aceite: ' + item['acceptance'], 'Estado: requer revisão', '```', '']
    return '\n'.join(lines)


def render_dashboard(summary, findings, plan):
    payload = json.dumps({'summary': summary, 'findings': findings, 'plan': plan}, ensure_ascii=False)
    # Impede fechar o elemento script e interpretar payloads como HTML executável.
    payload = payload.replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    return TEMPLATE.replace('__REPORT_DATA__', payload)


TEMPLATE = '''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Achernar Security · Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b111c;--panel:#121d2d;--line:#29384c;--text:#eaf0f8;--muted:#a8bbd1;--accent:#63dfc4}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}main{max-width:1320px;margin:auto;padding:32px}header{display:flex;justify-content:space-between;gap:20px;align-items:center}h1{font-size:34px;margin:4px 0}h2{margin-top:32px;font-size:21px}.brand{color:var(--accent);letter-spacing:2px;font-size:12px}.muted,small{color:var(--muted)}.gate{padding:12px 18px;border:1px solid var(--line);border-radius:10px;font-weight:700}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:25px 0}.card,article,.box{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.card strong{display:block;font-size:30px}.critical,.high{color:#ff9f9f}.medium{color:#ffd68b}.low{color:#93c7ff}.info{color:var(--muted)}.tools{display:flex;gap:10px;flex-wrap:wrap}.tool{border:1px solid var(--line);border-radius:8px;padding:10px 14px}.failed,.partial{border-color:#b26b68}.controls{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}input,select{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:12px;font:inherit}input{flex:1;min-width:200px}article{margin:12px 0}article h3{margin:8px 0;font-size:18px}.tag{display:inline-block;margin-right:8px;font-size:12px;text-transform:uppercase}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1421;padding:14px;border-radius:8px}details{margin-top:12px}summary{cursor:pointer;color:var(--accent)}a{color:var(--accent)}nav{display:flex;gap:18px;flex-wrap:wrap;margin:15px 0}.scope{overflow-wrap:anywhere}button{cursor:pointer}#result-count{color:var(--muted)}@media(max-width:700px){main{padding:18px}.cards{grid-template-columns:repeat(2,1fr)}header{display:block}.gate{display:inline-block;margin-top:12px}h1{font-size:27px}}@media print{.controls,nav{display:none}body{background:white;color:black}article,.box,.card{background:white;color:black;break-inside:avoid}}
</style></head><body><main>
<header><div><span class="brand">ACHERNAR SECURITY</span><h1 id="project">Análise de segurança</h1><div id="run" class="muted"></div></div><div id="gate" class="gate"></div></header>
<nav><a href="report.html">Relatório detalhado</a><a href="remediation-plan.md">Plano de correção</a><a href="findings.json" download>Achados JSON</a><a href="summary.json" download>Resumo JSON</a></nav>
<div id="cards" class="cards"></div>
<section class="box"><strong>Escopo e limites</strong><p id="scope" class="scope"></p><p id="auth" class="muted"></p><p>Achados de scanners exigem triagem. Etapas com falha ou não executadas representam cobertura incompleta. A ausência de um alerta não comprova correção.</p><p id="delta" class="muted"></p></section>
<h2>Cobertura da execução</h2><div id="tools" class="tools"></div>
<h2>Achados e plano de correção</h2><p id="notice" class="muted"></p>
<div class="controls"><input id="search" type="search" placeholder="Buscar título, arquivo, pacote ou regra" aria-label="Buscar achados"><select id="severity" aria-label="Severidade"><option value="">Todas as severidades</option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><select id="category" aria-label="Categoria"><option value="">Todas as categorias</option><option>sast</option><option>sca</option><option>secret</option><option>dast</option></select><select id="source" aria-label="Ferramenta"><option value="">Todas as ferramentas</option></select></div>
<p id="result-count" aria-live="polite"></p><div id="findings"></div>
<noscript>Ative JavaScript para usar o dashboard ou abra report.html.</noscript>
</main><script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
'use strict';
const data=JSON.parse(document.getElementById('report-data').textContent),s=data.summary;
const byId=id=>document.getElementById(id);
const element=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
byId('project').textContent=s.project||'Análise de segurança';
byId('run').textContent=s.run_id+' · '+s.generated_at;
byId('gate').textContent='Gate: '+s.gate.result;
const labels={critical:'Críticos',high:'Altos',medium:'Médios',low:'Baixos',info:'Informativos'};
for(const [sev,label] of Object.entries(labels)){const card=element('div',undefined,'card '+sev);card.append(element('small',label),element('strong',String(s.counts[sev]||0)));byId('cards').append(card);}
byId('scope').textContent=Object.entries(s.scope||{}).filter(([,v])=>v).map(([k,v])=>k+': '+v).join(' · ')||'Escopo não informado';
byId('auth').textContent='DAST: '+(s.dast?.mode||'não informado')+' · Autenticação configurada: '+(s.dast?.auth_mode||'none')+(s.dast?.auth_verified?' · Sessão confirmada na rota protegida. Isso não comprova cobertura de todas as áreas.':'. A obtenção de token/cookie não comprova cobertura de áreas protegidas.');
byId('delta').textContent=s.delta?(s.delta.error||('Comparação: '+s.delta.new+' novos · '+s.delta.persisting+' persistentes · '+s.delta.fixed+' não observados novamente; confirmar cobertura equivalente.')):'Sem comparação com execução anterior.';
for(const tool of s.tools||[]){const box=element('div',undefined,'tool '+tool.status);box.append(element('strong',tool.stage+' · '+tool.status),element('div',tool.detail,'muted'));byId('tools').append(box);}
if(!(s.tools||[]).length)byId('tools').textContent='Sem registros de execução: cobertura não comprovada.';
byId('notice').textContent=data.plan.notice;
for(const source of [...new Set(data.findings.map(f=>f.source))].sort()){const o=element('option',source);o.value=source;byId('source').append(o);}
const plans=new Map(data.plan.items.map(p=>[p.finding_id,p]));
function render(){
 const q=byId('search').value.toLocaleLowerCase(),sev=byId('severity').value,cat=byId('category').value,src=byId('source').value;
 const filtered=data.findings.filter(f=>(!sev||f.severity===sev)&&(!cat||f.category===cat)&&(!src||f.source===src)&&JSON.stringify(f).toLocaleLowerCase().includes(q));
 byId('findings').replaceChildren();byId('result-count').textContent=filtered.length+' de '+data.findings.length+' achados';
 for(const f of filtered){const p=plans.get(f.id),card=element('article');
 card.append(element('span',f.severity,'tag '+f.severity),element('span',f.source+' · '+f.category,'tag'),element('h3',f.id+' · '+f.title));
 card.append(element('p',Object.entries(f.location||{}).map(([k,v])=>k+': '+v).join(' · '),'muted'));
 if(f.description)card.append(element('p',f.description));
 const details=element('details');details.append(element('summary','Evidência e plano de correção'));
 if(f.evidence)details.append(element('pre',f.evidence));
 if(p){for(const [label,value] of [['Prioridade',p.priority+' · requer revisão'],['Ação proposta',p.action],['Como validar',p.validation],['Critério de aceite',p.acceptance]]){details.append(element('strong',label),element('p',value));}}
 if(f.cwe?.length)details.append(element('p','CWE: '+f.cwe.join(', ')));
 if(f.rule)details.append(element('p','Regra: '+f.rule,'muted'));
 card.append(details);byId('findings').append(card);}
 if(!filtered.length)byId('findings').append(element('p','Nenhum achado corresponde aos filtros. Confira a cobertura das ferramentas.','box'));
}
for(const id of ['search','severity','category','source'])byId(id).addEventListener('input',render);
render();
</script></body></html>'''
