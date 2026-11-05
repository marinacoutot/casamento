'use strict';
/*
 * Controle do casamento.
 * Sem servidor: o app roda no GitHub Pages e guarda os dados CIFRADOS
 * (AES-GCM 256) no branch "dados" do próprio repositório.
 *
 * vault.json  usuários; cada um guarda a chave dos dados embrulhada pela
 *             própria senha (PBKDF2), mais o token do GitHub cifrado.
 * dados.json  todos os dados do casamento, cifrados com a chave dos dados.
 *
 * Em localhost o app usa o localStorage no lugar do GitHub (modo teste).
 */

// ---------- configuração ----------
const CFG = (() => {
  const local = location.protocol === 'file:' || ['localhost', '127.0.0.1'].includes(location.hostname);
  let owner = 'marinacoutot', repo = 'casamento';
  const m = location.hostname.match(/^([^.]+)\.github\.io$/i);
  if (m) { owner = m[1]; repo = location.pathname.split('/')[1] || repo; }
  return { local, owner, repo, branch: 'dados', iter: 310000 };
})();

const STATUS = [
  ['pesquisando', 'Pesquisando'],
  ['orcamento', 'Orçamento recebido'],
  ['negociando', 'Negociando'],
  ['fechado', 'Fechado'],
  ['descartado', 'Descartado'],
];
const CARTAO = 'Cartão de crédito';
const FORMAS = ['Pix', 'Boleto', CARTAO, 'Transferência', 'Dinheiro'];

// ---------- utilidades ----------
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
const sum = a => a.reduce((s, x) => s + (Number(x) || 0), 0);
const r2 = n => Math.round(n * 100) / 100;
const BRL = new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' });
const brl = n => BRL.format(n || 0);
const brl0 = n => BRL.format(Math.round(n || 0)).replace(/,00$/, '');
const MESES = ['jan', 'fev', 'mar', 'abr', 'mai', 'jun', 'jul', 'ago', 'set', 'out', 'nov', 'dez'];
const MESES_LONGOS = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'];

function hojeISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
const mesDe = iso => iso.slice(0, 7);
const mesAtual = () => mesDe(hojeISO());
function fmtData(iso) { if (!iso) return ''; const [y, m, d] = iso.split('-'); return `${d}/${m}/${y}`; }
function fmtMes(ym) { const [y, m] = ym.split('-'); return `${MESES[+m - 1]}/${y.slice(2)}`; }
function fmtMesLongo(ym) { const [y, m] = ym.split('-'); return `${MESES_LONGOS[+m - 1]} de ${y}`; }
function addMeses(iso, n) {
  const [y, m, d] = iso.split('-').map(Number);
  const alvo = new Date(y, m - 1 + n, 1);
  const ultimo = new Date(alvo.getFullYear(), alvo.getMonth() + 1, 0).getDate();
  alvo.setDate(Math.min(d, ultimo));
  return `${alvo.getFullYear()}-${String(alvo.getMonth() + 1).padStart(2, '0')}-${String(alvo.getDate()).padStart(2, '0')}`;
}
function proxMes(ym) { return mesDe(addMeses(ym + '-01', 1)); }
function diasAte(iso) { return Math.round((new Date(iso + 'T12:00') - new Date(hojeISO() + 'T12:00')) / 86400000); }

// aceita "73.232,59", "73232.59", "R$ 1.500"
function parseValor(v) {
  if (typeof v === 'number') return v;
  let s = String(v || '').replace(/[R$\s]/g, '');
  if (!s) return 0;
  if (s.includes(',')) s = s.replace(/\./g, '').replace(',', '.');
  else if (/^\d{1,3}(\.\d{3})+$/.test(s)) s = s.replace(/\./g, '');
  const n = parseFloat(s);
  return isNaN(n) ? 0 : r2(n);
}
const valorInput = n => n ? String(r2(n)).replace('.', ',') : '';

function toast(msg, erro) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'on' + (erro ? ' err' : '');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.className = '', erro ? 5000 : 2400);
}

// ---------- cripto ----------
const enc = new TextEncoder(), dec = new TextDecoder();
function b64(buf) {
  const b = new Uint8Array(buf); let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) { const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b; }

async function chaveDaSenha(senha, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(senha), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function cifrar(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
  return { iv: b64(iv), ct: b64(ct) };
}
async function decifrar(key, box) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct)));
}
const importarDEK = raw => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);

async function embrulharParaUsuario(usuario, senha, dekRaw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await chaveDaSenha(senha, salt, CFG.iter);
  return { u: usuario.toLowerCase().trim(), nome: usuario.trim(), salt: b64(salt), iter: CFG.iter, chave: await cifrar(kek, dekRaw) };
}

// ---------- armazenamento ----------
const Store = {
  async get(arquivo, token) {
    if (CFG.local) {
      const v = localStorage.getItem('casamento.' + arquivo);
      return v ? { text: v, sha: 'local' } : null;
    }
    const url = `https://api.github.com/repos/${CFG.owner}/${CFG.repo}/contents/${arquivo}?ref=${CFG.branch}&t=${Date.now()}`;
    const headers = { Accept: 'application/vnd.github+json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    const r = await fetch(url, { headers, cache: 'no-store' });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`GitHub respondeu ${r.status} ao ler ${arquivo}`);
    const j = await r.json();
    let text;
    if (j.content) text = dec.decode(unb64(j.content.replace(/\n/g, '')));
    else {
      // arquivos acima de 1 MB vêm sem conteúdo inline
      const raw = await fetch(j.download_url, { cache: 'no-store', headers: token ? { Authorization: 'Bearer ' + token } : {} });
      text = await raw.text();
    }
    return { text, sha: j.sha };
  },
  async put(arquivo, text, sha, token, mensagem) {
    if (CFG.local) { localStorage.setItem('casamento.' + arquivo, text); return 'local'; }
    const body = { message: mensagem, content: b64(enc.encode(text)), branch: CFG.branch };
    if (sha) body.sha = sha;
    const r = await fetch(`https://api.github.com/repos/${CFG.owner}/${CFG.repo}/contents/${arquivo}`, {
      method: 'PUT',
      headers: { Accept: 'application/vnd.github+json', Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (r.status === 409 || r.status === 422) { const e = new Error('conflito'); e.conflito = true; throw e; }
    if (r.status === 401 || r.status === 403) throw new Error('O token do GitHub foi recusado (expirou ou perdeu a permissão). Atualize em Ajustes.');
    if (!r.ok) throw new Error(`GitHub respondeu ${r.status} ao salvar`);
    return (await r.json()).content.sha;
  },
};

// ---------- estado ----------
const S = {
  dek: null, dekRaw: null, token: null, usuario: null,
  vault: null, vaultSha: null, data: null, dataSha: null,
  view: 'resumo', filtroStatus: 'ativos', busca: '', filtroPag: 'pendentes',
};

function dadosIniciais() {
  const cat = (nome, orcado) => ({ id: uid(), nome, orcado });
  const categorias = [
    cat('Local e buffet', 75000), cat('Bebidas', 6000), cat('Assessoria e cerimonial', 6000),
    cat('Decoração e flores', 15000), cat('Fotografia', 8000), cat('Filmagem', 6000),
    cat('Música e DJ', 5000), cat('Bolo e doces', 4000), cat('Vestido da noiva', 8000),
    cat('Traje do noivo', 2500), cat('Beleza (cabelo e make)', 2500), cat('Alianças', 4000),
    cat('Convites e papelaria', 1500), cat('Celebrante', 2000), cat('Lembrancinhas', 1500),
    cat('Lua de mel', 20000), cat('Outros', 5000),
  ];
  const local = categorias[0].id;
  const forn = (nome, extra) => ({ id: uid(), nome, categoriaId: local, status: 'pesquisando', contato: '', telefone: '', email: '', link: '', valorOrcado: 0, valorFechado: 0, dataFechamento: '', obs: '', ...extra });
  return {
    versao: 1,
    config: { noivos: 'Marina & Davi', data: '2027-10-30', cidade: 'Florianópolis', convidados: 80, teto: 0, saldoAtual: 0 },
    categorias,
    fornecedores: [
      forn('Indaiá Eventos (Mirante da Lagoa)', {
        status: 'negociando', valorOrcado: 73232.59,
        obs: 'Prévia de contrato p/ 80 pessoas. Entrada R$ 36.616,30 no cartão + saldo R$ 36.626,19 em boleto 01/10/2027.\nConferir: prévia diz 01/11/2027 em vez de 30/10. Reclame Aqui 4,2/10; restrição recente de banda no Mirante.',
      }),
      forn('Empório Capella', { obs: 'Ex-igreja na estrada da Lagoa, até 60 pessoas com cerimônia + festa.' }),
      forn('Villa do Porto', { obs: 'Santo Antônio de Lisboa, prédio de pedra na praia.' }),
      forn('Coco Beach Floripa', { obs: 'Ribeirão da Ilha.' }),
      forn('Quinta da Bela Vista', { obs: 'Santo Antônio de Lisboa, bosque.' }),
    ],
    pagamentos: [],
    entradas: [],
  };
}

// ---------- sessão ----------
async function carregarVault() {
  const v = await Store.get('vault.json');
  if (!v) return false;
  S.vault = JSON.parse(v.text); S.vaultSha = v.sha;
  return true;
}
async function entrar(usuario, senha) {
  const u = S.vault.usuarios.find(x => x.u === usuario.toLowerCase().trim());
  if (!u) throw new Error('Usuário ou senha incorretos.');
  const kek = await chaveDaSenha(senha, unb64(u.salt), u.iter);
  let raw;
  try { raw = await decifrar(kek, u.chave); } catch { throw new Error('Usuário ou senha incorretos.'); }
  await abrirSessao(u.u, raw);
  sessionStorage.setItem('casamento.sessao', JSON.stringify({ u: u.u, k: b64(raw) }));
}
async function abrirSessao(u, raw) {
  S.dekRaw = raw; S.dek = await importarDEK(raw); S.usuario = u;
  S.token = S.vault.token ? dec.decode(await decifrar(S.dek, S.vault.token)) : null;
  await carregarDados();
}
async function carregarDados() {
  const d = await Store.get('dados.json', S.token);
  if (!d) { S.data = dadosIniciais(); S.dataSha = null; return; }
  S.data = JSON.parse(dec.decode(await decifrar(S.dek, JSON.parse(d.text))));
  S.dataSha = d.sha;
}
function sair() {
  sessionStorage.removeItem('casamento.sessao');
  Object.assign(S, { dek: null, dekRaw: null, token: null, usuario: null, data: null });
  render();
}

let salvando = Promise.resolve();
function salvar(msg = 'atualiza dados') {
  salvando = salvando.then(async () => {
    const ind = document.createElement('div'); ind.className = 'saving'; ind.textContent = 'Salvando…';
    document.body.appendChild(ind);
    try {
      const box = await cifrar(S.dek, enc.encode(JSON.stringify(S.data)));
      S.dataSha = await Store.put('dados.json', JSON.stringify(box), S.dataSha, S.token, msg);
    } catch (e) {
      if (e.conflito) {
        await carregarDados(); render();
        toast('Outra pessoa salvou ao mesmo tempo. Recarreguei os dados; refaça a última alteração.', true);
      } else toast(e.message, true);
    } finally { ind.remove(); }
  });
  return salvando;
}
async function salvarVault(msg) {
  S.vaultSha = await Store.put('vault.json', JSON.stringify(S.vault, null, 1), S.vaultSha, S.token, msg);
}

// ---------- cálculos ----------
const catNome = id => S.data.categorias.find(c => c.id === id)?.nome || 'Sem categoria';
const fornNome = id => S.data.fornecedores.find(f => f.id === id)?.nome || '';

function porCategoria() {
  const d = S.data;
  return d.categorias.map(c => {
    const fs = d.fornecedores.filter(f => f.categoriaId === c.id);
    const fechados = fs.filter(f => f.status === 'fechado');
    const pags = d.pagamentos.filter(p => p.categoriaId === c.id);
    const avulsos = pags.filter(p => !p.fornecedorId);
    const comprometido = sum(fechados.map(f => f.valorFechado)) + sum(avulsos.map(p => p.valor));
    const pago = sum(pags.filter(p => p.pago).map(p => p.valor));
    const abertos = fs.filter(f => !['fechado', 'descartado'].includes(f.status));
    const cotacoes = abertos.filter(f => f.valorOrcado > 0).map(f => f.valorOrcado);
    const situacao = fechados.length ? 'fechado' : abertos.length ? 'andamento' : 'nada';
    return {
      ...c, comprometido, pago, aPagar: comprometido - pago, abertos: abertos.length,
      menorCotacao: cotacoes.length ? Math.min(...cotacoes) : null, situacao,
      aContratar: situacao === 'fechado' ? 0 : c.orcado || 0,
    };
  });
}

function totais() {
  const cats = porCategoria();
  const orcado = sum(cats.map(c => c.orcado));
  const comprometido = sum(cats.map(c => c.comprometido));
  const pago = sum(cats.map(c => c.pago));
  const aContratar = sum(cats.map(c => c.aContratar));
  return { cats, orcado, comprometido, pago, aPagar: comprometido - pago, aContratar, previsaoFinal: comprometido + aContratar };
}

function statusPag(p) {
  if (p.pago) return 'pago';
  return p.vencimento < hojeISO() ? 'atrasado' : 'pendente';
}

// fluxo de caixa: do mês atual até o mês seguinte ao casamento
function fluxo() {
  const d = S.data, atual = mesAtual();
  const pend = d.pagamentos.filter(p => !p.pago);
  let fim = proxMes(mesDe(d.config.data || hojeISO()));
  for (const p of pend) if (mesDe(p.vencimento) > fim) fim = mesDe(p.vencimento);
  const meses = [];
  for (let m = atual; m <= fim; m = proxMes(m)) meses.push({ mes: m, saidas: 0, entradas: 0, itensS: [], itensE: [] });
  const idx = m => meses.find(x => x.mes === (m < atual ? atual : m));

  for (const p of pend) {
    const alvo = idx(mesDe(p.vencimento)); if (!alvo) continue;
    alvo.saidas += p.valor;
    alvo.itensS.push({ desc: (fornNome(p.fornecedorId) || catNome(p.categoriaId)) + (p.descricao ? ' · ' + p.descricao : ''), valor: p.valor, atrasado: p.vencimento < hojeISO() });
  }
  for (const e of d.entradas) {
    if (e.recorrente) {
      const ate = e.ate ? mesDe(e.ate) : mesDe(d.config.data);
      for (let m = mesDe(e.data) < atual ? atual : mesDe(e.data); m <= ate; m = proxMes(m)) {
        const alvo = idx(m); if (!alvo) break;
        alvo.entradas += e.valor; alvo.itensE.push({ desc: e.descricao, valor: e.valor });
      }
    } else if (!e.recebido) {
      const alvo = idx(mesDe(e.data)); if (!alvo) continue;
      alvo.entradas += e.valor; alvo.itensE.push({ desc: e.descricao, valor: e.valor });
    }
  }
  let saldo = d.config.saldoAtual || 0;
  for (const m of meses) { saldo += m.entradas - m.saidas; m.saldo = r2(saldo); }
  return meses;
}

// ---------- render ----------
function render() {
  const app = $('#app');
  if (!S.vault) return renderSetup(app);
  if (!S.dek) return renderLogin(app);
  const dias = diasAte(S.data.config.data);
  const contagem = dias > 0 ? `faltam <b>${dias}</b> dias` : dias === 0 ? '<b>é hoje!</b>' : 'casados ♥';
  const tabs = [['resumo', 'Resumo'], ['fornecedores', 'Fornecedores'], ['orcamento', 'Orçamento'], ['pagamentos', 'Pagamentos'], ['fluxo', 'Fluxo de caixa'], ['ajustes', 'Ajustes']];
  app.innerHTML = `
    <header class="top"><div class="top-in">
      <div class="top-row">
        <h1>${esc(S.data.config.noivos)}</h1>
        <div class="count">${fmtData(S.data.config.data)} · ${esc(S.data.config.cidade)} · ${contagem}</div>
      </div>
      <nav class="tabs">${tabs.map(([k, l]) => `<button data-tab="${k}" class="${S.view === k ? 'on' : ''}">${l}</button>`).join('')}</nav>
    </div></header>
    <main id="main"></main>`;
  app.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => { S.view = b.dataset.tab; render(); scrollTo(0, 0); });
  ({ resumo: vResumo, fornecedores: vFornecedores, orcamento: vOrcamento, pagamentos: vPagamentos, fluxo: vFluxo, ajustes: vAjustes })[S.view]($('#main'));
}

const ANEIS = `<svg class="rings" width="64" height="44" viewBox="0 0 64 44" aria-hidden="true"><circle cx="24" cy="22" r="15" fill="none" stroke="#B5694A" stroke-width="3"/><circle cx="40" cy="22" r="15" fill="none" stroke="#6F8466" stroke-width="3"/></svg>`;

function renderLogin(app) {
  app.innerHTML = `<div class="login-wrap"><form class="login-card" id="f">
    ${ANEIS}<h1>Nosso casamento</h1><p class="sub">Entre para ver o planejamento</p>
    <label class="f"><span>Usuário</span><input name="u" autocomplete="username" required autofocus></label>
    <label class="f"><span>Senha</span><input name="s" type="password" autocomplete="current-password" required></label>
    <div class="err" id="err"></div>
    <button class="btn primary block" id="go">Entrar</button>
  </form></div>`;
  $('#f').onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData(e.target), btn = $('#go');
    btn.disabled = true; btn.textContent = 'Entrando…'; $('#err').textContent = '';
    try { await entrar(fd.get('u'), fd.get('s')); render(); }
    catch (er) { $('#err').textContent = er.message; btn.disabled = false; btn.textContent = 'Entrar'; }
  };
}

function renderSetup(app) {
  app.innerHTML = `<div class="login-wrap"><form class="login-card" id="f">
    ${ANEIS}<h1>Primeira configuração</h1>
    <p class="sub">Crie o seu acesso. Os dados ficam cifrados com a sua senha no repositório <b>${esc(CFG.owner)}/${esc(CFG.repo)}</b>.</p>
    ${CFG.local ? '<div class="alert gold">Modo teste local: os dados ficam só neste navegador.</div>' : `
    <label class="f"><span>Token do GitHub (fine-grained, só este repositório, Contents: read and write)</span><input name="t" required autocomplete="off" spellcheck="false"></label>`}
    <label class="f"><span>Usuário</span><input name="u" required autocomplete="username"></label>
    <label class="f"><span>Senha (mínimo 10 caracteres)</span><input name="s" type="password" minlength="10" required autocomplete="new-password"></label>
    <label class="f"><span>Repita a senha</span><input name="s2" type="password" required autocomplete="new-password"></label>
    <div class="err" id="err"></div>
    <button class="btn primary block" id="go">Criar acesso</button>
  </form></div>`;
  $('#f').onsubmit = async e => {
    e.preventDefault();
    const fd = new FormData(e.target), btn = $('#go'), err = $('#err');
    if (fd.get('s') !== fd.get('s2')) { err.textContent = 'As senhas não conferem.'; return; }
    btn.disabled = true; btn.textContent = 'Configurando…'; err.textContent = '';
    try {
      const token = CFG.local ? null : fd.get('t').trim();
      if (token) {
        const r = await fetch(`https://api.github.com/repos/${CFG.owner}/${CFG.repo}`, { headers: { Authorization: 'Bearer ' + token } });
        if (!r.ok) throw new Error('Token não tem acesso ao repositório.');
        const j = await r.json();
        if (!j.permissions?.push) throw new Error('Token sem permissão de escrita (Contents: read and write).');
        S.token = token;
      }
      const dek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', dek));
      S.dek = dek; S.dekRaw = raw;
      S.vault = { versao: 1, usuarios: [await embrulharParaUsuario(fd.get('u'), fd.get('s'), raw)], token: token ? await cifrar(dek, enc.encode(token)) : null };
      S.vaultSha = null;
      await salvarVault('cria acesso');
      S.usuario = S.vault.usuarios[0].u;
      S.data = dadosIniciais(); S.dataSha = null;
      await salvar('dados iniciais');
      sessionStorage.setItem('casamento.sessao', JSON.stringify({ u: S.usuario, k: b64(raw) }));
      render();
    } catch (er) {
      S.vault = null; S.dek = null;
      err.textContent = er.message; btn.disabled = false; btn.textContent = 'Criar acesso';
    }
  };
}

// --- Resumo ---
function vResumo(el) {
  const t = totais(), fl = fluxo(), d = S.data;
  const teto = d.config.teto || t.orcado;
  const pend = d.pagamentos.filter(p => !p.pago).sort((a, b) => a.vencimento.localeCompare(b.vencimento));
  const atrasados = pend.filter(p => p.vencimento < hojeISO());
  const negativo = fl.find(m => m.saldo < 0);
  const nFech = t.cats.filter(c => c.situacao === 'fechado').length;
  const nAnd = t.cats.filter(c => c.situacao === 'andamento').length;
  const nNada = t.cats.length - nFech - nAnd;
  const pct = teto ? Math.min(100, t.comprometido / teto * 100) : 0;
  const pctPago = teto ? Math.min(100, t.pago / teto * 100) : 0;

  el.innerHTML = `
    ${atrasados.length ? `<div class="alert red"><b>${atrasados.length} pagamento(s) atrasado(s)</b>, total ${brl(sum(atrasados.map(p => p.valor)))}. <a href="#" data-go="pagamentos">Ver</a></div>` : ''}
    ${negativo ? `<div class="alert gold">Pelo fluxo de caixa, o saldo fica negativo em <b>${fmtMesLongo(negativo.mes)}</b> (${brl(negativo.saldo)}). <a href="#" data-go="fluxo">Ver fluxo</a></div>` : ''}
    <div class="grid kpis">
      <div class="card kpi"><div class="lbl">Orçamento previsto</div><div class="val num">${brl0(teto)}</div><div class="det">${d.config.teto ? 'teto definido' : 'soma das categorias'}</div></div>
      <div class="card kpi"><div class="lbl">Já fechado</div><div class="val num">${brl0(t.comprometido)}</div><div class="det">${teto ? Math.round(t.comprometido / teto * 100) + '% do previsto' : ''}</div></div>
      <div class="card kpi"><div class="lbl">Já pago</div><div class="val num" style="color:var(--sage)">${brl0(t.pago)}</div><div class="det">falta pagar ${brl0(t.aPagar)}</div></div>
      <div class="card kpi"><div class="lbl">Previsão final</div><div class="val num" style="color:${t.previsaoFinal > teto && teto ? 'var(--red)' : 'inherit'}">${brl0(t.previsaoFinal)}</div><div class="det">fechado + ${brl0(t.aContratar)} a contratar</div></div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="bar" style="height:12px"><i class="pago" style="width:${pctPago}%"></i><i class="fech" style="width:${pct - pctPago}%"></i></div>
      <div class="legend" style="margin-top:8px"><span><i style="background:var(--sage)"></i>Pago</span><span><i style="background:#A9B9A1"></i>Fechado, a pagar</span><span><i style="background:var(--surface-2)"></i>Livre</span></div>
    </div>
    <div class="grid two" style="margin-top:14px">
      <div class="card">
        <div class="section-title"><h3>Próximos pagamentos</h3><a href="#" class="small" data-go="pagamentos">todos</a></div>
        ${pend.length ? pend.slice(0, 6).map(itemPagamento).join('') : '<div class="empty">Nenhum pagamento pendente.</div>'}
      </div>
      <div class="card">
        <div class="section-title"><h3>Categorias</h3><a href="#" class="small" data-go="orcamento">detalhes</a></div>
        <div class="legend" style="margin-bottom:10px">
          <span><span class="badge b-fechado">${nFech} fechada${nFech === 1 ? '' : 's'}</span></span>
          <span><span class="badge b-negociando">${nAnd} em andamento</span></span>
          <span><span class="badge b-pesquisando">${nNada} não iniciada${nNada === 1 ? '' : 's'}</span></span>
        </div>
        ${t.cats.map(c => `<div class="list-item" style="padding:7px 0">
          <div class="grow"><div class="t">${esc(c.nome)}</div></div>
          ${c.situacao === 'fechado' ? `<span class="badge b-fechado">${brl0(c.comprometido)}</span>` : c.situacao === 'andamento' ? `<span class="badge b-negociando">${c.abertos} opç${c.abertos > 1 ? 'ões' : 'ão'}</span>` : '<span class="badge b-pesquisando">a buscar</span>'}
        </div>`).join('')}
      </div>
    </div>`;
  ligarGo(el); ligarPagamentos(el);
}
function ligarGo(el) { el.querySelectorAll('[data-go]').forEach(a => a.onclick = e => { e.preventDefault(); S.view = a.dataset.go; render(); }); }

function itemPagamento(p) {
  const st = statusPag(p), [y, m, dd] = p.vencimento.split('-');
  return `<div class="list-item">
    <div class="date-box ${st === 'atrasado' ? 'late' : ''}"><b>${dd}</b><span>${MESES[+m - 1]} ${y.slice(2)}</span></div>
    <div class="grow"><div class="t">${esc(fornNome(p.fornecedorId) || catNome(p.categoriaId))}</div>
      <div class="small muted">${esc(p.descricao || '')}${p.forma ? ' · ' + esc(p.forma) : ''}${st === 'atrasado' ? ' · <span style="color:var(--red)">atrasado</span>' : ''}${p.pago && p.pagoEm ? ' · pago em ' + fmtData(p.pagoEm) : ''}</div></div>
    <div class="num right"><b>${brl(p.valor)}</b></div>
    <label title="Marcar como pago" style="display:flex"><input type="checkbox" data-pago="${p.id}" ${p.pago ? 'checked' : ''}></label>
    <button class="btn ghost sm" data-editpag="${p.id}" title="Editar">✎</button>
  </div>`;
}
function ligarPagamentos(el) {
  el.querySelectorAll('[data-pago]').forEach(cb => cb.onchange = () => {
    const p = S.data.pagamentos.find(x => x.id === cb.dataset.pago);
    p.pago = cb.checked; p.pagoEm = cb.checked ? hojeISO() : '';
    salvar(cb.checked ? 'marca pagamento como pago' : 'desmarca pagamento'); render();
    toast(cb.checked ? 'Pagamento marcado como pago' : 'Pagamento voltou para pendente');
  });
  el.querySelectorAll('[data-editpag]').forEach(b => b.onclick = () => formPagamento(S.data.pagamentos.find(p => p.id === b.dataset.editpag)));
}

// --- Fornecedores ---
function vFornecedores(el) {
  const d = S.data;
  const filtros = [['ativos', 'Ativos'], ['todos', 'Todos'], ...STATUS];
  const q = S.busca.toLowerCase();
  const visivel = f => (S.filtroStatus === 'todos' || (S.filtroStatus === 'ativos' ? f.status !== 'descartado' : f.status === S.filtroStatus))
    && (!q || [f.nome, f.contato, f.obs, catNome(f.categoriaId)].join(' ').toLowerCase().includes(q));
  const grupos = d.categorias.map(c => ({ c, fs: d.fornecedores.filter(f => f.categoriaId === c.id && visivel(f)) })).filter(g => g.fs.length);
  el.innerHTML = `
    <div class="head"><h2>Fornecedores</h2><button class="btn primary" id="novo">+ Fornecedor</button></div>
    <div class="head">
      <div class="chips">${filtros.map(([k, l]) => `<button class="chip ${S.filtroStatus === k ? 'on' : ''}" data-f="${k}">${l}</button>`).join('')}</div>
      <input id="busca" placeholder="Buscar…" value="${esc(S.busca)}" style="max-width:220px">
    </div>
    ${grupos.length ? grupos.map(({ c, fs }) => `<div class="cat-group">
      <h3>${esc(c.nome)} <span class="small muted" style="font-family:Inter">previsto ${brl0(c.orcado)}</span></h3>
      <div class="card flush">${fs.map(cardFornecedor).join('')}</div>
    </div>`).join('') : '<div class="card empty">Nenhum fornecedor aqui ainda.</div>'}`;
  $('#novo').onclick = () => formFornecedor();
  el.querySelectorAll('[data-f]').forEach(b => b.onclick = () => { S.filtroStatus = b.dataset.f; render(); });
  const busca = $('#busca');
  busca.oninput = () => { S.busca = busca.value; const pos = busca.selectionStart; render(); const nb = $('#busca'); nb.focus(); nb.setSelectionRange(pos, pos); };
  el.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => formFornecedor(d.fornecedores.find(f => f.id === b.dataset.edit)));
  el.querySelectorAll('[data-parc]').forEach(b => b.onclick = () => formParcelas(d.fornecedores.find(f => f.id === b.dataset.parc)));
  el.querySelectorAll('[data-pagf]').forEach(b => b.onclick = () => formPagamento(null, d.fornecedores.find(f => f.id === b.dataset.pagf)));
}
function cardFornecedor(f) {
  const st = STATUS.find(s => s[0] === f.status);
  const pags = S.data.pagamentos.filter(p => p.fornecedorId === f.id);
  const pago = sum(pags.filter(p => p.pago).map(p => p.valor));
  const lancado = sum(pags.map(p => p.valor));
  const semParcela = f.status === 'fechado' ? r2(f.valorFechado - lancado) : 0;
  const link = f.link ? (/^https?:/.test(f.link) ? f.link : f.link.startsWith('@') ? 'https://instagram.com/' + f.link.slice(1) : 'https://' + f.link) : '';
  const tel = f.telefone ? f.telefone.replace(/\D/g, '') : '';
  return `<div class="forn ${f.status}">
    <div>
      <div class="nome">${esc(f.nome)} <span class="badge b-${f.status}">${st[1]}</span></div>
      <div class="meta">
        ${f.contato ? `<span>${esc(f.contato)}</span>` : ''}
        ${tel ? `<a href="https://wa.me/${tel.length <= 11 ? '55' + tel : tel}" target="_blank" rel="noopener">${esc(f.telefone)}</a>` : ''}
        ${f.email ? `<a href="mailto:${esc(f.email)}">${esc(f.email)}</a>` : ''}
        ${link ? `<a href="${esc(link)}" target="_blank" rel="noopener">${esc(f.link)}</a>` : ''}
        ${f.status === 'fechado' && f.dataFechamento ? `<span>fechado em ${fmtData(f.dataFechamento)}</span>` : ''}
      </div>
    </div>
    <div class="valores">
      ${f.status === 'fechado'
        ? `<div class="num"><b>${brl(f.valorFechado)}</b></div><div class="small muted num">pago ${brl(pago)}</div>`
        : f.valorOrcado ? `<div class="num">${brl(f.valorOrcado)}</div><div class="small muted">orçamento</div>` : '<div class="small muted">sem orçamento</div>'}
    </div>
    ${f.obs ? `<div class="obs">${esc(f.obs)}</div>` : ''}
    ${semParcela > 0.009 ? `<div class="obs" style="color:#87663a">${brl(semParcela)} ainda sem pagamento lançado.</div>` : ''}
    <div class="acts">
      <button class="btn ghost sm" data-edit="${f.id}">Editar</button>
      ${f.status === 'fechado' ? `<button class="btn ghost sm" data-parc="${f.id}">Gerar parcelas</button><button class="btn ghost sm" data-pagf="${f.id}">+ Pagamento</button>` : ''}
    </div>
  </div>`;
}

// --- Orçamento por categoria ---
function vOrcamento(el) {
  const t = totais();
  el.innerHTML = `
    <div class="head"><h2>Orçamento por categoria</h2><button class="btn primary" id="nova">+ Categoria</button></div>
    <p class="small muted" style="margin-top:-6px">"Previsto" é o quanto vocês querem gastar em cada item. Os valores iniciais são referência para cerca de 80 convidados em Florianópolis; ajuste à vontade.</p>
    <div class="card"><div class="table-wrap"><table>
      <thead><tr><th>Categoria</th><th class="right">Previsto</th><th class="right">Fechado</th><th class="right">Pago</th><th class="right">A pagar</th><th>Situação</th><th></th></tr></thead>
      <tbody>${t.cats.map(c => {
        const base = Math.max(c.orcado, c.comprometido) || 1;
        const over = c.comprometido > c.orcado && c.orcado > 0;
        return `<tr>
          <td><div style="font-weight:500">${esc(c.nome)}</div>
            <div class="bar" style="margin-top:6px;max-width:220px"><i class="pago" style="width:${c.pago / base * 100}%"></i><i class="${over ? 'over' : 'fech'}" style="width:${(c.comprometido - c.pago) / base * 100}%"></i></div></td>
          <td class="right num">${brl0(c.orcado)}</td>
          <td class="right num" style="${over ? 'color:var(--red)' : ''}">${c.comprometido ? brl0(c.comprometido) : '<span class="muted">-</span>'}</td>
          <td class="right num">${c.pago ? brl0(c.pago) : '<span class="muted">-</span>'}</td>
          <td class="right num">${c.aPagar ? brl0(c.aPagar) : '<span class="muted">-</span>'}</td>
          <td>${c.situacao === 'fechado' ? '<span class="badge b-fechado">Fechado</span>'
            : c.situacao === 'andamento' ? `<span class="badge b-negociando">${c.abertos} em análise</span>${c.menorCotacao ? `<div class="small muted num">menor: ${brl0(c.menorCotacao)}</div>` : ''}`
            : '<span class="badge b-pesquisando">Não iniciado</span>'}</td>
          <td class="right"><button class="btn ghost sm" data-cat="${c.id}">✎</button></td>
        </tr>`;
      }).join('')}
      <tr class="total"><td>Total</td><td class="right num">${brl0(t.orcado)}</td><td class="right num">${brl0(t.comprometido)}</td><td class="right num">${brl0(t.pago)}</td><td class="right num">${brl0(t.aPagar)}</td><td colspan="2" class="small muted">a contratar ${brl0(t.aContratar)}</td></tr>
      </tbody></table></div>
      <div class="legend" style="margin-top:14px"><span><i style="background:var(--sage)"></i>Pago</span><span><i style="background:#A9B9A1"></i>Fechado, a pagar</span><span><i style="background:var(--red)"></i>Acima do previsto</span></div>
    </div>`;
  $('#nova').onclick = () => formCategoria();
  el.querySelectorAll('[data-cat]').forEach(b => b.onclick = () => formCategoria(S.data.categorias.find(c => c.id === b.dataset.cat)));
}

// --- Pagamentos ---
function vPagamentos(el) {
  const filtros = [['pendentes', 'Pendentes'], ['atrasados', 'Atrasados'], ['pagos', 'Pagos'], ['todos', 'Todos']];
  let ps = [...S.data.pagamentos];
  if (S.filtroPag === 'pendentes') ps = ps.filter(p => !p.pago);
  if (S.filtroPag === 'atrasados') ps = ps.filter(p => statusPag(p) === 'atrasado');
  if (S.filtroPag === 'pagos') ps = ps.filter(p => p.pago);
  ps.sort((a, b) => S.filtroPag === 'pagos' ? b.vencimento.localeCompare(a.vencimento) : a.vencimento.localeCompare(b.vencimento));
  const grupos = {};
  for (const p of ps) (grupos[mesDe(p.vencimento)] ||= []).push(p);
  el.innerHTML = `
    <div class="head"><h2>Pagamentos</h2><button class="btn primary" id="novo">+ Pagamento</button></div>
    <div class="head"><div class="chips">${filtros.map(([k, l]) => `<button class="chip ${S.filtroPag === k ? 'on' : ''}" data-f="${k}">${l}</button>`).join('')}</div>
      <div class="small muted num">${ps.length} itens · ${brl(sum(ps.map(p => p.valor)))}</div></div>
    ${ps.length ? Object.entries(grupos).map(([m, l]) => `<div class="card">
      <div class="section-title"><h3 style="text-transform:capitalize">${fmtMesLongo(m)}</h3><span class="num muted">${brl(sum(l.map(p => p.valor)))}</span></div>
      ${l.map(itemPagamento).join('')}</div>`).join('')
      : `<div class="card empty">Nada por aqui. Ao fechar um fornecedor, use "Gerar parcelas" para lançar entrada e parcelas de uma vez.</div>`}`;
  $('#novo').onclick = () => formPagamento();
  el.querySelectorAll('[data-f]').forEach(b => b.onclick = () => { S.filtroPag = b.dataset.f; render(); });
  ligarPagamentos(el);
}

// --- Fluxo de caixa ---
function vFluxo(el) {
  const d = S.data, fl = fluxo(), t = totais();
  const totS = sum(fl.map(m => m.saidas)), totE = sum(fl.map(m => m.entradas));
  const final = fl.length ? fl[fl.length - 1].saldo : d.config.saldoAtual;
  const minimo = fl.reduce((a, m) => m.saldo < a.saldo ? m : a, fl[0] || { saldo: 0 });
  el.innerHTML = `
    <div class="head"><h2>Fluxo de caixa</h2>
      <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn" id="saldo">Saldo hoje: ${brl0(d.config.saldoAtual)}</button><button class="btn primary" id="nova">+ Entrada de dinheiro</button></div></div>
    <p class="small muted" style="margin-top:-6px">Projeção mês a mês: parte do que já está guardado hoje, soma as entradas previstas (poupança mensal, ajuda da família) e desconta os pagamentos pendentes. Pagamentos atrasados entram no mês atual.</p>
    <div class="grid kpis">
      <div class="card kpi"><div class="lbl">Saldo hoje</div><div class="val num">${brl0(d.config.saldoAtual)}</div></div>
      <div class="card kpi"><div class="lbl">Entradas previstas</div><div class="val num" style="color:var(--sage)">${brl0(totE)}</div></div>
      <div class="card kpi"><div class="lbl">Saídas previstas</div><div class="val num" style="color:var(--terra)">${brl0(totS)}</div></div>
      <div class="card kpi"><div class="lbl">Saldo no fim</div><div class="val num" style="color:${final < 0 ? 'var(--red)' : 'inherit'}">${brl0(final)}</div>
        <div class="det">${minimo && minimo.saldo < 0 ? `pior mês: ${fmtMes(minimo.mes)} (${brl0(minimo.saldo)})` : 'sem mês negativo'}</div></div>
    </div>
    ${t.aContratar ? `<div class="alert gold" style="margin-top:14px">Ainda faltam <b>${brl0(t.aContratar)}</b> em categorias sem fornecedor fechado. Esse valor ainda não está no fluxo; se tudo sair pelo previsto, o saldo final seria <b>${brl0(final - t.aContratar)}</b>.</div>` : ''}
    <div class="card" style="margin-top:14px">${graficoFluxo(fl)}
      <div class="legend" style="margin-top:6px"><span><i style="background:var(--sage)"></i>Entradas</span><span><i style="background:var(--terra)"></i>Saídas</span><span><i style="background:var(--ink);height:2px;vertical-align:3px"></i>Saldo acumulado</span></div></div>
    <div class="card"><div class="table-wrap"><table>
      <thead><tr><th>Mês</th><th class="right">Entradas</th><th class="right">Saídas</th><th class="right">Saldo</th><th>O que vence</th></tr></thead>
      <tbody>${fl.map(m => `<tr class="${m.saldo < 0 ? 'neg' : ''}">
        <td style="text-transform:capitalize;white-space:nowrap">${fmtMes(m.mes)}${m.mes === mesDe(d.config.data) ? ' ♥' : ''}</td>
        <td class="right num" style="color:var(--sage)">${m.entradas ? brl0(m.entradas) : '<span class="muted">-</span>'}</td>
        <td class="right num" style="color:var(--terra)">${m.saidas ? brl0(m.saidas) : '<span class="muted">-</span>'}</td>
        <td class="right num"><b>${brl0(m.saldo)}</b></td>
        <td class="small muted">${m.itensS.map(i => `${esc(i.desc)} (${brl0(i.valor)})${i.atrasado ? ' <span style="color:var(--red)">atrasado</span>' : ''}`).join('; ')}</td>
      </tr>`).join('')}</tbody></table></div></div>
    <div class="card">
      <div class="section-title"><h3>Entradas de dinheiro</h3></div>
      ${d.entradas.length ? d.entradas.map(e => `<div class="list-item">
        <div class="grow"><div class="t">${esc(e.descricao)}</div>
          <div class="small muted">${e.recorrente ? `todo mês, de ${fmtMes(mesDe(e.data))} a ${fmtMes(mesDe(e.ate || d.config.data))}` : `${fmtData(e.data)}${e.recebido ? ' · recebido' : ''}`}</div></div>
        <div class="num"><b>${brl(e.valor)}</b>${e.recorrente ? '<span class="small muted">/mês</span>' : ''}</div>
        <button class="btn ghost sm" data-ent="${e.id}">✎</button></div>`).join('')
      : '<div class="empty">Cadastre quanto vocês conseguem guardar por mês e outras entradas (ajuda da família, 13º, bônus).</div>'}
    </div>`;
  $('#nova').onclick = () => formEntrada();
  $('#saldo').onclick = formSaldo;
  el.querySelectorAll('[data-ent]').forEach(b => b.onclick = () => formEntrada(d.entradas.find(e => e.id === b.dataset.ent)));
}

function graficoFluxo(fl) {
  if (!fl.length) return '';
  const W = 760, H = 240, pl = 56, pr = 10, pt = 12, pb = 26;
  const vals = fl.flatMap(m => [m.entradas, m.saidas, m.saldo, 0]);
  let max = Math.max(...vals), min = Math.min(...vals);
  if (max === min) max = min + 1;
  const pad = (max - min) * .08; max += pad; if (min < 0) min -= pad;
  const y = v => pt + (max - v) / (max - min) * (H - pt - pb);
  const bw = (W - pl - pr) / fl.length;
  const bar = Math.max(2, Math.min(14, bw * .32));
  const ticks = 4, tk = [];
  for (let i = 0; i <= ticks; i++) tk.push(min + (max - min) * i / ticks);
  const k = v => Math.abs(v) >= 1000 ? (v / 1000).toFixed(Math.abs(v) >= 10000 ? 0 : 1).replace('.', ',') + 'k' : Math.round(v);
  const pts = fl.map((m, i) => `${pl + bw * i + bw / 2},${y(m.saldo)}`).join(' ');
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Gráfico do fluxo de caixa">
    ${tk.map(v => `<line x1="${pl}" x2="${W - pr}" y1="${y(v)}" y2="${y(v)}" stroke="#EEE8DE"/><text x="${pl - 6}" y="${y(v) + 4}" text-anchor="end">${k(v)}</text>`).join('')}
    <line x1="${pl}" x2="${W - pr}" y1="${y(0)}" y2="${y(0)}" stroke="#CFC6B6"/>
    ${fl.map((m, i) => {
      const x = pl + bw * i + bw / 2;
      return `${m.entradas ? `<rect x="${x - bar - 1}" y="${y(m.entradas)}" width="${bar}" height="${y(0) - y(m.entradas)}" rx="2" fill="#6F8466"><title>${fmtMes(m.mes)} entradas ${brl0(m.entradas)}</title></rect>` : ''}
        ${m.saidas ? `<rect x="${x + 1}" y="${y(m.saidas)}" width="${bar}" height="${y(0) - y(m.saidas)}" rx="2" fill="#B5694A"><title>${fmtMes(m.mes)} saídas ${brl0(m.saidas)}</title></rect>` : ''}
        ${fl.length <= 16 || i % 2 === 0 ? `<text x="${x}" y="${H - 8}" text-anchor="middle">${fmtMes(m.mes)}</text>` : ''}`;
    }).join('')}
    <polyline points="${pts}" fill="none" stroke="#2B2A28" stroke-width="2" stroke-linejoin="round"/>
    ${fl.map((m, i) => `<circle cx="${pl + bw * i + bw / 2}" cy="${y(m.saldo)}" r="3" fill="${m.saldo < 0 ? '#B23A3A' : '#2B2A28'}"><title>${fmtMes(m.mes)} saldo ${brl0(m.saldo)}</title></circle>`).join('')}
  </svg>`;
}

// --- Ajustes ---
function vAjustes(el) {
  const c = S.data.config;
  el.innerHTML = `
    <div class="head"><h2>Ajustes</h2><button class="btn" id="sair">Sair</button></div>
    <div class="grid two">
      <form class="card" id="fc">
        <h3 style="margin-bottom:12px">O casamento</h3>
        <label class="f"><span>Noivos</span><input name="noivos" value="${esc(c.noivos)}"></label>
        <div class="row">
          <label class="f"><span>Data</span><input type="date" name="data" value="${esc(c.data)}"></label>
          <label class="f"><span>Cidade</span><input name="cidade" value="${esc(c.cidade)}"></label>
        </div>
        <div class="row">
          <label class="f"><span>Convidados</span><input type="number" name="convidados" value="${c.convidados || ''}"></label>
          <label class="f"><span>Teto do orçamento (opcional)</span><input name="teto" inputmode="decimal" value="${valorInput(c.teto)}" placeholder="soma das categorias"></label>
        </div>
        <button class="btn primary">Salvar</button>
      </form>
      <div>
        <div class="card">
          <h3 style="margin-bottom:8px">Quem acessa</h3>
          ${S.vault.usuarios.map(u => `<div class="list-item"><div class="grow">${esc(u.nome)}${u.u === S.usuario ? ' <span class="small muted">(você)</span>' : ''}</div>
            ${u.u !== S.usuario ? `<button class="btn ghost sm danger" data-rm="${esc(u.u)}">Remover</button>` : ''}</div>`).join('')}
          <div class="actions" style="justify-content:flex-start"><button class="btn sm" id="addu">+ Pessoa</button><button class="btn sm" id="senha">Trocar minha senha</button>${CFG.local ? '' : '<button class="btn sm" id="tok">Atualizar token</button>'}</div>
        </div>
        <div class="card">
          <h3 style="margin-bottom:8px">Backup</h3>
          <p class="small muted" style="margin-top:0">Os dados já ficam salvos (cifrados) no GitHub a cada alteração. Este arquivo é uma cópia extra, legível, para guardar onde quiser.</p>
          <div class="actions" style="justify-content:flex-start"><button class="btn sm" id="exp">Baixar backup (.json)</button><label class="btn sm">Restaurar backup<input type="file" id="imp" accept=".json" class="hidden"></label></div>
        </div>
      </div>
    </div>`;
  $('#sair').onclick = sair;
  $('#fc').onsubmit = e => {
    e.preventDefault();
    const fd = Object.fromEntries(new FormData(e.target));
    Object.assign(c, { noivos: fd.noivos.trim(), data: fd.data, cidade: fd.cidade.trim(), convidados: +fd.convidados || 0, teto: parseValor(fd.teto) });
    salvar('ajustes do casamento'); render(); toast('Salvo');
  };
  $('#addu').onclick = formUsuario;
  $('#senha').onclick = formSenha;
  if ($('#tok')) $('#tok').onclick = formToken;
  el.querySelectorAll('[data-rm]').forEach(b => b.onclick = async () => {
    if (!confirm('Remover o acesso de ' + b.dataset.rm + '?')) return;
    S.vault.usuarios = S.vault.usuarios.filter(u => u.u !== b.dataset.rm);
    try { await salvarVault('remove acesso'); toast('Acesso removido'); render(); } catch (er) { toast(er.message, true); }
  });
  $('#exp').onclick = () => {
    const blob = new Blob([JSON.stringify(S.data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `casamento-backup-${hojeISO()}.json`; a.click();
  };
  $('#imp').onchange = async e => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const novo = JSON.parse(await f.text());
      if (!novo.categorias || !novo.fornecedores) throw new Error('Arquivo não parece um backup deste sistema.');
      if (!confirm('Substituir TODOS os dados atuais pelo backup?')) return;
      S.data = novo; await salvar('restaura backup'); render(); toast('Backup restaurado');
    } catch (er) { toast(er.message, true); }
  };
}

// ---------- formulários ----------
function modal(html, onSubmit, onDelete) {
  const m = $('#modal');
  m.innerHTML = `<form>${html}<div class="actions">${onDelete ? '<button type="button" class="btn danger left" data-del>Excluir</button>' : ''}<button type="button" class="btn" data-x>Cancelar</button><button class="btn primary">Salvar</button></div></form>`;
  const form = $('form', m);
  m.showModal();
  form.querySelector('[data-x]').onclick = () => m.close();
  if (onDelete) form.querySelector('[data-del]').onclick = () => { if (confirm('Excluir mesmo?')) { onDelete(); m.close(); } };
  form.onsubmit = e => {
    e.preventDefault();
    const fd = {}; for (const [k, v] of new FormData(form)) fd[k] = v;
    form.querySelectorAll('input[type=checkbox]').forEach(cb => fd[cb.name] = cb.checked);
    if (onSubmit(fd, form) !== false) m.close();
  };
  return form;
}
const optCats = sel => S.data.categorias.map(c => `<option value="${c.id}" ${c.id === sel ? 'selected' : ''}>${esc(c.nome)}</option>`).join('');
const optFormas = sel => `<option value="">-</option>` + FORMAS.map(f => `<option ${f === sel ? 'selected' : ''}>${f}</option>`).join('');

function formFornecedor(f) {
  const novo = !f;
  f = f || { categoriaId: S.data.categorias[0]?.id, status: 'pesquisando' };
  const form = modal(`
    <h2>${novo ? 'Novo fornecedor' : 'Editar fornecedor'}</h2>
    <label class="f"><span>Nome</span><input name="nome" required value="${esc(f.nome)}"></label>
    <div class="row">
      <label class="f"><span>Categoria</span><select name="categoriaId">${optCats(f.categoriaId)}</select></label>
      <label class="f"><span>Situação</span><select name="status">${STATUS.map(([k, l]) => `<option value="${k}" ${k === f.status ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
    </div>
    <div class="row">
      <label class="f"><span>Contato (pessoa)</span><input name="contato" value="${esc(f.contato)}"></label>
      <label class="f"><span>Telefone / WhatsApp</span><input name="telefone" inputmode="tel" value="${esc(f.telefone)}"></label>
    </div>
    <div class="row">
      <label class="f"><span>E-mail</span><input name="email" type="email" value="${esc(f.email)}"></label>
      <label class="f"><span>Instagram ou site</span><input name="link" value="${esc(f.link)}" placeholder="@perfil ou site.com"></label>
    </div>
    <div class="row">
      <label class="f"><span>Valor do orçamento (R$)</span><input name="valorOrcado" inputmode="decimal" value="${valorInput(f.valorOrcado)}"></label>
      <label class="f fech"><span>Valor fechado (R$)</span><input name="valorFechado" inputmode="decimal" value="${valorInput(f.valorFechado)}"></label>
    </div>
    <label class="f fech"><span>Data do fechamento</span><input name="dataFechamento" type="date" value="${esc(f.dataFechamento)}"></label>
    <label class="f"><span>Observações</span><textarea name="obs">${esc(f.obs)}</textarea></label>`,
    fd => {
      const v = {
        nome: fd.nome.trim(), categoriaId: fd.categoriaId, status: fd.status, contato: fd.contato.trim(), telefone: fd.telefone.trim(),
        email: fd.email.trim(), link: fd.link.trim(), valorOrcado: parseValor(fd.valorOrcado), valorFechado: parseValor(fd.valorFechado),
        dataFechamento: fd.dataFechamento, obs: fd.obs.trim(),
      };
      if (v.status === 'fechado' && !v.valorFechado) v.valorFechado = v.valorOrcado;
      if (v.status === 'fechado' && !v.dataFechamento) v.dataFechamento = hojeISO();
      const virouFechado = v.status === 'fechado' && f.status !== 'fechado';
      let alvo;
      if (novo) { alvo = { id: uid(), ...v }; S.data.fornecedores.push(alvo); }
      else { alvo = Object.assign(f, v); S.data.pagamentos.filter(p => p.fornecedorId === f.id).forEach(p => p.categoriaId = v.categoriaId); }
      salvar(novo ? 'novo fornecedor' : 'edita fornecedor'); render();
      if (virouFechado && !S.data.pagamentos.some(p => p.fornecedorId === alvo.id)) setTimeout(() => formParcelas(alvo), 50);
    },
    novo ? null : () => {
      const n = S.data.pagamentos.filter(p => p.fornecedorId === f.id).length;
      if (n && !confirm(`Este fornecedor tem ${n} pagamento(s) lançado(s), que também serão excluídos. Continuar?`)) return;
      S.data.fornecedores = S.data.fornecedores.filter(x => x.id !== f.id);
      S.data.pagamentos = S.data.pagamentos.filter(p => p.fornecedorId !== f.id);
      salvar('exclui fornecedor'); render();
    });
  const st = form.querySelector('[name=status]');
  const sync = () => form.querySelectorAll('.fech').forEach(x => x.classList.toggle('hidden', st.value !== 'fechado'));
  st.onchange = sync; sync();
}

function formParcelas(f) {
  const lancado = sum(S.data.pagamentos.filter(p => p.fornecedorId === f.id).map(p => p.valor));
  const restante = r2(Math.max(0, f.valorFechado - lancado));
  const form = modal(`
    <h2>Gerar parcelas</h2>
    <p class="muted" style="margin-top:-6px">${esc(f.nome)} · fechado em ${brl(f.valorFechado)}${lancado ? ` · já lançado ${brl(lancado)}` : ''}</p>
    <label class="f"><span>Total a parcelar (R$)</span><input name="total" inputmode="decimal" required value="${valorInput(restante)}"></label>
    <div class="row3">
      <label class="f"><span>Entrada (R$)</span><input name="entrada" inputmode="decimal" placeholder="0"></label>
      <label class="f"><span>Data da entrada</span><input name="dataEntrada" type="date" value="${hojeISO()}"></label>
      <label class="f"><span>Forma</span><select name="formaEntrada">${optFormas('')}</select></label>
    </div>
    <div class="row" id="cartaoE">
      <label class="f"><span>Entrada em quantas vezes no cartão</span><input name="nCartaoE" type="number" min="1" value="1"></label>
      <label class="f"><span>Vencimento da 1ª fatura</span><input name="faturaE" type="date" value="${addMeses(hojeISO(), 1)}"></label>
    </div>
    <div class="row3">
      <label class="f"><span>Nº de parcelas</span><input name="n" type="number" min="0" value="1"></label>
      <label class="f"><span>1ª parcela</span><input name="primeira" type="date" value="${addMeses(hojeISO(), 1)}"></label>
      <label class="f"><span>Forma</span><select name="forma">${optFormas('')}</select></label>
    </div>
    <p class="hint">As parcelas são mensais, no mesmo dia. Dá para editar cada uma depois (valor, data) na aba Pagamentos.</p>
    <div class="alert green" id="prev"></div>`,
    fd => {
      const pags = calcParcelas(fd);
      if (!pags.length) { toast('Nada para lançar', true); return false; }
      for (const p of pags) S.data.pagamentos.push({ id: uid(), fornecedorId: f.id, categoriaId: f.categoriaId, pago: false, pagoEm: '', ...p });
      salvar(`lança ${pags.length} pagamento(s)`); render(); toast(`${pags.length} pagamento(s) lançado(s)`);
    });
  const prev = () => {
    const fd = Object.fromEntries(new FormData(form));
    $('#cartaoE').classList.toggle('hidden', fd.formaEntrada !== CARTAO);
    const ps = calcParcelas(fd);
    $('#prev').innerHTML = ps.length ? ps.map(p => `${fmtData(p.vencimento)} · ${esc(p.descricao)} · <b class="num">${brl(p.valor)}</b>`).join('<br>') : 'Preencha total e parcelas.';
  };
  form.oninput = prev; prev();
}
// divide em n valores com centavos exatos (a última parcela absorve a sobra)
function dividir(total, n) {
  const base = Math.floor(total / n * 100) / 100;
  return Array.from({ length: n }, (_, i) => i === n - 1 ? r2(total - base * (n - 1)) : base);
}
// compra no cartão parcelada: uma saída por fatura, mês a mês
function faturasCartao(valor, n, primeiraFatura, descricao) {
  return dividir(valor, n).map((v, i) => ({ descricao: `${descricao} · cartão ${i + 1}/${n}`, valor: v, vencimento: addMeses(primeiraFatura, i), forma: CARTAO }));
}
function calcParcelas(fd) {
  const total = parseValor(fd.total), entrada = Math.min(parseValor(fd.entrada), total), n = Math.max(0, parseInt(fd.n) || 0);
  const out = [];
  if (entrada > 0) {
    const nc = parseInt(fd.nCartaoE) || 1;
    if (fd.formaEntrada === CARTAO && nc > 1 && fd.faturaE) out.push(...faturasCartao(entrada, nc, fd.faturaE, 'Entrada'));
    else out.push({ descricao: 'Entrada', valor: entrada, vencimento: fd.dataEntrada || hojeISO(), forma: fd.formaEntrada });
  }
  const resto = r2(total - entrada);
  if (n > 0 && resto > 0 && fd.primeira) {
    dividir(resto, n).forEach((valor, i) =>
      out.push({ descricao: n === 1 ? (entrada ? 'Saldo' : 'Pagamento único') : `Parcela ${i + 1}/${n}`, valor, vencimento: addMeses(fd.primeira, i), forma: fd.forma }));
  }
  return out;
}

function formPagamento(p, fornecedor) {
  const novo = !p;
  p = p || { fornecedorId: fornecedor?.id || '', categoriaId: fornecedor?.categoriaId || S.data.categorias[0]?.id, vencimento: hojeISO(), pago: false };
  const fechados = S.data.fornecedores.filter(f => f.status === 'fechado' || f.id === p.fornecedorId);
  const form = modal(`
    <h2>${novo ? 'Novo pagamento' : 'Editar pagamento'}</h2>
    <label class="f"><span>Fornecedor</span><select name="fornecedorId"><option value="">Sem fornecedor (despesa avulsa)</option>
      ${fechados.map(f => `<option value="${f.id}" ${f.id === p.fornecedorId ? 'selected' : ''}>${esc(f.nome)}</option>`).join('')}</select></label>
    <label class="f" id="lcat"><span>Categoria</span><select name="categoriaId">${optCats(p.categoriaId)}</select></label>
    <label class="f"><span>Descrição</span><input name="descricao" value="${esc(p.descricao)}" placeholder="Ex.: Entrada, Parcela 2/5, Prova do vestido"></label>
    <div class="row3">
      <label class="f"><span>Valor (R$)</span><input name="valor" inputmode="decimal" required value="${valorInput(p.valor)}"></label>
      <label class="f"><span>Vencimento</span><input name="vencimento" type="date" required value="${esc(p.vencimento)}"></label>
      <label class="f"><span>Forma</span><select name="forma">${optFormas(p.forma)}</select></label>
    </div>
    ${novo ? `<div class="row" id="lcartao">
      <label class="f"><span>Em quantas vezes no cartão</span><input name="nCartao" type="number" min="1" value="1"></label>
      <label class="f"><span>Vencimento da 1ª fatura</span><input name="fatura" type="date" value="${addMeses(hojeISO(), 1)}"></label>
    </div>
    <div class="alert green hidden" id="prevCartao"></div>` : ''}
    <div class="row" id="lpago">
      <label class="f" style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="pago" ${p.pago ? 'checked' : ''}> Já pago</label>
      <label class="f"><span>Pago em</span><input name="pagoEm" type="date" value="${esc(p.pagoEm)}"></label>
    </div>`,
    fd => {
      const forn = S.data.fornecedores.find(f => f.id === fd.fornecedorId);
      const v = {
        fornecedorId: fd.fornecedorId || null, categoriaId: forn ? forn.categoriaId : fd.categoriaId, descricao: fd.descricao.trim(),
        valor: parseValor(fd.valor), vencimento: fd.vencimento, forma: fd.forma, pago: fd.pago, pagoEm: fd.pago ? (fd.pagoEm || hojeISO()) : '',
      };
      if (!v.valor) { toast('Informe o valor', true); return false; }
      const nc = parseInt(fd.nCartao) || 1;
      if (novo && v.forma === CARTAO && nc > 1) {
        if (!fd.fatura) { toast('Informe o vencimento da 1ª fatura', true); return false; }
        const fats = faturasCartao(v.valor, nc, fd.fatura, v.descricao || 'Compra');
        for (const f of fats) S.data.pagamentos.push({ id: uid(), ...v, ...f, pago: false, pagoEm: '' });
        salvar(`lança compra em ${nc}x no cartão`); render(); toast(`${nc} faturas lançadas`);
        return;
      }
      if (novo) S.data.pagamentos.push({ id: uid(), ...v }); else Object.assign(p, v);
      salvar(novo ? 'novo pagamento' : 'edita pagamento'); render();
    },
    novo ? null : () => { S.data.pagamentos = S.data.pagamentos.filter(x => x.id !== p.id); salvar('exclui pagamento'); render(); });
  const sel = form.querySelector('[name=fornecedorId]');
  const sync = () => {
    $('#lcat').classList.toggle('hidden', !!sel.value);
    if (!novo) return;
    const fd = Object.fromEntries(new FormData(form));
    const cartao = fd.forma === CARTAO, nc = parseInt(fd.nCartao) || 1, emVezes = cartao && nc > 1;
    $('#lcartao').classList.toggle('hidden', !cartao);
    $('#lpago').classList.toggle('hidden', emVezes);
    // com parcelamento no cartão, o vencimento que vale é o das faturas
    form.querySelector('[name=vencimento]').closest('label').classList.toggle('hidden', emVezes);
    form.querySelector('[name=vencimento]').required = !emVezes;
    const pv = $('#prevCartao'), valor = parseValor(fd.valor);
    pv.classList.toggle('hidden', !(emVezes && valor && fd.fatura));
    if (emVezes && valor && fd.fatura) pv.innerHTML = `${nc} faturas de <b class="num">${brl(dividir(valor, nc)[0])}</b>, de ${fmtMes(mesDe(fd.fatura))} a ${fmtMes(mesDe(addMeses(fd.fatura, nc - 1)))}`;
  };
  form.oninput = sync; sel.onchange = sync; sync();
}

function formCategoria(c) {
  const novo = !c; c = c || {};
  modal(`
    <h2>${novo ? 'Nova categoria' : 'Editar categoria'}</h2>
    <label class="f"><span>Nome</span><input name="nome" required value="${esc(c.nome)}"></label>
    <label class="f"><span>Valor previsto (R$)</span><input name="orcado" inputmode="decimal" value="${valorInput(c.orcado)}"></label>`,
    fd => {
      const v = { nome: fd.nome.trim(), orcado: parseValor(fd.orcado) };
      if (novo) S.data.categorias.push({ id: uid(), ...v }); else Object.assign(c, v);
      salvar(novo ? 'nova categoria' : 'edita categoria'); render();
    },
    novo ? null : () => {
      if (S.data.fornecedores.some(f => f.categoriaId === c.id) || S.data.pagamentos.some(p => p.categoriaId === c.id)) {
        toast('Essa categoria tem fornecedores ou pagamentos. Mova-os antes de excluir.', true); return;
      }
      S.data.categorias = S.data.categorias.filter(x => x.id !== c.id); salvar('exclui categoria'); render();
    });
}

function formEntrada(e) {
  const novo = !e; e = e || { data: hojeISO(), recorrente: true };
  const form = modal(`
    <h2>${novo ? 'Nova entrada de dinheiro' : 'Editar entrada'}</h2>
    <label class="f"><span>Descrição</span><input name="descricao" required value="${esc(e.descricao)}" placeholder="Ex.: Poupança mensal, Ajuda dos pais"></label>
    <div class="row">
      <label class="f"><span>Valor (R$)</span><input name="valor" inputmode="decimal" required value="${valorInput(e.valor)}"></label>
      <label class="f"><span id="ldata">Data</span><input name="data" type="date" required value="${esc(e.data)}"></label>
    </div>
    <label class="f" style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="recorrente" ${e.recorrente ? 'checked' : ''}> Repete todo mês</label>
    <label class="f" id="late"><span>Até (deixe vazio para ir até o casamento)</span><input name="ate" type="date" value="${esc(e.ate)}"></label>
    <label class="f" id="lrec" style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="recebido" ${e.recebido ? 'checked' : ''}> Já recebido (já está no saldo de hoje)</label>`,
    fd => {
      const v = { descricao: fd.descricao.trim(), valor: parseValor(fd.valor), data: fd.data, recorrente: fd.recorrente, ate: fd.recorrente ? fd.ate : '', recebido: !fd.recorrente && fd.recebido };
      if (novo) S.data.entradas.push({ id: uid(), ...v }); else Object.assign(e, v);
      salvar(novo ? 'nova entrada' : 'edita entrada'); render();
    },
    novo ? null : () => { S.data.entradas = S.data.entradas.filter(x => x.id !== e.id); salvar('exclui entrada'); render(); });
  const rec = form.querySelector('[name=recorrente]');
  const sync = () => { $('#late').classList.toggle('hidden', !rec.checked); $('#lrec').classList.toggle('hidden', rec.checked); $('#ldata').textContent = rec.checked ? 'A partir de' : 'Data'; };
  rec.onchange = sync; sync();
}

function formSaldo() {
  modal(`
    <h2>Saldo de hoje</h2>
    <label class="f"><span>Quanto vocês já têm guardado para o casamento (R$)</span><input name="saldo" inputmode="decimal" value="${valorInput(S.data.config.saldoAtual)}" autofocus></label>
    <p class="hint">É o ponto de partida do fluxo. Atualize de vez em quando com o valor real da conta.</p>`,
    fd => { S.data.config.saldoAtual = parseValor(fd.saldo); salvar('atualiza saldo'); render(); });
}

function formUsuario() {
  modal(`
    <h2>Dar acesso a outra pessoa</h2>
    <label class="f"><span>Usuário</span><input name="u" required autocomplete="off"></label>
    <label class="f"><span>Senha (mínimo 10 caracteres)</span><input name="s" type="password" minlength="10" required autocomplete="new-password"></label>
    <p class="hint">Passe usuário e senha pessoalmente. A pessoa pode trocar a senha depois em Ajustes.</p>`,
    async fd => {
      const u = fd.u.toLowerCase().trim();
      if (S.vault.usuarios.some(x => x.u === u)) { toast('Esse usuário já existe', true); return; }
      S.vault.usuarios.push(await embrulharParaUsuario(fd.u, fd.s, S.dekRaw));
      try { await salvarVault('novo acesso'); toast('Acesso criado'); render(); } catch (er) { toast(er.message, true); }
    });
}

function formSenha() {
  modal(`
    <h2>Trocar minha senha</h2>
    <label class="f"><span>Nova senha (mínimo 10 caracteres)</span><input name="s" type="password" minlength="10" required autocomplete="new-password"></label>
    <label class="f"><span>Repita</span><input name="s2" type="password" required autocomplete="new-password"></label>`,
    fd => {
      if (fd.s !== fd.s2) { toast('As senhas não conferem', true); return false; }
      (async () => {
        const i = S.vault.usuarios.findIndex(x => x.u === S.usuario);
        const nome = S.vault.usuarios[i].nome;
        S.vault.usuarios[i] = await embrulharParaUsuario(nome, fd.s, S.dekRaw);
        try { await salvarVault('troca senha'); toast('Senha trocada'); } catch (er) { toast(er.message, true); }
      })();
    });
}

function formToken() {
  modal(`
    <h2>Atualizar token do GitHub</h2>
    <label class="f"><span>Novo token (fine-grained, Contents: read and write neste repositório)</span><input name="t" required autocomplete="off" spellcheck="false"></label>`,
    fd => {
      (async () => {
        const token = fd.t.trim();
        const r = await fetch(`https://api.github.com/repos/${CFG.owner}/${CFG.repo}`, { headers: { Authorization: 'Bearer ' + token } });
        if (!r.ok || !(await r.json()).permissions?.push) { toast('Token sem acesso de escrita ao repositório', true); return; }
        S.token = token; S.vault.token = await cifrar(S.dek, enc.encode(token));
        try { await salvarVault('atualiza token'); toast('Token atualizado'); } catch (er) { toast(er.message, true); }
      })();
    });
}

// ---------- início ----------
(async function init() {
  $('#app').innerHTML = '<div class="login-wrap"><div class="muted">Carregando…</div></div>';
  try {
    await carregarVault();
    const ses = JSON.parse(sessionStorage.getItem('casamento.sessao') || 'null');
    if (ses && S.vault) {
      try { await abrirSessao(ses.u, unb64(ses.k)); } catch { sessionStorage.removeItem('casamento.sessao'); S.dek = null; }
    }
    render();
  } catch (e) {
    $('#app').innerHTML = `<div class="login-wrap"><div class="card" style="max-width:420px">Não consegui carregar: ${esc(e.message)}<br><br><button class="btn" onclick="location.reload()">Tentar de novo</button></div></div>`;
  }
})();
