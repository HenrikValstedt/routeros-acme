let S = {certs: [], routers: [], settings: {}, mail: {}}, tab = 'certs', me = null, users = [], invites = [], timer, resetEnabled = false, linkToken = '';
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = t => t ? new Date(t).toLocaleString() : '—';
const hasT = t => t && !t.startsWith('0001');
const isAdmin = () => me?.role === 'admin';

function toast(msg, bad) {
  const t = $('#toast'); t.textContent = msg; t.style.background = bad ? 'var(--err)' : ''; t.style.display = 'block';
  clearTimeout(t._h); t._h = setTimeout(() => t.style.display = 'none', bad ? 6000 : 2500);
}
async function api(method, path, body, retried, raw) {
  const o = {method, headers: {}, credentials: 'same-origin'};
  if (method !== 'GET') { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(body ?? {}); }
  const r = await fetch(path.replace(/^\//, ''), o); // relative: works when served under a sub-path
  if (r.status === 401 && me) { showAuth('login'); throw new Error('Session expired, please sign in'); }
  if (!r.ok) {
    const msg = (await r.text()).trim() || r.statusText;
    // sensitive action: ask for a fresh 2FA code, then repeat the request once
    if (r.status === 403 && msg.startsWith('otp_required') && !retried) {
      if (await askOTP()) return api(method, path, body, true, raw);
      throw new Error('Cancelled – the change was not made');
    }
    if (r.status === 403 && msg.startsWith('mfa_setup_required')) { boot(); throw new Error('Set up two-factor authentication first'); }
    throw new Error(msg.replace(/^(otp_required|mfa_setup_required): /, ''));
  }
  return raw ? r : r.json();
}
// download a file the server sends back (as an attachment) from a POST
async function download(path, body) {
  const r = await api('POST', path, body, false, true);
  const name = (r.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'download';
  const url = URL.createObjectURL(await r.blob()), a = document.createElement('a');
  a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  return name;
}
async function act(method, path, msg, body) {
  try { await api(method, path, body); if (msg) toast(msg); await refresh(); return true; }
  catch (e) { toast(e.message, true); return false; }
}

// ---------- auth ----------
async function boot() {
  // e-mailed links: #invite=<token> or #reset=<token> (fragment never reaches server logs)
  const m = location.hash.match(/^#(invite|reset)=([\w-]+)$/);
  if (m) { linkToken = m[2]; history.replaceState(null, '', location.pathname + location.search); }
  try {
    const s = await api('GET', '/api/session');
    resetEnabled = s.resetEnabled;
    passkey = {...(s.passkey || {}), browser: !!(window.PublicKeyCredential && window.isSecureContext)};
    if (m && m[1] === 'reset') return showAuth('reset');
    if (m && m[1] === 'invite') {
      try {
        const inv = await api('POST', '/api/invite/check', {token: linkToken});
        $('#inviteInfo').innerHTML = `You were invited as <b>${esc(inv.role)}</b> (${esc(inv.email)}). Choose a username and password.`;
        return showAuth('invite');
      } catch (e) { toast(e.message, true); }
    }
    if (s.mfaPending) return showAuth('otp');
    if (s.user && s.mfaSetupRequired) return startMfaSetup(s.user, true);
    if (s.user) return startApp(s.user);
    showAuth(s.setupRequired ? 'setup' : 'login');
  } catch (e) { toast(e.message, true); }
}
function showAuth(mode = 'login') {
  clearTimeout(timer); me = null;
  document.querySelectorAll('dialog').forEach(d => d.open && d.close());
  $('#app').hidden = true; $('#auth').hidden = false;
  const forms = {setup: '#setupForm', login: '#loginForm', forgot: '#forgotForm', reset: '#resetForm', invite: '#inviteForm',
    otp: '#otpForm', mfa: '#mfaForm'};
  for (const [k, sel] of Object.entries(forms)) $(sel).hidden = k !== mode;
  $('#forgotLink').hidden = !resetEnabled;
  $('#pkLoginBox').hidden = !(passkey.available && passkey.browser) || mode !== 'login';
  const f = $(forms[mode]);
  f.querySelector('.err-box').textContent = '';
  f.querySelector('input:not([type=hidden])')?.focus();
}
function startApp(user) {
  me = user;
  document.body.classList.toggle('viewer', !isAdmin());
  $('#meBtn').innerHTML = `<span class="av">${esc(me.username[0])}</span><span class="nm">${esc(me.username)}</span><span class="badge ${me.role}">${me.role}</span>`;
  $('#setFs').disabled = $('#mailFs').disabled = !isAdmin(); $('#roNote').hidden = isAdmin();
  $('#auth').hidden = true; $('#app').hidden = false;
  if (tab === 'users' && !isAdmin()) tab = 'certs';
  selectTab(tab);
  loop();
}
// helper: submit an auth form, show errors inline
function authSubmit(sel, fn) {
  $(sel).onsubmit = async e => {
    e.preventDefault(); const f = e.target, eb = f.querySelector('.err-box'); eb.textContent = '';
    if (f.password2 && f.password.value !== f.password2.value) { eb.textContent = 'Passwords do not match'; return; }
    try { await fn(f); } catch (err) { eb.textContent = err.message; }
  };
}
authSubmit('#loginForm', async f => {
  const r = await api('POST', '/api/login', {username: f.username.value, password: f.password.value});
  f.password.value = '';
  if (r.mfa) { showAuth('otp'); return; }
  boot();
});
authSubmit('#otpForm', async f => {
  const r = await api('POST', '/api/login/otp', {code: f.code.value});
  f.reset();
  if (r.usedRecovery) toast(`Signed in with a recovery code. ${r.user.recoveryLeft} left – make new ones under My account.`, r.user.recoveryLeft < 3);
  boot();
});
authSubmit('#setupForm', async f => {
  await api('POST', '/api/setup', {code: f.code.value, username: f.username.value, email: f.email.value, password: f.password.value});
  f.reset(); boot();
});
authSubmit('#inviteForm', async f => {
  const u = await api('POST', '/api/invite/accept', {token: linkToken, username: f.username.value, password: f.password.value});
  f.reset(); linkToken = ''; toast('Welcome, ' + u.username + '!'); boot();
});

// ---------- two-factor authentication ----------
let mfaRequired = false;
async function startMfaSetup(user, required) {
  mfaRequired = required;
  showAuth('mfa');
  $('#mfaWhy').innerHTML = required
    ? (user.role === 'admin'
      ? 'Admins need a second step when signing in, because they control routers, DNS and other users. Set it up once to continue.'
      : 'Your organisation requires a second step when signing in. Set it up once to continue.')
    : 'After a password, sign-in will also ask for a code from your phone.';
  $('#mfaCancel').textContent = required ? 'Sign out' : 'Cancel';
  $('#mfaQr').innerHTML = ''; $('#mfaKey').textContent = '…';
  try {
    const r = await api('POST', '/api/me/2fa/setup');
    $('#mfaQr').innerHTML = r.qr;   // SVG generated by the server
    $('#mfaKey').textContent = r.secret.match(/.{1,4}/g).join(' ');
  } catch (e) { $('#mfaForm .err-box').textContent = e.message; }
  $('#mfaCode').focus();
}
$('#mfaCancel').onclick = () => mfaRequired ? logout() : boot();
$('#mfaKeyCopy').onclick = e => { e.preventDefault(); copyText($('#mfaKey').textContent.replace(/ /g, ''), 'Key copied'); };
authSubmit('#mfaForm', async f => {
  const r = await api('POST', '/api/me/2fa/enable', {code: f.code.value});
  f.reset();
  showRecovery(r.recovery, () => { toast('Two-factor authentication is on'); boot(); });
});
function copyText(text, msg) {
  navigator.clipboard?.writeText(text).then(() => toast(msg), () => toast('Select the text and copy it', true));
}
function showRecovery(codes, done) {
  $('#recList').innerHTML = codes.map(c => `<span>${esc(c)}</span>`).join('');
  $('#recSaved').checked = false; $('#recDone').disabled = true;
  const text = 'RouterOS ACME recovery codes (each works once)\n\n' + codes.join('\n') + '\n';
  $('#recCopy').onclick = () => copyText(text, 'Recovery codes copied');
  $('#recDl').onclick = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], {type: 'text/plain'}));
    a.download = 'routeros-acme-recovery-codes.txt'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  $('#recForm').onsubmit = e => { e.preventDefault(); recDlg.close(); done && done(); };
  recDlg.showModal();
}
$('#recSaved').onchange = e => { $('#recDone').disabled = !e.target.checked; };
recDlg.addEventListener('cancel', e => e.preventDefault()); // codes must be acknowledged

// Code prompt. submit(code) must throw on a wrong code; resolves true when it succeeded.
function askCode({title = "Confirm it's you", hint = 'This change needs a fresh code from your authenticator app.', submit, viaPasskey}) {
  return new Promise(resolve => {
    const f = $('#otpDlgForm'), eb = f.querySelector('.err-box');
    $('#otpDlgTitle').textContent = title; $('#otpDlgHint').textContent = hint;
    f.reset(); eb.textContent = '';
    const finish = ok => { otpDlg.close(); resolve(ok); };
    const pk = $('#otpDlgPasskey');
    pk.hidden = !viaPasskey;
    pk.onclick = async () => {
      eb.textContent = '';
      try { await viaPasskey(); finish(true); } catch (err) { eb.textContent = err.message; }
    };
    f.onsubmit = async e => {
      e.preventDefault(); eb.textContent = '';
      try { await submit(f.code.value); finish(true); }
      catch (err) { eb.textContent = err.message; f.code.select(); }
    };
    $('#otpDlgCancel').onclick = () => finish(false);
    otpDlg.oncancel = e => { e.preventDefault(); finish(false); };
    otpDlg.showModal(); $('#otpDlgCode').focus();
  });
}
const hasPasskeyHere = () => passkey.available && passkey.browser && (S.myPasskeys || []).some(p => p.rpId === passkey.rpId);
const askOTP = () => askCode({submit: code => api('POST', '/api/me/2fa/verify', {code}, true),
  hint: hasPasskeyHere() ? 'This change needs a fresh code from your authenticator app, or your passkey.' : undefined,
  viaPasskey: hasPasskeyHere() ? () => passkeyCeremony('get', '/api/me/2fa/passkey') : null});

// ---------- passkeys (WebAuthn) ----------
let passkey = {};
const b64u = {
  enc: buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0)),
};
function credToJSON(c) {
  const r = c.response, out = {id: c.id, rawId: b64u.enc(c.rawId), type: c.type,
    authenticatorAttachment: c.authenticatorAttachment || undefined,
    clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
    response: {clientDataJSON: b64u.enc(r.clientDataJSON)}};
  if (r.attestationObject) {
    out.response.attestationObject = b64u.enc(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports();
  } else {
    out.response.authenticatorData = b64u.enc(r.authenticatorData);
    out.response.signature = b64u.enc(r.signature);
    if (r.userHandle) out.response.userHandle = b64u.enc(r.userHandle);
  }
  return out;
}
// passkeyCeremony runs begin -> browser prompt -> finish. kind: 'create' (add) or 'get' (sign in / confirm).
async function passkeyCeremony(kind, base, body) {
  const b = await api('POST', base + '/begin', body);
  const o = b.options.publicKey;
  o.challenge = b64u.dec(o.challenge);
  if (o.user) o.user.id = b64u.dec(o.user.id);
  for (const c of [...(o.excludeCredentials || []), ...(o.allowCredentials || [])]) c.id = b64u.dec(c.id);
  let cred;
  try { cred = kind === 'create' ? await navigator.credentials.create({publicKey: o}) : await navigator.credentials.get({publicKey: o}); }
  catch (e) {
    if (e.name === 'NotAllowedError') throw new Error('Cancelled, or no passkey was chosen');
    if (e.name === 'InvalidStateError') throw new Error('This device already has a passkey for your account');
    throw new Error(e.message || 'The passkey prompt failed');
  }
  return api('POST', `${base}/finish?c=${encodeURIComponent(b.ceremony)}`, credToJSON(cred), true);
}
$('#pkLogin').onclick = async () => {
  const eb = $('#loginForm .err-box'); eb.textContent = '';
  try { await passkeyCeremony('get', '/api/passkey/login'); boot(); }
  catch (e) { eb.textContent = e.message; }
};
function renderPasskeys(box) {
  const list = S.myPasskeys || [];
  const here = list.filter(p => p.rpId === passkey.rpId), elsewhere = list.length - here.length;
  let html = `<div class="row u-mt6"><b>Passkeys</b><span class="badge ${list.length ? 'on' : ''}">${list.length || 'None'}</span></div>`;
  if (list.length) html += '<div class="pklist">' + list.map(p => `<div class="pkrow"><div><b>${esc(p.name)}</b>
      <div class="sub">${esc(p.rpId)} · added ${date(p.created)}${hasT(p.lastUsed) ? ' · used ' + rel(p.lastUsed) : ''}</div></div>
      <button type="button" class="del" data-act="removePasskey" data-id="${p.id}" data-name="${esc(p.name)}">Remove</button></div>`).join('') + '</div>';
  if (!(passkey.available && passkey.browser)) {
    html += `<div class="hint u-m0">${esc(passkey.reason || 'This browser does not support passkeys.')}</div>`;
  } else {
    html += `<div class="hint u-m0">Sign in with Face ID, a fingerprint or your device PIN instead of password and code${elsewhere ? `. ${elsewhere} passkey(s) belong to another address` : ''}.</div>
      <div class="acts"><input class="u-grow u-minw140" type="text" id="pkName" maxlength="40" placeholder="Name, e.g. iPhone">
      <button type="button" id="pkAdd"><svg class="i"><use href="#i-key"/></svg>Add a passkey</button></div>`;
  }
  box.insertAdjacentHTML('beforeend', html);
  const add = $('#pkAdd');
  if (add) add.onclick = async () => {
    try {
      const r = await passkeyCeremony('create', '/api/me/passkeys', {name: $('#pkName').value});
      toast(`Passkey "${r.name}" added`); await refresh(); renderMfaBox();
    } catch (e) { toast(e.message, true); }
  };
}
async function removePasskey(id, name) {
  if (!confirm(`Remove passkey "${name}"? You can still sign in with your password and code.`)) return;
  if (await act('DELETE', '/api/me/passkeys/' + id, 'Passkey removed')) renderMfaBox();
}

authSubmit('#forgotForm', async f => {
  const msg = await api('POST', '/api/forgot', {login: f.login.value});
  f.reset(); showAuth('login'); toast(msg);
});
authSubmit('#resetForm', async f => {
  const r = await api('POST', '/api/reset', {token: linkToken, password: f.password.value});
  f.reset(); linkToken = ''; showAuth('login'); $('#loginForm').username.value = r.username; $('#loginForm').password.focus();
  toast('Password changed – sign in with your new password');
});
$('#forgotLink').onclick = e => { e.preventDefault(); showAuth('forgot'); };
async function logout() {
  try { await api('POST', '/api/logout'); } catch (e) {}
  showAuth('login');
}
function openAccount() {
  const f = $('#acctForm'); f.email.value = me.email || ''; f.notify.checked = !!me.notify;
  renderMfaBox(); acctDlg.showModal();
}
function renderMfaBox() {
  const required = me.role === 'admin' || S.settings.require2faAll, box = $('#mfaBox');
  if (!me.totp) {
    box.innerHTML = `<div class="row"><b>Two-factor authentication</b><span class="badge off">Off</span></div>
      <div class="hint u-m0">Adds a code from your phone to your sign-in.</div>
      <div><button type="button" id="mfaOn">Set up two-factor authentication</button></div>`;
    $('#mfaOn').onclick = () => { acctDlg.close(); startMfaSetup(me, false); };
    return;
  }
  box.innerHTML = `<div class="row"><b>Two-factor authentication</b><span class="badge on">On</span></div>
    <div class="hint u-m0">${me.recoveryLeft} of 10 recovery codes left.${required ? ' Required for your account.' : ''}</div>
    <div class="acts"><button type="button" id="mfaNewRec">New recovery codes</button>${required ? '' : '<button type="button" class="del" id="mfaOff">Turn off</button>'}</div>`;
  $('#mfaNewRec').onclick = async () => {
    try { const r = await api('POST', '/api/me/2fa/recovery'); acctDlg.close(); showRecovery(r.recovery, refresh); }
    catch (e) { toast(e.message, true); }
  };
  if (!required) $('#mfaOff').onclick = async () => {
    acctDlg.close();
    if (await askCode({title: 'Turn off two-factor authentication', hint: 'Enter a code from your authenticator app to confirm. Your passkeys are removed too.',
        submit: code => api('POST', '/api/me/2fa/disable', {code}, true)})) {
      toast('Two-factor authentication is off'); refresh();
    }
  };
  renderPasskeys(box);
}

$('#acctForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  if (await act('PUT', '/api/me', 'Saved', {email: f.email.value, notify: f.notify.checked})) {
    me.email = f.email.value.trim(); me.notify = f.notify.checked; acctDlg.close();
  }
};
$('#pwForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  if (f.new.value !== f.new2.value) { toast('Passwords do not match', true); return; }
  if (await act('PUT', '/api/me/password', 'Password changed', {current: f.current.value, new: f.new.value})) { f.reset(); pwDlg.close(); }
};

// ---------- tabs ----------
function selectTab(t) {
  tab = t;
  document.querySelectorAll('#tabs button').forEach(x => x.classList.toggle('on', x.dataset.t === t));
  document.querySelectorAll('main > section').forEach(s => s.hidden = s.id !== 't-' + t);
}
$('#tabs').onclick = e => {
  const b = e.target.closest('button'); if (!b) return;
  selectTab(b.dataset.t);
  if (tab === 'settings') fillSettings();
  refresh();
};

// ---------- rendering ----------
const pill = (cls, t) => `<span class="pill ${cls}">${t}</span>`;
const icon = n => `<svg class="i"><use href="#i-${n}"/></svg>`;
const date = t => hasT(t) ? new Date(t).toLocaleDateString(undefined, {year: 'numeric', month: 'short', day: 'numeric'}) : '—';
const rel = t => {
  if (!hasT(t)) return '—';
  const m = Math.round((Date.now() - new Date(t)) / 6e4);
  return m < 1 ? 'just now' : m < 60 ? m + ' min ago' : m < 1440 ? Math.round(m / 60) + ' h ago' : date(t);
};
const daysLeft = c => Math.floor((new Date(c.notAfter) - Date.now()) / 864e5);
function certStatus(c) {
  if (c.lastError) return pill('err', 'Error') + `<div class="errtxt" title="${esc(c.lastError)}">${esc(c.lastError)}</div>`;
  if (!hasT(c.notAfter)) return pill('warn', 'Not issued yet');
  const d = daysLeft(c);
  return d < 0 ? pill('err', 'Expired') : pill(d < S.settings.renewDays ? 'warn' : 'ok', d + ' days left');
}
function routerStatus(r) {
  const c = S.certs.find(c => c.id === r.certId);
  let s = !r.enrolled ? pill('warn', 'Not enrolled')
    : !r.enabled ? pill('muted', 'Disabled')
    : !c ? pill('muted', 'No certificate')
    : c.fingerprint && r.deployedFingerprint === c.fingerprint ? pill('ok', 'Up to date')
    : pill('warn', 'Pending');
  if (r.lastError) s += `<div class="errtxt" title="${esc(r.lastError)}">${esc(r.lastError)}</div>`;
  return s;
}
const isUpToDate = r => { const c = S.certs.find(c => c.id === r.certId); return r.enrolled && c?.fingerprint && r.deployedFingerprint === c.fingerprint; };
function renderStats() {
  const valid = S.certs.filter(c => hasT(c.notAfter) && daysLeft(c) >= 0).length;
  const soon = S.certs.filter(c => hasT(c.notAfter) && daysLeft(c) < (S.mail?.warnDays || 14)).length;
  const upd = S.routers.filter(isUpToDate).length;
  const probs = S.certs.filter(c => c.lastError).length + S.routers.filter(r => r.lastError || !r.enrolled).length;
  const tile = (cls, ic, n, t) => `<div class="stat"><span class="si ${cls}">${icon(ic)}</span><div><b>${n}</b><span>${t}</span></div></div>`;
  $('#stats').innerHTML =
    tile('acc', 'cert', `${valid}<small class="muted u-fs13"> / ${S.certs.length}</small>`, 'Valid certificates') +
    tile(soon ? 'warn' : 'ok', 'clock', soon, 'Expiring soon') +
    tile('acc', 'router', `${upd}<small class="muted u-fs13"> / ${S.routers.length}</small>`, 'Devices up to date') +
    tile(probs ? 'err' : 'ok', 'alert', probs, probs === 1 ? 'Needs attention' : 'Need attention');
}
const cell = (label, html, cls = '') => `<td data-label="${label}" class="${cls}"><div class="v">${html}</div></td>`;
const emptyRow = (cols, ic, html) => `<tr><td colspan="${cols}" class="empty">${icon(ic)}${html}</td></tr>`;
function render() {
  $('#status').classList.toggle('busy', S.busy);
  if (S.version) $('#appVer').textContent = S.version;
  $('#statusTxt').textContent = S.busy ? 'Working…' : 'Idle';
  renderStats();
  renderDNS();
  $('#proxyHint').hidden = !S.proxyHint;
  $('#proxyHint').innerHTML = S.proxyHint ? `<b>Reverse proxy not trusted.</b> ${esc(S.proxyHint)}` : '';
  $('#certRows').innerHTML = S.certs.length ? S.certs.map(c => `<tr>
    <td class="main">${esc(c.name)}</td>
    ${cell('Domains', c.domains.map(esc).join('<br>') + dnsVia(c), 'small')}
    ${cell('Expires', date(c.notAfter), 'small nw')}
    ${cell('Status', certStatus(c))}
    <td class="adm acts-cell"><div class="acts">
      ${hasT(c.notAfter) ? `<button data-act="exportCert" data-id="${c.id}">Export</button>` : ''}
      <button data-act="renewCert" data-id="${c.id}">Renew</button>
      <button data-act="editCert" data-id="${c.id}">Edit</button></div></td></tr>`).join('')
    : emptyRow(5, 'cert', 'No certificates yet.<div class="small">Add a DNS account under <b>Settings → DNS accounts</b> first, then your first certificate.</div>');
  $('#routerRows').innerHTML = S.routers.length ? S.routers.map(r => {
    const c = S.certs.find(c => c.id === r.certId);
    return `<tr>
    <td class="main">${esc(r.name)}<div class="sub">${[r.board, r.version && 'RouterOS ' + r.version].filter(Boolean).map(esc).join(' · ')}</div></td>
    ${cell('Connection', esc(r.host) + (r.enrolled ? `<div><span class="lockline" title="api-ssl with pinned certificate, service account ${esc(r.serviceUser)}">${icon('lock')}api-ssl :${r.apiPort}</span></div>` : ''), 'small')}
    ${cell('Certificate', (c ? esc(c.name) : '—') + (c && r.services?.length ? `<div class="muted">${r.services.map(esc).join(', ')}</div>` : ''), 'small')}
    ${cell('Last deploy', `<span title="${hasT(r.lastDeploy) ? fmt(r.lastDeploy) : ''}">${rel(r.lastDeploy)}</span>`, 'small nw')}
    ${cell('Status', routerStatus(r))}
    <td class="adm acts-cell"><div class="acts">
      ${r.enrolled ? `<button data-act="testDevice" data-id="${r.id}">Test</button>
      <button data-act="deployDevice" data-id="${r.id}">Deploy</button>
      <button data-act="editRouter" data-id="${r.id}">Edit</button>`
      : `<button class="pri" data-act="enrollWizard" data-id="${r.id}">Enroll</button>
      <button class="del" data-act="delRouter" data-id="${r.id}">Remove</button>`}</div></td></tr>`;
  }).join('') : emptyRow(6, 'router', 'No devices yet.<div class="small">Use <b>Enroll device</b> to add a MikroTik router.</div>');
}
function renderUsers() {
  $('#userRows').innerHTML = users.map(u => `<tr>
    <td class="main"><span class="u-iflex"><span class="av">${esc(u.username[0])}</span>${esc(u.username)}${u.id === me.id ? ' <span class="muted small">(you)</span>' : ''}</span></td>
    ${cell('E-mail', (esc(u.email) || '—') + (u.notify ? ` <span class="badge" title="receives notifications">${icon('mail').replace('class="i"', 'class="i u-ic13"')}</span>` : ''), 'small')}
    ${cell('Role', `<span class="badge ${u.role}">${u.role}</span> ${u.totp ? '<span class="badge on" title="Two-factor authentication on">2FA</span>' : '<span class="badge off" title="Two-factor authentication off">no 2FA</span>'}${u.passkeys ? ` <span class="badge on" title="${u.passkeys} passkey(s)">passkey</span>` : ''}`)}
    ${cell('Created', date(u.created), 'small nw')}
    ${cell('Last login', rel(u.lastLogin), 'small nw')}
    <td class="acts-cell"><div class="acts"><button data-act="editUser" data-id="${u.id}">Edit</button>
      ${u.id === me.id ? '' : `<button class="del" data-act="delUser" data-id="${u.id}">Delete</button>`}</div></td></tr>`).join('');
  $('#invCard').hidden = !invites.length;
  $('#invRows').innerHTML = invites.map(i => `<tr>
    <td class="main">${esc(i.email)}</td>${cell('Role', `<span class="badge ${i.role}">${i.role}</span>`)}
    ${cell('Invited by', esc(i.createdBy), 'small')}
    ${cell('Expires', fmt(i.expires), 'small nw')}
    <td class="acts-cell"><div class="acts"><button class="del" data-act="revokeInvite" data-id="${i.id}">Revoke</button></div></td></tr>`).join('');
}

async function refresh() {
  if (!me) return;
  try {
    S = await api('GET', '/api/state');
    if (S.me && (S.me.role !== me.role || S.me.username !== me.username)) startApp(S.me); // role changed by an admin
    if (S.me) Object.assign(me, S.me);
    render();
    if (tab === 'users' && isAdmin()) {
      [users, invites] = await Promise.all([api('GET', '/api/users'), api('GET', '/api/invites')]);
      renderUsers();
    }
    if (tab === 'log') {
      const L = await api('GET', '/api/logs'), el = $('#log');
      const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
      el.textContent = L.map(l => new Date(l.t).toLocaleString() + '  ' + l.msg).join('\n');
      if (atBottom) el.scrollTop = el.scrollHeight;
    }
  } catch (e) { if (me) toast(e.message, true); }
}
function loop() {
  clearTimeout(timer);
  refresh().finally(() => { if (me) timer = setTimeout(loop, S.busy || tab === 'log' ? 2000 : 10000); });
}

// ---------- settings ----------
function fillSettings() {
  const f = $('#setForm'), s = S.settings;
  f.email.value = s.email || ''; f.keyType.value = s.keyType;
  f.renewDays.value = s.renewDays; f.checkHours.value = s.checkHours;
  f.dnsResolvers.value = s.dnsResolvers || ''; f.staging.checked = !!s.staging; f.require2fa.checked = !!s.require2faAll;
  const m = S.mail, g = $('#mailForm');
  for (const k of ['host', 'port', 'security', 'user', 'from', 'publicUrl', 'warnDays', 'extraRecipients']) g[k].value = m[k] ?? '';
  for (const k of ['notifyIssueOk', 'notifyIssueFail', 'notifyDeployOk', 'notifyDeployFail', 'notifyExpiry']) g[k].checked = !!m[k];
  g.password.value = ''; g.password.placeholder = m.hasPassword ? '•••••••• (saved, leave empty to keep)' : '';
  const sec = S.security; $('#secLine').hidden = !sec;
  if (sec) $('#secLine').textContent = 'Encryption key: ' + (sec.keySource === 'data folder' ? 'stored in the data folder (default)' : 'from ' + sec.keySource)
    + ' · Runs as: ' + (sec.runUid === 0 ? 'root' : 'user ' + sec.runUid)
    + (sec.keySource === 'data folder' || sec.runUid === 0 ? ' · See "Hardened setup" in the guide to keep the key out of backups and run unprivileged.' : '');
  $('#mailState').innerHTML = m.host && m.from ? '<span class="pill ok">Configured</span>' : '<span class="pill muted">Not configured</span>';
}
$('#mailForm').onsubmit = async e => {
  e.preventDefault(); const g = e.target, body = {};
  for (const k of ['host', 'security', 'user', 'password', 'from', 'publicUrl', 'extraRecipients']) body[k] = g[k].value;
  for (const k of ['port', 'warnDays']) body[k] = +g[k].value;
  for (const k of ['notifyIssueOk', 'notifyIssueFail', 'notifyDeployOk', 'notifyDeployFail', 'notifyExpiry']) body[k] = g[k].checked;
  if (await act('PUT', '/api/mail', 'E-mail settings saved', body)) fillSettings();
};
// tests what's in the form right now, saved or not (nothing is stored)
async function testMail() {
  const g = $('#mailForm'), m = S.mail || {};
  const settings = {host: g.host.value, port: +g.port.value, security: g.security.value, user: g.user.value,
    password: g.password.value, from: g.from.value};
  const unsaved = settings.password !== '' || ['host', 'port', 'security', 'user', 'from']
    .some(k => String(settings[k] ?? '') !== String(m[k] ?? ''));
  const to = prompt('Send a test e-mail to:', me.email || '');
  if (to === null) return;
  toast('Sending…');
  try {
    const r = await api('POST', '/api/mail/test', {to, settings});
    toast('Test e-mail ' + r + (unsaved ? ' – these settings aren\'t saved yet, click Save e-mail settings to keep them' : ''));
  } catch (e) { toast(e.message, true); }
}
$('#setForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  if (await act('PUT', '/api/settings', 'Settings saved', {
    email: f.email.value, keyType: f.keyType.value,
    renewDays: +f.renewDays.value, checkHours: +f.checkHours.value,
    dnsResolvers: f.dnsResolvers.value, staging: f.staging.checked, require2faAll: f.require2fa.checked })) fillSettings();
};

// ---------- certificates ----------
function exportCert(id) {
  const c = S.certs.find(c => c.id === id), f = $('#expForm');
  f.reset(); f.id.value = id; $('#expPfx').hidden = true; f.password.required = false;
  $('#expWhat').textContent = `${c.name} · ${c.domains.join(', ')} · valid until ${date(c.notAfter)}`;
  expDlg.showModal();
}
$('#expForm').addEventListener('change', e => {
  if (e.target.name !== 'format') return;
  const pfx = e.target.value === 'pfx', f = $('#expForm');
  $('#expPfx').hidden = !pfx; f.password.required = pfx;
});
$('#expGen').onclick = () => {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789', r = crypto.getRandomValues(new Uint32Array(20));
  $('#expPw').value = Array.from(r, n => abc[n % abc.length]).join('').replace(/(.{5})(?!$)/g, '$1-');
};
$('#expForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target, btn = f.querySelector('button.pri');
  const body = {format: f.format.value, password: f.format.value === 'pfx' ? f.password.value : '', legacy: f.legacy.checked};
  btn.disabled = true;
  try { const name = await download(`/api/certs/${f.id.value}/export`, body); expDlg.close(); toast('Downloaded ' + name); }
  catch (err) { toast(err.message, true); }
  finally { btn.disabled = false; }
};
function editCert(id) {
  const c = S.certs.find(c => c.id === id) || {}, f = $('#certForm');
  $('#certTitle').textContent = id ? 'Edit certificate' : 'Add certificate';
  f.id.value = c.id || ''; f.name.value = c.name || ''; f.domains.value = (c.domains || []).join('\n');
  $('#certDns').innerHTML = '<option value="">Automatic (by domain)</option>' +
    (S.dnsAccounts || []).map(a => `<option value="${a.id}">${esc(a.name)}</option>`).join('');
  f.dnsAccountId.value = c.dnsAccountId || '';
  certRoutePreview();
  $('#certDel').hidden = !id; $('#certDel').onclick = () => { certDlg.close(); delCert(id); };
  certDlg.showModal();
}
$('#certForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  if (await act('POST', '/api/certs', 'Saved – issuing in the background',
    {id: f.id.value, name: f.name.value, domains: f.domains.value.split('\n'), dnsAccountId: f.dnsAccountId.value})) certDlg.close();
};
$('#certForm').domains.addEventListener('input', () => certRoutePreview());
$('#certDns').addEventListener('change', () => certRoutePreview());

// ---------- DNS accounts ----------
// same rule as the server: the most specific zone (longest suffix) wins
function zoneFor(name, accounts) {
  name = name.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  let best = null, zone = '';
  for (const a of accounts) for (const z of a.zones || [])
    if ((name === z || name.endsWith('.' + z)) && z.length > zone.length) { best = a; zone = z; }
  return {account: best, zone};
}
function certRoutePreview() {
  const f = $('#certForm'), accs = S.dnsAccounts || [], pick = f.dnsAccountId.value;
  const names = f.domains.value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
  if (!accs.length) { $('#certRoute').innerHTML = '<span class="warn">No DNS account yet – add one under Settings → DNS accounts.</span>'; return; }
  if (!names.length) { $('#certRoute').textContent = ''; return; }
  const unknown = accs.filter(a => !(a.zones || []).length);
  $('#certRoute').innerHTML = names.map(n => {
    const pool = pick ? accs.filter(a => a.id === pick) : accs;
    let {account} = zoneFor(n, pool);
    if (!account && !pick && unknown.length === 1) account = unknown[0];
    if (!account && pick && !(pool[0].zones || []).length) account = pool[0];
    return account ? `${esc(n)} → <b>${esc(account.name)}</b>` : `<span class="err">${esc(n)} → no DNS account covers this zone</span>`;
  }).join('<br>');
}
function dnsVia(c) {
  const r = (S.dnsRoutes || {})[c.id];
  if (!r) return '';
  if (r.error) return `<div class="errtxt" title="${esc(r.error)}">${esc(r.error)}</div>`;
  const names = [...new Set((r.routes || []).map(x => (S.dnsAccounts.find(a => a.id === x.accountId) || {}).name).filter(Boolean))];
  // acme-dns: CNAME records still to be created at the DNS host
  const todo = (r.routes || []).flatMap(x => ((S.dnsAccounts.find(a => a.id === x.accountId) || {}).cnames || [])
    .filter(cn => !cn.ok && cn.name === x.name.replace(/^\*\./, '').toLowerCase()));
  const need = [...new Map(todo.map(cn => [cn.record, cn])).values()]
    .map(cn => `<div class="warn">create CNAME <span class="mono">${esc(cn.record)}</span> → <span class="mono">${esc(cn.target)}</span></div>`).join('');
  return (names.length ? `<div class="muted">via ${names.map(esc).join(', ')}</div>` : '') + need;
}
const provDef = id => (S.dnsProviders || []).find(p => p.id === (id || 'cloudflare')) || {fields: []};
function renderDNS() {
  const rows = (S.dnsAccounts || []).map(a => {
    const def = provDef(a.provider), cn = a.cnames || [], open = cn.filter(c => !c.ok).length;
    const zones = (a.zones || []).length ? a.zones.map(esc).join('<br>') : '<span class="muted">not checked yet</span>';
    const cnames = cn.map(c => `<div class="cname ${c.ok ? 'ok' : 'warn'}">${c.ok ? '✓' : '✗'} <span class="mono">${esc(c.record)}</span> → <span class="mono">${esc(c.target)}</span></div>`).join('');
    const status = a.lastError ? pill('err', 'Error') + `<div class="errtxt" title="${esc(a.lastError)}">${esc(a.lastError)}</div>`
      : open ? pill('warn', open === 1 ? 'CNAME needed' : `${open} CNAMEs needed`) + '<div class="sub">create them at your DNS host</div>'
      : a.provider === 'cloudflare' || !a.provider ? pill('ok', 'Working') + (hasT(a.zonesChecked) ? `<div class="sub">checked ${rel(a.zonesChecked)}</div>` : '')
      : pill('ok', 'Ready') + '<div class="sub">use Test to check it</div>';
    const refreshBtn = def.autoZones ? `<button data-act="refreshDNS" data-id="${a.id}">Refresh</button>`
      : a.provider === 'acmedns' ? `<button data-act="refreshDNS" data-id="${a.id}">Check CNAMEs</button>` : '';
    return `<tr>
    <td class="main">${esc(a.name)}<div class="sub">${esc(def.name || a.provider)}</div></td>
    ${cell('Zones', zones + cnames, 'small')}
    ${cell('Status', status)}
    <td class="adm acts-cell"><div class="acts"><button data-act="testDNS" data-id="${a.id}">Test</button>${refreshBtn}<button data-act="editDNS" data-id="${a.id}">Edit</button></div></td></tr>`;
  }).join('');
  $('#dnsRows').innerHTML = rows || emptyRow(4, 'gear', 'No DNS account yet.<div class="small">Add one to start issuing certificates.</div>');
}
function dnsFields(provider, a) {
  const def = provDef(provider), f = $('#dnsForm'), editing = !!a.id;
  $('#dnsHelp').innerHTML = def.help || '';   // static text from the server's provider list
  $('#dnsZonesBox').hidden = !!def.autoZones; f.zones.required = !def.autoZones;
  $('#dnsFields').innerHTML = def.fields.map(x => {
    const id = 'dnsF-' + x.key, val = x.secret ? '' : esc((a.config || {})[x.key] ?? x.default ?? '');
    const kept = x.secret && editing && (a.hasToken || a.hasSecret);
    const input = x.options
      ? `<select id="${id}" data-key="${x.key}">${x.options.map(o => `<option${o === ((a.config || {})[x.key] || x.default) ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`
      : `<input id="${id}" data-key="${x.key}" ${x.secret ? 'data-secret="1" type="password" autocomplete="new-password"' : 'type="text"'} value="${val}"
          placeholder="${esc(kept ? 'saved – leave empty to keep' : x.placeholder || '')}"${x.required && !kept ? ' required' : ''} spellcheck="false">`;
    return `<label for="${id}">${esc(x.label)}</label>${input}${x.hint ? `<div class="hint">${esc(x.hint)}</div>` : ''}`;
  }).join('');
}
function editDNS(id) {
  const a = (S.dnsAccounts || []).find(x => x.id === id) || {}, f = $('#dnsForm');
  $('#dnsTitle').textContent = id ? 'Edit DNS account' : 'Add DNS account';
  f.id.value = a.id || ''; f.name.value = a.name || '';
  f.provider.innerHTML = (S.dnsProviders || []).map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  f.provider.value = a.provider || 'cloudflare'; f.provider.disabled = !!id;
  f.zones.value = (a.zones || []).join('\n');
  dnsFields(f.provider.value, a);
  f.provider.onchange = () => dnsFields(f.provider.value, {});
  $('#dnsDel').hidden = !id;
  $('#dnsDel').onclick = async () => {
    if (confirm(`Delete DNS account "${a.name}"?`) && await act('DELETE', '/api/dns-accounts/' + id, 'DNS account deleted')) dnsDlg.close();
  };
  dnsDlg.showModal();
}
$('#dnsForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target, btn = f.querySelector('button.pri');
  const body = {id: f.id.value, name: f.name.value, provider: f.provider.value, config: {}, secrets: {}, zones: f.zones.value.split('\n')};
  f.querySelectorAll('#dnsFields [data-key]').forEach(el => (el.dataset.secret ? body.secrets : body.config)[el.dataset.key] = el.value);
  btn.disabled = true; btn.textContent = 'Checking…';
  try {
    const r = await api('POST', '/api/dns-accounts', body);
    if (r.warning) toast('Saved, but: ' + r.warning, true);
    else toast(body.provider === 'cloudflare' && r.zones?.length ? `Saved – this token manages ${r.zones.join(', ')}` : 'Saved – use Test to check it');
    dnsDlg.close(); refresh();
  } catch (err) { toast(err.message, true); }
  finally { btn.disabled = false; btn.textContent = 'Save'; }
};
async function refreshDNS(id) {
  try {
    const z = await api('POST', `/api/dns-accounts/${id}/refresh`);
    const a = S.dnsAccounts.find(x => x.id === id);
    toast(a?.provider === 'acmedns' ? 'CNAME records checked' : 'Zones: ' + (z.join(', ') || 'none')); refresh();
  } catch (e) { toast(e.message, true); refresh(); }
}
async function testDNS(id, btn) {
  const a = S.dnsAccounts.find(x => x.id === id);
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  try {
    const r = await api('POST', `/api/dns-accounts/${id}/test`);
    $('#dnsTestTitle').textContent = (r.ok ? '✓ ' : '✗ ') + 'Test of ' + a.name;
    $('#dnsTestMsg').textContent = r.message;
    $('#dnsTestList').innerHTML = (r.details || []).map(d => `<li>${esc(d)}</li>`).join('');
    dnsTestDlg.showModal(); refresh();
  } catch (e) { toast(e.message, true); }
  finally { if (btn) { btn.disabled = false; btn.textContent = 'Test'; } }
}
function delCert(id) {
  const c = S.certs.find(c => c.id === id);
  if (confirm(`Delete certificate "${c.name}"?`)) act('DELETE', '/api/certs/' + id, 'Deleted');
}

// ---------- devices ----------
function certOptions() {
  document.querySelectorAll('.certSel').forEach(sel => sel.innerHTML = '<option value="">— none —</option>' +
    S.certs.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join(''));
}
const ago = t => hasT(t) ? fmt(t) : '—';
function editRouter(id) {
  const r = S.routers.find(r => r.id === id), f = $('#rtForm');
  certOptions();
  $('#rtTitle').textContent = 'Device: ' + r.name;
  f.id.value = r.id; f.name.value = r.name; f.certId.value = r.certId || '';
  f.extraCommands.value = r.extraCommands || ''; f.enabled.checked = !!r.enabled;
  f.querySelectorAll('[name=svc]').forEach(cb => cb.checked = (r.services || []).includes(cb.value));
  $('#rtInfo').innerHTML = `<b>🔒 Secure connection</b><dl class="kv u-mt6">
    <dt>Address</dt><dd>${esc(r.host)} – api-ssl port ${r.apiPort}</dd>
    <dt>Service account</dt><dd>${esc(r.serviceUser)}, login only from ${esc(r.allowedFrom || 'any address')}</dd>
    <dt>Password</dt><dd>random, known only to this app · last rotated ${ago(r.rotatedAt)}</dd>
    <dt>Pinned TLS cert</dt><dd class="mono">${(r.pins || []).map(p => esc(p.slice(0, 32)) + '…').join('<br>')}</dd>
    <dt>SSH host key</dt><dd class="mono">${esc(r.sshHostKey)}</dd>
    <dt>Enrolled</dt><dd>${ago(r.enrolledAt)} by ${esc(r.enrolledBy)}</dd>
    <dt>Last seen</dt><dd>${ago(r.lastSeen)}</dd></dl>`;
  $('#rotBtn').onclick = () => act('POST', `/api/routers/${r.id}/rotate`, 'Password rotation started – see Log');
  $('#reBtn').onclick = () => { rtDlg.close(); enrollWizard(r.id); };
  $('#rmBtn').onclick = () => { rtDlg.close(); delRouter(r.id); };
  rtDlg.showModal();
}
$('#rtForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  const body = {id: f.id.value, name: f.name.value, certId: f.certId.value, extraCommands: f.extraCommands.value,
    enabled: f.enabled.checked, services: [...f.querySelectorAll('[name=svc]:checked')].map(c => c.value)};
  if (await act('POST', '/api/routers', 'Device saved', body)) rtDlg.close();
};
async function testDevice(id) {
  toast('Connecting…');
  try {
    const i = await api('POST', `/api/routers/${id}/test`);
    toast(`✓ ${i.identity}: RouterOS ${i.version}, up ${i.uptime} (TLS ${i.tls})`); refresh();
  } catch (e) { toast(e.message, true); }
}

// enrollment wizard
let enrCur = 1, enrProbe = null;
function enrStep(n) {
  enrCur = n;
  document.querySelectorAll('#enrForm [data-step]').forEach(d => d.hidden = +d.dataset.step !== n);
  document.querySelectorAll('.stepper span').forEach(s => s.classList.toggle('on', +s.dataset.s === n));
  $('#enrBack').hidden = n !== 2;
  $('#enrNext').hidden = false;
  $('#enrNext').textContent = n === 1 ? 'Connect' : n === 2 ? 'Enroll device' : 'Done';
  $('#enrCancel').hidden = n === 3;
}
function enrAuthUI() { const k = $('#enrAuth').value === 'key'; $('#enrKey').hidden = !k; $('#enrPw').hidden = k; }
$('#enrAuth').onchange = enrAuthUI;
function enrollWizard(id) {
  const f = $('#enrForm'), r = S.routers.find(r => r.id === id);
  f.reset(); certOptions(); enrProbe = null;
  f.id.value = id || '';
  $('#enrTitle').textContent = r ? 'Re-enroll ' + r.name : 'Enroll device';
  if (r) {
    f.host.value = r.host; f.sshPort.value = r.sshPort || 22; f.name.value = r.name;
    f.certId.value = r.certId || ''; f.extraCommands.value = r.extraCommands || ''; f.enabled.checked = r.enabled;
    f.querySelectorAll('[name=svc]').forEach(cb => cb.checked = (r.services || []).includes(cb.value));
    if (r.serviceUser) f.serviceUser.value = r.serviceUser;
  } else if (S.certs.length === 1) f.certId.value = S.certs[0].id;
  enrAuthUI(); enrStep(1); enrDlg.showModal();
}
function enrLogin(f) {
  const key = $('#enrAuth').value === 'key';
  return {host: f.host.value.trim(), sshPort: +f.sshPort.value || 22, adminUser: f.adminUser.value.trim(),
    adminPassword: key ? '' : f.adminPassword.value, adminKey: key ? f.adminKey.value : ''};
}
function enrChanges(f) {
  const p = enrProbe, u = esc(f.serviceUser.value || 'routeros-acme');
  const items = [
    p.apiSslCert ? `keep api-ssl's certificate <b>${esc(p.apiSslCert)}</b> and pin its fingerprint`
                 : 'add a self-signed certificate <b>routeros-acme-api</b> for api-ssl and pin its fingerprint',
    `${p.apiSslDisabled ? '<b>enable</b>' : 'keep'} the api-ssl service on port <b>${+f.apiPort.value || 8729}</b> (other services stay as they are)`,
    'add user group <b>routeros-acme</b>: api, read, write, ftp, sensitive, password. Denied: ssh, winbox, web, telnet, console, policy, reboot',
    `${p.serviceUserExists ? 'take over' : 'add'} user <b>${u}</b> with a random password${f.allowedFrom.value ? `, allowed from <b>${esc(f.allowedFrom.value)}</b> only` : ''}`,
    'verify the new login over api-ssl. If it fails, the user is removed again'];
  $('#enrChanges').innerHTML = items.map(i => `<li>${i}</li>`).join('');
}
['serviceUser', 'allowedFrom', 'apiPort'].forEach(n => $('#enrForm')[n].addEventListener('input', () => enrProbe && enrChanges($('#enrForm'))));

$('#enrForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target, btn = $('#enrNext');
  if (enrCur === 3) { enrDlg.close(); return; }
  btn.disabled = true;
  try {
    if (enrCur === 1) {
      btn.textContent = 'Connecting…';
      const p = await api('POST', '/api/devices/probe', {...enrLogin(f), serviceUser: f.serviceUser.value});
      enrProbe = p;
      $('#enrDev').innerHTML = `<dt>Identity</dt><dd>${esc(p.identity)}</dd><dt>Model</dt><dd>${esc(p.board)}</dd>
        <dt>RouterOS</dt><dd>${esc(p.version)}</dd><dt>api-ssl</dt><dd>${p.apiSslDisabled ? 'disabled' : 'enabled'}, port ${p.apiSslPort}, certificate ${esc(p.apiSslCert || 'none')}</dd>`;
      $('#enrHostKey').textContent = p.hostKey;
      $('#enrWarn').hidden = !p.warnings?.length;
      $('#enrWarn').innerHTML = (p.warnings || []).map(esc).join('<br>');
      if (!f.name.value) f.name.value = p.identity;
      f.apiPort.value = p.apiSslPort || 8729;
      f.allowedFrom.value = p.sourceIp || '';
      f.confirmed.checked = false;
      enrChanges(f); enrStep(2);
    } else if (enrCur === 2) {
      if (!f.confirmed.checked) { toast('Confirm the device (host key) first', true); return; }
      btn.textContent = 'Enrolling…';
      const r = await api('POST', '/api/devices/enroll', {...enrLogin(f), hostKey: enrProbe.hostKey, id: f.id.value,
        name: f.name.value, apiPort: +f.apiPort.value, serviceUser: f.serviceUser.value, allowedFrom: f.allowedFrom.value,
        certId: f.certId.value, extraCommands: f.extraCommands.value, enabled: f.enabled.checked,
        services: [...f.querySelectorAll('[data-step="2"] [name=svc]:checked')].map(c => c.value)});
      f.adminPassword.value = ''; f.adminKey.value = '';   // don't keep them in the page either
      $('#enrSteps').innerHTML = r.steps.map(s => `<li class="${s.ok ? 'ok' : 'bad'}"><span class="ico">${s.ok ? '✓' : '✗'}</span>
        <span>${esc(s.title)}</span><span class="d">${esc(s.detail)}</span></li>`).join('');
      $('#enrDone').hidden = !r.ok; $('#enrFail').hidden = r.ok;
      $('#enrDone').innerHTML = `<b>Enrolled.</b> RouterOS ACME now manages this device over api-ssl only, with a pinned certificate
        and its own restricted account. ${f.certId.value ? 'The certificate is deployed in the background. Watch the status in the device list.' : 'Pick a certificate under Edit to start deploying.'}`;
      $('#enrFail').innerHTML = `<b>Enrollment did not complete:</b> ${esc(r.error || '')}<br>Nothing is left half-configured for login. Fix the problem and run enrollment again.`;
      enrStep(3); refresh();
    }
  } catch (err) { toast(err.message, true); }
  finally { btn.disabled = false; if (enrCur !== 3) btn.textContent = enrCur === 1 ? 'Connect' : 'Enroll device'; }
};

// remove
function delRouter(id) {
  const r = S.routers.find(r => r.id === id), f = $('#rmForm');
  f.reset(); f.id.value = id; $('#rmCreds').hidden = true;
  $('#rmTitle').textContent = 'Remove ' + r.name;
  $('#rmForgetHint').innerHTML = r.enrolled ? `The service account <b>${esc(r.serviceUser)}</b> stays on the device until you remove it there. Certificates on the device are not touched.` : 'Nothing on the device is changed.';
  f.querySelector('[value=cleanup]').disabled = !r.enrolled;
  rmDlg.showModal();
}
$('#rmForm').addEventListener('change', e => { if (e.target.name === 'mode') $('#rmCreds').hidden = e.target.value !== 'cleanup'; });
$('#rmForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  const body = f.mode.value === 'cleanup' ? {cleanup: {adminUser: f.adminUser.value, adminPassword: f.adminPassword.value}} : {};
  try { toast(await api('DELETE', '/api/routers/' + f.id.value, body)); rmDlg.close(); refresh(); }
  catch (err) { toast(err.message, true); }
  f.adminPassword.value = '';
};

// ---------- users ----------
function editUser(id) {
  const u = users.find(u => u.id === id) || {role: 'viewer'}, f = $('#userForm');
  $('#userTitle').textContent = id ? 'Edit user' : 'Add user';
  f.id.value = u.id || ''; f.username.value = u.username || ''; f.role.value = u.role; f.password.value = '';
  f.email.value = u.email || ''; f.notify.checked = !!u.notify;
  const mb = $('#userMfa');
  mb.hidden = !id || id === me.id;
  if (!mb.hidden) {
    mb.innerHTML = u.totp
      ? `<b>Two-factor authentication: on</b><div class="hint">If ${esc(u.username)} lost their phone and recovery codes, reset it. They set it up again at the next sign-in.</div><div><button type="button" class="del" id="userReset2fa">Reset 2FA</button></div>`
      : `<b>Two-factor authentication: off</b><div class="hint">${u.role === 'admin' || S.settings.require2faAll ? 'They must set it up at their next sign-in.' : 'Optional for this user.'}</div>`;
    if (u.totp) $('#userReset2fa').onclick = async () => {
      if (await act('POST', `/api/users/${u.id}/reset-2fa`, `2FA reset for ${u.username}`)) userDlg.close();
    };
  }
  f.password.required = !id;
  $('#userPwHint').textContent = id ? 'Leave empty to keep the current password. Setting one signs the user out everywhere.' : 'At least 8 characters.';
  userDlg.showModal();
}
$('#userForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  if (await act('POST', '/api/users', 'User saved', {id: f.id.value, username: f.username.value, role: f.role.value,
    password: f.password.value, email: f.email.value, notify: f.notify.checked})) userDlg.close();
};
function inviteUser() {
  const f = $('#invForm'); f.reset(); $('#invResult').hidden = true; $('#invBtn').hidden = false; invDlg.showModal();
}
$('#invForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  try {
    const r = await api('POST', '/api/invites', {email: f.email.value, role: f.role.value});
    f.link.value = r.link; $('#invResult').hidden = false; $('#invBtn').hidden = true;
    $('#invMsg').innerHTML = r.emailed ? '<span class="ok">Invitation e-mailed.</span> You can also share the link yourself.'
      : `<span class="warn">Not e-mailed${r.error ? ': ' + esc(r.error) : ' (e-mail is not configured)'}.</span> Send this link to the person yourself.`;
    refresh();
  } catch (err) { toast(err.message, true); }
};
function delUser(id) {
  const u = users.find(u => u.id === id);
  if (confirm(`Delete user "${u.username}"?`)) act('DELETE', '/api/users/' + id, 'User deleted');
}

// long error messages are clamped to 3 lines; tap to expand
document.addEventListener('click', e => { const t = e.target.closest('.errtxt'); if (t) t.classList.toggle('open'); });
// an invite/reset link opened in a tab that already shows this site only changes the hash
window.addEventListener('hashchange', () => { if (/^#(invite|reset)=/.test(location.hash)) boot(); });
// ---------- buttons ----------
// Buttons say what they do with data-act (and data-id). The Content Security Policy
// doesn't allow inline onclick="" handlers, so one listener dispatches all clicks.
const actions = {
  backToLogin: () => showAuth('login'),
  logout: () => logout(),
  runCheck: () => act('POST', '/api/run', 'Check started'),
  openAccount: () => openAccount(),
  changePassword: () => { acctDlg.close(); pwDlg.showModal(); },
  closeDialog: el => el.closest('dialog').close(),
  selectText: el => el.select(),
  removePasskey: el => removePasskey(el.dataset.id, el.dataset.name),
  editCert: el => editCert(el.dataset.id),
  exportCert: el => exportCert(el.dataset.id),
  renewCert: el => act('POST', `/api/certs/${el.dataset.id}/issue`, 'Renewal started'),
  editDNS: el => editDNS(el.dataset.id),
  refreshDNS: el => refreshDNS(el.dataset.id),
  testDNS: el => testDNS(el.dataset.id, el),
  testMail: () => testMail(),
  enrollWizard: el => enrollWizard(el.dataset.id),
  enrBack: () => enrStep(enrCur - 1),
  testDevice: el => testDevice(el.dataset.id),
  deployDevice: el => act('POST', `/api/routers/${el.dataset.id}/deploy`, 'Deploy started'),
  editRouter: el => editRouter(el.dataset.id),
  delRouter: el => delRouter(el.dataset.id),
  inviteUser: () => inviteUser(),
  editUser: el => editUser(el.dataset.id),
  delUser: el => delUser(el.dataset.id),
  revokeInvite: el => act('DELETE', `/api/invites/${el.dataset.id}`, 'Invitation revoked'),
};
document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]');
  if (el && Object.hasOwn(actions, el.dataset.act)) actions[el.dataset.act](el, e);
});

boot();
