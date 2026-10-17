const el = id => document.getElementById(id);
const feedback = message => { el('module-feedback').textContent = message; };
async function request(path, body) {
    const response = await fetch(path, body === undefined ? {} : {
        method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || data.error || 'Module operation failed');
    return data;
}
async function action(button, operation) {
    button.disabled = true;
    feedback('Working...');
    try { await operation(); } catch(error) { feedback(error.message); }
    finally { button.disabled = false; updateRelayConsent(); }
}
function renderModules(modules) {
    for (const module of modules) {
        const field = el(`module-${module.kind}-state`);
        if (!field) continue;
        field.textContent = `${module.state}${module.certificate_id ? ` · certificate ${module.certificate_id}` : ''}${module.error_code ? ` · ${module.error_code}` : ''}`;
        field.className = module.state === 'active' ? 'c-green' : 'c-amber';
    }
}
async function refresh() {
    renderModules(await request('/api/modules'));
    const status = await request('/api/network-manager');
    el('network-manager-status').textContent = `Network owner: ${status.owner_process_id} · ${status.interface_name || 'not configured'} · desired ${status.desired_revision}, applied ${status.applied_revision ?? 'pending'}${status.error_code ? ` · ${status.error_code}` : ''}`;
}
function updateRelayConsent() { el('module-relay-enable').disabled = !el('relay-consent').checked; }
el('relay-consent').addEventListener('change', updateRelayConsent);
for (const kind of ['master', 'relay']) {
    el(`module-${kind}-enable`).addEventListener('click', event => action(event.currentTarget, async () => {
        const activation = {kind};
        if (kind === 'relay') {
            if (!el('relay-consent').checked) throw new Error('Confirm forwarding consent first');
            const budget = Number(el('relay-budget').value);
            if (!Number.isSafeInteger(budget) || budget < 1) throw new Error('Enter a positive forwarding budget');
            activation.forwarding_limit_bps = budget;
        }
        renderModules(await request('/api/modules/enable', activation));
        feedback(`${kind === 'master' ? 'Master' : 'Relay'} enabled; the daemon verifies its capability before startup.`);
    }));
    el(`module-${kind}-disable`).addEventListener('click', event => action(event.currentTarget, async () => {
        renderModules(await request('/api/modules/disable', {kind}));
        feedback(`${kind === 'master' ? 'Master' : 'Relay'} disabled. The Base Node retains its identity and address.`);
    }));
}
el('module-refresh').addEventListener('click', event => action(event.currentTarget, async () => {await refresh(); feedback('Local state refreshed.');}));
el('authority-sync').addEventListener('click', event => action(event.currentTarget, async () => {
    el('authority-sync-status').textContent = 'Synchronizing with Supervisor...';
    try {
        await request('/api/authority/sync', {});
        el('authority-sync-status').textContent = `Last successful synchronization: ${new Date().toLocaleString()}`;
        await refresh(); feedback('Signed authority synchronized.');
    } catch(error) {
        el('authority-sync-status').textContent = 'Synchronization unavailable. This does not expire cached certificates.';
        throw error;
    }
}));
el('authority-import').addEventListener('click', event => action(event.currentTarget, async () => {
    const file = el('authority-file').files[0];
    if (!file || file.size > 60000) throw new Error('Choose a JSON authority package smaller than 60 KB');
    const context = JSON.parse(await file.text());
    await request('/api/authority/import', {context});
    await refresh(); feedback('Authority package verified and saved.');
}));
el('local-master-send').addEventListener('click', event => action(event.currentTarget, async () => {
    const operation = el('local-master-operation').value;
    const readOnly = ['fleet_inventory','list_jobs','list_runtimes','list_artifacts'].includes(operation);
    const bytes = new TextEncoder().encode(readOnly ? '' : JSON.stringify(JSON.parse(el('local-master-body').value)));
    const body_base64 = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''));
    const reply = await request('/api/local-master', {operation,body_base64});
    const content = new TextDecoder().decode(Uint8Array.from(atob(reply.body_base64), value => value.charCodeAt(0)));
    el('local-master-result').textContent = `HTTP ${reply.status}\n${content}`;
    if (reply.status >= 400) throw new Error('Master rejected the operation; see the response.');
    feedback('Local Master operation completed.');
}));
refresh().catch(error => feedback(error.message));
