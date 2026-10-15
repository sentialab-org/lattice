import {authenticatedFetch} from './auth.js';
export function buildInstallCommand({siteBase = 'https://lattice.sentialab.org', os, role = 'node', version = ''}) {
  if (!/^https:\/\/[A-Za-z0-9.-]+(?::[0-9]+)?$/.test(siteBase)) throw new Error('Use a valid HTTPS site origin');
  if (!['macos', 'linux', 'windows'].includes(os) || !['node', 'master'].includes(role)) throw new Error('Select an operating system and role');
  if (version && !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(version)) throw new Error('Use a valid release version or leave it empty');
  if (os === 'windows') return `$env:LATTICE_ROLE='${role}'; $env:LATTICE_SITE_BASE='${siteBase}'; ${version ? `$env:LATTICE_VERSION='${version}'; ` : ''}irm '${siteBase}/installer/windows.ps1' | iex`;
  return `curl -fsSL '${siteBase}/installer/${os}.sh' | env LATTICE_ROLE='${role}' LATTICE_SITE_BASE='${siteBase}'${version ? ` LATTICE_VERSION='${version}'` : ''} bash`;
}
export async function refreshTokens() {
  const response = await authenticatedFetch('/api/v1/operator/master-tokens');
  if (!response.ok) return;
  const target = document.getElementById('master-tokens'); if (!target) return;
  target.replaceChildren();
  for (const token of await response.json()) {
    const row = document.createElement('div'); row.style.cssText='display:flex;gap:1rem;align-items:center;padding:8px 0;border-bottom:1px solid #333';
    const label = document.createElement('span'); label.textContent = `${token.label} · ${token.revoked_at_ms ? 'Revoked' : token.activated_node_id ? 'Activated' : 'Available'} · expires ${new Date(token.expires_at_ms).toLocaleString()}`; row.append(label);
    if (!token.revoked_at_ms && !token.activated_node_id) { const button = document.createElement('button'); button.className='btn-term'; button.textContent='Revoke token'; button.setAttribute('aria-label', `Revoke ${token.label}`); button.onclick=async()=>{const r=await authenticatedFetch('/api/v1/operator/master-tokens/revoke',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token_id:token.token_id})});if(r.ok)await refreshTokens();}; row.append(button); }
    target.append(row);
  }
}
export async function refreshMasters() {
  const target=document.getElementById('master-directory');if(!target)return;
  const response=await authenticatedFetch('/api/v1/operator/masters');
  if(!response.ok){target.textContent='Master directory is unavailable.';return;}
  const {directory}=await response.json();target.replaceChildren();
  if(!directory.masters.length){target.textContent='No activated masters. Install a master using an activation token.';return;}
  for(const {grant} of directory.masters){
    const row=document.createElement('div');row.style.cssText='display:flex;gap:1rem;align-items:center;flex-wrap:wrap;padding:8px 0;border-bottom:1px solid #333';
    const label=document.createElement('span');label.textContent=`${grant.control_id} · ${grant.node_id} · ${grant.overlay_ipv4} · ${directory.active_master_id===grant.control_id?'Active':'Standby'}`;row.append(label);
    for(const [action,text] of [['active','Designate'],['revoke','Revoke management']]){
      if(action==='active'&&directory.active_master_id===grant.control_id)continue;
      const button=document.createElement('button');button.className='btn-term';button.textContent=text;button.setAttribute('aria-label',`${text} ${grant.control_id}`);
      button.onclick=async()=>{button.disabled=true;try{const r=await authenticatedFetch(`/api/v1/operator/masters/${action}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({control_id:grant.control_id})});if(!r.ok)throw new Error('Master update failed');await refreshMasters();}catch(e){document.getElementById('master-management-error').textContent=e.message;button.disabled=false;}};row.append(button);
    }
    target.append(row);
  }
}
export async function createToken() {
  const label=document.getElementById('master-token-label');
  const r=await authenticatedFetch('/api/v1/operator/master-tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:label.value})});
  if(!r.ok)throw new Error('Token creation failed');
  const data=await r.json();const output=document.getElementById('created-master-token');output.value=data.activation_token;document.getElementById('token-once').hidden=false;await refreshTokens();
}
export function dismissToken(){const o=document.getElementById('created-master-token');if(o)o.value='';const panel=document.getElementById('token-once');if(panel)panel.hidden=true;}
