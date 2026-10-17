import {useEffect, useState} from 'react';
import {invoke} from '@tauri-apps/api/core';

type ModuleKind = 'master'|'relay'|'supervisor';
type ModuleStatus = {kind:ModuleKind;enabled:boolean;state:string;error_code:string|null;certificate_id:string|null};
type NetworkOwner = {owner_process_id:number;interface_name:string|null;desired_revision:number;applied_revision:number|null;error_code:string|null};
const errorText = (error:unknown) => typeof error === 'string' ? error : error instanceof Error ? error.message : 'Operation failed';
export function ModuleControls({online,accepted}:{online:boolean;accepted:boolean}) {
    const [modules,setModules] = useState<ModuleStatus[]>([]);
    const [network,setNetwork] = useState<NetworkOwner|null>(null);
    const [busy,setBusy] = useState(false);
    const [feedback,setFeedback] = useState('Reading local module state');
    const [sync,setSync] = useState('Synchronization has not been requested. Cached certificates retain their signed validity.');
    const [relayConsent,setRelayConsent] = useState(false);
    const [budget,setBudget] = useState('8000000');
    const [authorityFile,setAuthorityFile] = useState<File|null>(null);
    const [operation,setOperation] = useState('fleet_inventory');
    const [body,setBody] = useState('{}');
    const [result,setResult] = useState('');
    async function refresh() {
        const [next,owner] = await Promise.all([invoke<ModuleStatus[]>('get_modules'),invoke<NetworkOwner>('get_network_manager')]);
        setModules(next);setNetwork(owner);
    }
    useEffect(()=>{if(online)refresh().catch(error=>setFeedback(errorText(error)));},[online]);
    async function action(task:()=>Promise<void>) {
        setBusy(true);setFeedback('Working...');
        try {await task();} catch(error) {setFeedback(errorText(error));} finally {setBusy(false);}
    }
    async function toggle(kind:'master'|'relay',enabled:boolean) {
        const activation:{kind:ModuleKind;forwarding_limit_bps?:number} = {kind};
        if(enabled&&kind==='relay') {
            const value = Number(budget);
            if(!relayConsent||!Number.isSafeInteger(value)||value<1)throw new Error('Confirm forwarding consent and enter a positive budget');
            activation.forwarding_limit_bps=value;
        }
        setModules(await invoke<ModuleStatus[]>(enabled?'enable_module':'disable_module',enabled?{activation}:{kind}));
        setFeedback(`${kind==='master'?'Master':'Relay'} ${enabled?'enabled; capability verification is required before startup':'disabled; the Base Node keeps its identity and address'}.`);
    }
    return <section className="cache-section module-controls" aria-label="Optional node modules">
      <div className="cache-section-head"><span>Base Node and optional modules</span><small>One identity, address and network owner per device</small></div>
      <p>{network?`Network owner ${network.owner_process_id} · ${network.interface_name??'not configured'} · desired ${network.desired_revision}, applied ${network.applied_revision??'pending'}${network.error_code?' · '+network.error_code:''}`:'Network owner not yet available'}</p>
      {(['master','relay','supervisor'] as const).map(kind=>{const module=modules.find(m=>m.kind===kind);return <div className="module-row" key={kind}>
        <div><strong>{kind==='master'?'Master':kind==='relay'?'Relay':'Supervisor'}</strong><p>{module?`${module.state}${module.certificate_id?` · certificate ${module.certificate_id}`:''}${module.error_code?' · '+module.error_code:''}`:'Reading state...'}</p></div>
        {kind==='supervisor'?<small>Provision or disable using an elevated local CLI. Authority keys remain isolated.</small>:<div className="save-row"><button disabled={!online||!accepted||busy||(kind==='relay'&&!relayConsent)} onClick={()=>action(()=>toggle(kind,true))}>Enable {kind==='master'?'Master':'Relay'}</button><button disabled={!online||busy} onClick={()=>action(()=>toggle(kind,false))}>Disable {kind==='master'?'Master':'Relay'}</button></div>}
      </div>;})}
      <label className="field"><span>Relay forwarding budget in bits per second</span><input type="number" min="1" step="1" value={budget} onChange={event=>setBudget(event.target.value)}/></label>
      <label><input type="checkbox" checked={relayConsent} onChange={event=>setRelayConsent(event.target.checked)}/> I allow overlay forwarding within this budget and the signed Relay grant.</label>
      <div className="save-row"><button disabled={!online||busy} onClick={()=>action(async()=>{await refresh();setFeedback('Local state refreshed.');})}>Refresh local state</button><button disabled={!online||busy} onClick={()=>action(async()=>{setSync('Synchronizing with Supervisor...');try{await invoke('sync_authority');setSync(`Last successful synchronization: ${new Date().toLocaleString()}`);await refresh();setFeedback('Signed authority synchronized.');}catch(error){setSync('Synchronization unavailable. This does not expire cached certificates.');throw error;}})}>Synchronize authority</button></div>
      <p role="status">{sync}</p>
      <label className="field"><span>Issued authority package</span><input type="file" accept="application/json,.json" onChange={event=>setAuthorityFile(event.target.files?.[0]??null)}/></label><button disabled={!online||busy||!authorityFile} onClick={()=>action(async()=>{if(!authorityFile||authorityFile.size>60000)throw new Error('Choose a JSON package smaller than 60 KB');await invoke('import_authority',{context:JSON.parse(await authorityFile.text())});await refresh();setFeedback('Authority package verified and saved.');})}>Import and verify package</button>
      <p role="status" aria-live="polite">{feedback}</p>
      <details><summary>Local Master administration</summary><div className="module-controls"><p>Use the local Master with cached authority while Supervisor is unavailable.</p>
        <label className="field"><span>Operation</span><select value={operation} onChange={event=>setOperation(event.target.value)}><option value="fleet_inventory">Fleet inventory</option><option value="list_jobs">List jobs</option><option value="list_runtimes">List runtimes</option><option value="list_artifacts">List artifacts</option><option value="queue_mining">Queue mining workload</option><option value="control_job">Change job resources or pause state</option><option value="cancel_job">Cancel job</option></select></label>
        <label className="field"><span>Request body (JSON, for workload changes)</span><textarea rows={5} value={body} onChange={event=>setBody(event.target.value)}/></label>
        <button disabled={!online||busy} onClick={()=>action(async()=>{const readOnly=['fleet_inventory','list_jobs','list_runtimes','list_artifacts'].includes(operation);const bytes=new TextEncoder().encode(readOnly?'':JSON.stringify(JSON.parse(body)));const reply=await invoke<{status:number;body_base64:string}>('local_master',{requestData:{operation,body_base64:btoa(Array.from(bytes,byte=>String.fromCharCode(byte)).join(''))}});setResult(`HTTP ${reply.status}\n${new TextDecoder().decode(Uint8Array.from(atob(reply.body_base64),char=>char.charCodeAt(0)))}`);if(reply.status>=400)throw new Error('Master rejected the operation; see the response.');setFeedback('Local Master operation completed.');})}>Run selected operation</button><pre role="status">{result}</pre>
      </div></details>
    </section>;
}
