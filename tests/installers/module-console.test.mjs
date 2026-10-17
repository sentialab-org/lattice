import {test} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('module console maps typed requests and refuses privileged host provisioning before IPC', async () => {
    const dir = await mkdtemp(join(tmpdir(),'lattice-modules-'));
    const socket = join(dir,'node.sock');
    const requests = [];
    const ipc = net.createServer(client => {
        let data = '';
        client.on('data', chunk => {
            data += chunk;
            if (!data.includes('\n')) return;
            const request = JSON.parse(data);
            requests.push(request);
            client.end(JSON.stringify({type: 'modules', data: []}) + '\n');
        });
    });
    await new Promise(resolve => ipc.listen(socket, resolve));
    const port = 18745;
    const child = spawn(process.execPath, ['web/node/server.mjs'], {
        cwd: new URL('../..', import.meta.url),
        env: {...process.env, LATTICE_SOCKET: socket, LATTICE_NODE_WEB_PORT: String(port), LATTICE_CONSOLE_TOKEN:'a'.repeat(64), LATTICE_CONSOLE_TEST_MODE:'1'},
        stdio: 'ignore'
    });
    const base = `http://127.0.0.1:${port}`;
    const post = (path, body) => fetch(base + path, {method:'POST', headers:{Origin:base,'Content-Type':'application/json',Cookie:`lattice_owner=${'a'.repeat(64)}`} ,body:JSON.stringify(body)});
    try {
        for (let i=0;i<60;i++) {try {await fetch(base);break;} catch {await new Promise(resolve=>setTimeout(resolve,50));}}
        assert.equal((await fetch(base+'/api/modules')).status,401);
        assert.equal((await fetch(base+'/api/modules',{headers:{Cookie:`lattice_owner=${'a'.repeat(64)}`}})).status,200);
        assert.equal(requests.at(-1).method,'get_modules');
        assert.equal((await post('/api/modules/enable',{kind:'relay',forwarding_limit_bps:1000000})).status,200);
        assert.deepEqual(requests.at(-1), {method:'enable_module',params:{activation:{kind:'relay',forwarding_limit_bps:1000000}}});
        assert.equal((await post('/api/modules/disable',{kind:'master'})).status,200);
        assert.equal(requests.at(-1).method,'disable_module');
        assert.equal((await fetch(base+'/api/network-manager',{headers:{Cookie:`lattice_owner=${'a'.repeat(64)}`}})).status,200);
        assert.equal(requests.at(-1).method,'get_network_manager');
        assert.equal((await post('/api/authority/sync',{})).status,200);
        assert.equal(requests.at(-1).method,'sync_authority');
        const context = {snapshot:null,certificates:[]};
        assert.equal((await post('/api/authority/import',{context})).status,200);
        assert.deepEqual(requests.at(-1),{method:'import_authority',params:{context}});
        const request = {operation:'list_nodes',body_base64:''};
        assert.equal((await post('/api/local-master',request)).status,200);
        assert.deepEqual(requests.at(-1),{method:'local_master',params:{request}});
        const count = requests.length;
        for (const activation of [
            {kind:'supervisor',authority_data_dir:'/private/authority'},
            {kind:'relay',adopt_gateway:true},
            {kind:'master',authority_data_dir:'/private/authority'},
            {kind:'supervisor'}
        ]) assert.equal((await post('/api/modules/enable',activation)).status,403);
        assert.equal((await post('/api/modules/disable',{kind:'supervisor'})).status,403);
        assert.equal(requests.length,count,'no privileged request may reach the root daemon');
        assert.equal((await post('/api/modules/enable',{kind:'unknown'})).status,400);
    } finally {
        child.kill(); await new Promise(resolve=>child.once('exit',resolve));
        await new Promise(resolve=>ipc.close(resolve));
        await rm(dir,{recursive:true,force:true});
    }
});
