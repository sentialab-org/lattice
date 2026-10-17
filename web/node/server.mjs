import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.LATTICE_NODE_WEB_PORT || '7444', 10);
const HOST = '127.0.0.1'; // Strictly bind loopback interface only (CRIT-05)
const SOCKET_PATH = process.env.LATTICE_SOCKET || (process.platform === 'win32' ? '\\\\.\\pipe\\lattice-node' : '/var/run/lattice/node.sock');
// Start this bridge as the local owner; the private launch link authenticates its browser session.
const CONSOLE_TOKEN = process.env.LATTICE_CONSOLE_TEST_MODE === '1' && /^[a-f0-9]{64}$/.test(process.env.LATTICE_CONSOLE_TOKEN || '')
    ? process.env.LATTICE_CONSOLE_TOKEN : crypto.randomBytes(32).toString('hex');
function ownerSession(req) {
    const cookies = (req.headers.cookie || '').split(';').map(value => value.trim());
    const bearer = req.headers.authorization;
    const value = bearer?.startsWith('Bearer ') ? bearer.slice(7) : cookies.find(value => value.startsWith('lattice_owner='))?.slice('lattice_owner='.length) || '';
    return /^[a-f0-9]{64}$/.test(value) && crypto.timingSafeEqual(Buffer.from(value), Buffer.from(CONSOLE_TOKEN));
}
const MAX_IPC_RESPONSE_SIZE = 96 * 1024 * 1024;
const MAX_BODY_SIZE = 64 * 1024; // 64 KB maximum request body limit (MED-14)

function sendIpcRequest(request) {
    return new Promise((resolve, reject) => {
        const client = net.connect(SOCKET_PATH, () => {
            client.write(JSON.stringify(request) + '\n');
        });

        let responseData = '';
        client.on('data', (chunk) => {
            if (Buffer.byteLength(responseData) + chunk.length > MAX_IPC_RESPONSE_SIZE) {
                client.destroy();
                reject(new Error('IPC response exceeds the supported size'));
                return;
            }
            responseData += chunk.toString();
            if (responseData.includes('\n')) {
                client.end();
            }
        });

        client.on('end', () => {
            try {
                const parsed = JSON.parse(responseData.trim());
                resolve(parsed);
            } catch (err) {
                reject(new Error('Invalid JSON from lattice-node'));
            }
        });

        client.on('error', (err) => {
            reject(new Error(`Cannot connect to lattice-node socket (${SOCKET_PATH}): ${err.message}`));
        });

        client.setTimeout(120000, () => {
            client.destroy();
            reject(new Error('IPC socket request timed out'));
        });
    });
}

function parseJsonBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        let totalSize = 0;

        req.on('data', chunk => {
            totalSize += chunk.length;
            if (totalSize > MAX_BODY_SIZE) {
                req.destroy(new Error('Payload Too Large'));
                return;
            }
            body += chunk;
        });

        req.on('end', () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (err) {
                reject(err);
            }
        });

        req.on('error', reject);
    });
}

const server = http.createServer(async (req, res) => {
    // Generate per-request cryptographic nonce to eliminate unsafe-inline script-src (MED-06)
    const nonce = crypto.randomBytes(16).toString('base64');
    const source = fs.readFileSync(path.join(__dirname,'index.html'),'utf8');
    const handlerHashes = [...source.matchAll(/on(?:click|change|input)="([^"]+)"/g)].map(m => `'sha256-${crypto.createHash('sha256').update(m[1]).digest('base64')}'`).join(' ');
    res.setHeader('Content-Security-Policy', `default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'nonce-${nonce}' 'unsafe-hashes' ${handlerHashes}; connect-src 'self'; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    const hostHeader = req.headers.host || '';
    const allowedHosts = [`127.0.0.1:${PORT}`, `localhost:${PORT}`];
    if (!allowedHosts.includes(hostHeader) || (req.headers.origin && req.headers.origin !== `http://${hostHeader}`) || (req.method === 'POST' && req.headers.origin !== `http://${hostHeader}`)) {
        res.writeHead(403, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Same-origin local access required'})); return;
    }
    const url = new URL(req.url, `http://${hostHeader || '127.0.0.1'}`);

    if (url.pathname.startsWith('/api/')) {
        res.setHeader('Cache-Control','no-store');
        if (!ownerSession(req)) {
            res.writeHead(401, {'Content-Type':'application/json'});
            res.end(JSON.stringify({error:'Open the private console launch link from the local owner terminal'})); return;
        }
        res.setHeader('Set-Cookie',`lattice_owner=${CONSOLE_TOKEN}; Path=/; HttpOnly; SameSite=Strict`);
    }
    try {
        if ((req.method === 'GET' || req.method === 'HEAD') && (url.pathname === '/' || url.pathname === '/index.html')) {
            const htmlPath = path.join(__dirname, 'index.html');
            if (!fs.existsSync(htmlPath)) {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('index.html not found');
                return;
            }
            let html = fs.readFileSync(htmlPath, 'utf8');
            html = html.replace(/<script>/g, `<script nonce="${nonce}">`);
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            if (req.method === 'HEAD') {
                res.end();
            } else {
                res.end(html);
            }
            return;
        }

        if (req.method === 'GET' && url.pathname === '/modules.mjs') {
            res.writeHead(200, {'Content-Type':'text/javascript; charset=utf-8','Cache-Control':'no-store'});
            res.end(fs.readFileSync(path.join(__dirname, 'modules.mjs'))); return;
        }
        const moduleRoute = {
            'GET /api/master-catalog': 'get_master_catalog',
            'GET /api/modules': 'get_modules',
            'GET /api/network-manager': 'get_network_manager',
            'POST /api/modules/enable': 'enable_module',
            'POST /api/modules/disable': 'disable_module',
            'POST /api/authority/import': 'import_authority',
            'POST /api/authority/sync': 'sync_authority',
            'POST /api/local-master': 'local_master'
        }[`${req.method} ${url.pathname}`];
        if (moduleRoute) {
            let params;
            if (req.method === 'POST') {
                const body = await parseJsonBody(req);
                if (!body || Array.isArray(body) || typeof body !== 'object') {
                    res.writeHead(400, {'Content-Type':'application/json'});
                    res.end(JSON.stringify({error:'A JSON object is required'})); return;
                }
                if (moduleRoute === 'enable_module' || moduleRoute === 'disable_module') {
                    if (body.kind === 'supervisor' || body.adopt_gateway || body.enable_network || body.authority_data_dir != null) {
                        res.writeHead(403, {'Content-Type':'application/json'});
                        res.end(JSON.stringify({error:'Supervisor provisioning and gateway adoption require an elevated local CLI'})); return;
                    }
                    if (!['master','relay'].includes(body.kind)) {
                        res.writeHead(400, {'Content-Type':'application/json'});
                        res.end(JSON.stringify({error:'Choose Master or Relay'})); return;
                    }
                    params = moduleRoute === 'enable_module' ? {activation: body} : {kind: body.kind};
                } else if (moduleRoute === 'import_authority') params = {context: body.context};
                else if (moduleRoute === 'local_master') params = {request: body};
            }
            const reply = await sendIpcRequest({method:moduleRoute,...(params?{params}:{})});
            res.writeHead(reply.type === 'error' ? 400 : 200, {'Content-Type':'application/json','Cache-Control':'no-store'});
            res.end(JSON.stringify(reply.data ?? {})); return;
        }
        const ownerRoute = {
            'GET /api/participation': 'get_participation',
            'POST /api/participation': 'accept_participation',
            'GET /api/masters': 'list_masters',
            'POST /api/master': 'select_master'
        }[`${req.method} ${url.pathname}`];
        if (ownerRoute) {
            const params = req.method === 'POST' ? await parseJsonBody(req) : undefined;
            const reply = await sendIpcRequest({method:ownerRoute,...(params?{params}:{})});
            res.writeHead(reply.type === 'error' ? 400 : 200, {'Content-Type':'application/json','Cache-Control':'no-store'});
            res.end(JSON.stringify(reply.data)); return;
        }
        if (req.method === 'POST' && url.pathname === '/api/setup') {
            const options = await parseJsonBody(req);
            const reply = await sendIpcRequest({method:'begin_setup',params:{options}});
            res.writeHead(reply.type === 'error' ? 400 : 200, {'Content-Type':'application/json','Cache-Control':'no-store'});
            res.end(JSON.stringify(reply.data)); return;
        }
        if (req.method === 'GET' && url.pathname === '/api/setup') {
            const reply = await sendIpcRequest({method:'get_setup_status'});
            res.writeHead(reply.type === 'error' ? 400 : 200, {'Content-Type':'application/json','Cache-Control':'no-store'});
            res.end(JSON.stringify(reply.data)); return;
        }
        if (req.method === 'GET' && url.pathname === '/api/status') {
            const ipcRes = await sendIpcRequest({ method: 'get_status' });
            if (ipcRes.type === 'error') {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: ipcRes.data.message }));
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(ipcRes.data));
            return;
        }

        if (req.method === 'GET' && url.pathname === '/api/miner_log') {
            const possiblePaths = [
                path.join(process.cwd(), 'data-node', 'miner.log'),
                path.join(process.cwd(), 'miner.log'),
                '/tmp/lattice-miner.log'
            ];
            let content = '';
            for (const p of possiblePaths) {
                if (fs.existsSync(p)) {
                    content = fs.readFileSync(p, 'utf8');
                    break;
                }
            }
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(content);
            return;
        }

        if (req.method === 'POST' && url.pathname === '/api/config') {
            const body = await parseJsonBody(req);
            const ipcRes = await sendIpcRequest({
                method: 'set_config',
                params: { config: body.config }
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(ipcRes));
            return;
        }

        if (req.method === 'POST' && url.pathname === '/api/enroll') {
            const body = await parseJsonBody(req);
            const ipcRes = await sendIpcRequest({
                method: 'enroll',
                params: {
                    control_url: body.control_url,
                    enrollment_token: body.enrollment_token
                }
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(ipcRes));
            return;
        }

        if (req.method === 'POST' && url.pathname === '/api/reset_enrollment') {
            const ipcRes = await sendIpcRequest({ method: 'reset_enrollment' });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(ipcRes));
            return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Endpoint not found' }));
    } catch (err) {
        if (err.message === 'Payload Too Large') {
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Payload Too Large' }));
            return;
        }
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
    }
});

server.listen(PORT, HOST, () => {
    console.log(`Private Lattice Node Console: http://${HOST}:${PORT}/#access=${CONSOLE_TOKEN}`);
    console.log(`Connected to IPC Socket: ${SOCKET_PATH}`);
});
