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
const MAX_BODY_SIZE = 64 * 1024; // 64 KB maximum request body limit (MED-14)

function sendIpcRequest(request) {
    return new Promise((resolve, reject) => {
        const client = net.connect(SOCKET_PATH, () => {
            client.write(JSON.stringify(request) + '\n');
        });

        let responseData = '';
        client.on('data', (chunk) => {
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
                reject(new Error('Invalid JSON from lattice-node: ' + responseData));
            }
        });

        client.on('error', (err) => {
            reject(new Error(`Cannot connect to lattice-node socket (${SOCKET_PATH}): ${err.message}`));
        });

        client.setTimeout(4000, () => {
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
    console.log(`Lattice Node Console running on http://${HOST}:${PORT}`);
    console.log(`Connected to IPC Socket: ${SOCKET_PATH}`);
});
