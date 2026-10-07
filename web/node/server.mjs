import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.LATTICE_NODE_WEB_PORT || '7444', 10);
const HOST = '127.0.0.1'; // Strictly bind loopback interface only (CRIT-05)
const SOCKET_PATH = process.env.LATTICE_SOCKET || (process.platform === 'win32' ? '\\\\.\\pipe\\lattice-node' : '/tmp/lattice-node.sock');
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
    // Restrictive Security Headers (MED-15)
    res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'; img-src 'self' data:;");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    // Strict origin validation: No wildcard CORS (CRIT-05)
    const hostHeader = req.headers.host || '';
    if (req.headers.origin) {
        try {
            const originUrl = new URL(req.headers.origin);
            if (originUrl.hostname !== '127.0.0.1' && originUrl.hostname !== 'localhost') {
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Cross-origin request forbidden' }));
                return;
            }
            res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Malformed Origin header' }));
            return;
        }
    }

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
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
            const html = fs.readFileSync(htmlPath, 'utf8');
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            if (req.method === 'HEAD') {
                res.end();
            } else {
                res.end(html);
            }
            return;
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
