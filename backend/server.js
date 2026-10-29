'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const { ScrubberController } = require('./controllers/scrubber_controller');

const PORT = process.env.PORT || 8099;
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
const controller = new ScrubberController();

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

function sendCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function sendJson(res, statusCode, data) {
  sendCors(res);
  const payload = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload)
  });
  res.end(payload);
}

function handleRequest(req, res) {
  sendCors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // API Endpoints
  if (req.method === 'GET' && pathname === '/api/rules') {
    return sendJson(res, 200, controller.handleRules());
  }

  if (req.method === 'GET' && pathname === '/api/samples') {
    return sendJson(res, 200, controller.handleSamples());
  }

  if (req.method === 'GET' && pathname === '/api/health') {
    return sendJson(res, 200, { status: 'healthy', service: 'leke-regex-pii-scrubber' });
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let payload = {};
      try {
        payload = body ? JSON.parse(body) : {};
      } catch (err) {
        return sendJson(res, 400, { status: 'error', message: 'Malformed JSON payload' });
      }

      if (pathname === '/api/scrub') {
        const result = controller.handleScrub(payload);
        return sendJson(res, result.status === 'error' ? 400 : 200, result);
      } else if (pathname === '/api/rehydrate') {
        const result = controller.handleRehydrate(payload);
        return sendJson(res, result.status === 'error' ? 400 : 200, result);
      } else if (pathname === '/api/entropy') {
        const result = controller.handleEntropy(payload);
        return sendJson(res, 200, result);
      } else {
        return sendJson(res, 404, { status: 'error', message: 'Endpoint not found' });
      }
    });
    return;
  }

  // Static Frontend Assets
  let relPath = pathname.replace(/^\//, '');
  if (!relPath || relPath === 'index.html') {
    relPath = 'index.html';
  }

  const filePath = path.join(FRONTEND_DIR, relPath);
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });
}

const server = http.createServer(handleRequest);
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🛡️  Leke PII & Secret Scrubber Studio running at: http://localhost:${PORT}`);
  console.log(`   Frontend assets served from: ${FRONTEND_DIR}`);
});
