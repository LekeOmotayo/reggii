/**
 * Leke PII Scrubber - Embedded Lightweight Demo Server
 * Serves the interactive web UI and provides REST API endpoints for PII scrubbing & rehydration.
 * Pure Node.js standard library (http, fs, path) - zero external dependencies.
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { PiiScrubber, PII_RULES, calculateShannonEntropy } = require('./scrubber');

const HERE = __dirname;

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

function handleRequest(req, res) {
  sendCors(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // 1. GET /api/rules
  if (req.method === 'GET' && pathname === '/api/rules') {
    const rulesSummary = PII_RULES.map(r => ({
      type: r.type,
      title: r.title,
      mask: r.mask
    }));
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(rulesSummary));
    return;
  }

  // 2. POST /api/scrub
  if (req.method === 'POST' && pathname === '/api/scrub') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const text = payload.text || '';
        const mode = payload.mode || 'mask';
        const entropyThreshold = typeof payload.entropyThreshold === 'number' ? payload.entropyThreshold : 3.8;

        const result = PiiScrubber.scrub(text, { mode, entropyThreshold });
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify(result));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // 3. POST /api/rehydrate
  if (req.method === 'POST' && pathname === '/api/rehydrate') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const text = payload.text || '';
        const vault = payload.vault || {};

        const rehydrated = PiiScrubber.rehydrate(text, vault);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ rehydrated }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // 4. Serve static files (/static/...)
  if (req.method === 'GET' && pathname.startsWith('/static/')) {
    const filePath = path.join(HERE, pathname);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath);
      const mime = MIME_TYPES[ext] || 'text/plain';
      res.writeHead(200, { 'Content-Type': mime });
      fs.createReadStream(filePath).pipe(res);
      return;
    }
  }

  // 5. Serve index.html
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    const indexPath = path.join(HERE, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(indexPath).pipe(res);
      return;
    }
  }

  // 6. 404
  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: 'Not Found' }));
}

function runServer(port = 8002) {
  const server = http.createServer(handleRequest);
  server.listen(port, '127.0.0.1', () => {
    console.log('='.repeat(72));
    console.log('  🛡️  LEKE PII & SHANNON ENTROPY SCRUBBER — Interactive Web Demo Server');
    console.log('='.repeat(72));
    console.log(`\n  🌐 Server running at:     http://localhost:${port}`);
    console.log(`  📄 REST Scrub API:        http://localhost:${port}/api/scrub`);
    console.log(`  🔄 REST Rehydrate API:    http://localhost:${port}/api/rehydrate`);
    console.log('\n  Press Ctrl+C to stop.\n');
  });
}

module.exports = { runServer };

if (require.main === module) {
  const port = process.argv[2] ? parseInt(process.argv[2], 10) : 8002;
  runServer(port);
}
