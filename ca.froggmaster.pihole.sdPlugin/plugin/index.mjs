import WebSocket from 'ws';
import { appendFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { request as httpReq } from 'http';
import { request as httpsReq } from 'https';

const __dirname = dirname(fileURLToPath(import.meta.url));
const logDir = join(__dirname, '..', 'log');
mkdirSync(logDir, { recursive: true });

let websocket = null;
const instances = {};
const pendingAuth = {}; // deduplicates simultaneous auth calls to the same server

// write to the log
function log(message) {
    const now = new Date();
    const file = join(logDir, `${now.getFullYear()}.${now.getMonth() + 1}.${now.getDate()}.log`);
    const entry = `[${now.toISOString()}] ${message}\n`;
    process.stdout.write(entry);
    appendFileSync(file, entry);
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        send({ event: 'logMessage', payload: { message } });
    }
}

// send some data over the websocket
function send(data) {
    websocket.send(JSON.stringify(data));
}

// make an HTTP/HTTPS request and return the response body as a string,
// following redirects automatically (matching XMLHttpRequest browser behaviour)
function makeRequest(method, url, headers = {}, body = null, timeout = 30000, maxRedirects = 5) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const isHttps = u.protocol === 'https:';
        const bodyBuf = body ? Buffer.from(body, 'utf8') : null;
        const opts = {
            hostname: u.hostname,
            port: u.port || (isHttps ? 443 : 80),
            path: u.pathname + u.search,
            method,
            headers: { ...headers }
        };
        if (bodyBuf) {
            opts.headers['Content-Length'] = bodyBuf.length;
        }
        const req = (isHttps ? httpsReq : httpReq)(opts, res => {
            if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
                res.resume(); // discard body
                if (maxRedirects === 0) {
                    reject(new Error('too many redirects'));
                    return;
                }
                const redirectUrl = new URL(res.headers.location, url).toString();
                log(`[makeRequest] redirect ${res.statusCode} → ${redirectUrl}`);
                makeRequest(method, redirectUrl, headers, body, timeout, maxRedirects - 1)
                    .then(resolve).catch(reject);
                return;
            }
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        });
        req.setTimeout(timeout, () => req.destroy(new Error('timeout')));
        req.on('error', reject);
        if (bodyBuf) req.write(bodyBuf);
        req.end();
    });
}

// get auth token from pi-hole API
async function pihole_connect(settings, handler) {
    const req_addr = `${settings.protocol}://${settings.ph_addr}/api/auth`;
    log(`[pihole_connect] POST ${req_addr}`);
    try {
        const raw = await makeRequest('POST', req_addr,
            { 'Content-Type': 'application/json' },
            JSON.stringify({ password: settings.ph_key })
        );
        const data = JSON.parse(raw);
        log(`[pihole_connect] response: ${JSON.stringify(data)}`);
        handler(data);
    } catch (err) {
        log(`[pihole_connect] error or timeout connecting to ${req_addr}: ${err.message}`);
        handler({ error: "couldn't authenticate to Pi-hole" });
    }
}

// delete pi-hole session since API seats are limited
function pihole_end({ settings, session }) {
    if (!session) return;
    const req_addr = `${settings.protocol}://${settings.ph_addr}/api/auth`;
    log(`[pihole_end] DELETE ${req_addr}`);
    makeRequest('DELETE', req_addr, { 'X-FTL-SID': session.sid })
        .catch(err => log(`[pihole_end] error: ${err.message}`));
}

// wraps pihole_connect to collapse simultaneous calls to the same server into one,
// and retries automatically when pi-hole rate-limits login attempts
function pihole_connect_once(settings, handler) {
    const key = `${settings.protocol}://${settings.ph_addr}`;
    if (key in pendingAuth) {
        pendingAuth[key].push(handler);
        log(`[pihole_connect_once] queued for ${key} (${pendingAuth[key].length} waiting)`);
        return;
    }
    pendingAuth[key] = [handler];
    function attempt() {
        pihole_connect(settings, response => {
            if (response.error && response.error.key === 'rate_limiting') {
                log(`[pihole_connect_once] rate limited for ${key}, retrying in 60s`);
                setTimeout(attempt, 60000);
            } else {
                const handlers = pendingAuth[key] || [];
                delete pendingAuth[key];
                handlers.forEach(h => h(response));
            }
        });
    }
    attempt();
}

// make a call to check if pi-hole is enabled
async function getBlockingStatus(settings, session, handler) {
    if (!session) {
        log(`[getBlockingStatus] no active session, skipping`);
        handler({ error: 'no active session' });
        return;
    }
    const req_addr = `${settings.protocol}://${settings.ph_addr}/api/dns/blocking`;
    log(`[getBlockingStatus] GET ${req_addr}`);
    try {
        const raw = await makeRequest('GET', req_addr, { 'X-FTL-SID': session.sid });
        const data = JSON.parse(raw);
        log(`[getBlockingStatus] response: ${JSON.stringify(data)}`);
        handler(data);
    } catch (err) {
        log(`[getBlockingStatus] error connecting to ${req_addr}: ${err.message}`);
        handler({ error: "couldn't reach Pi-hole" });
    }
}

// make a call to enable or disable pi-hole
function setBlockingStatus(settings, session, enabled, timer) {
    if (!session) {
        log(`[setBlockingStatus] no active session, skipping`);
        return;
    }
    const req_addr = `${settings.protocol}://${settings.ph_addr}/api/dns/blocking`;
    const body = JSON.stringify({ blocking: enabled, timer });
    log(`[setBlockingStatus] POST ${req_addr} body=${body}`);
    makeRequest('POST', req_addr,
        { 'Content-Type': 'application/json', 'X-FTL-SID': session.sid },
        body
    ).catch(err => log(`[setBlockingStatus] error: ${err.message}`));
}

// get stats for the pi-hole (# queries, # clients, etc.) and pass to a handler function
async function getStatsSummary(settings, session, handler) {
    if (!session) {
        log(`[getStatsSummary] no active session, skipping`);
        handler({ error: 'no active session' });
        return;
    }
    const req_addr = `${settings.protocol}://${settings.ph_addr}/api/stats/summary`;
    log(`[getStatsSummary] GET ${req_addr}`);
    try {
        const raw = await makeRequest('GET', req_addr, { 'X-FTL-SID': session.sid });
        const data = JSON.parse(raw);
        log(`[getStatsSummary] response: ${JSON.stringify(data)}`);
        handler(data);
    } catch (err) {
        log(`[getStatsSummary] error connecting to ${req_addr}: ${err.message}`);
        handler({ error: "couldn't reach Pi-hole" });
    }
}

// event handler for ca.froggmaster.pihole.temporarily-disable
function temporarily_disable(context) {
    log(`[temporarily_disable] button pressed`);
    const { settings, session } = instances[context];
    getBlockingStatus(settings, session, response => {
        if (response.blocking === 'enabled') { // it only makes sense to temporarily disable p-h if it's currently enabled
            log(`[temporarily_disable] disabling for ${settings.disable_time}s`);
            setBlockingStatus(settings, session, false, parseInt(settings.disable_time));
        } else {
            log(`[temporarily_disable] skipping - blocking is already ${response.blocking}`);
        }
    });
}

// event handler for ca.froggmaster.pihole.toggle
function toggle(context) {
    log(`[toggle] button pressed`);
    const { settings, session } = instances[context];
    getBlockingStatus(settings, session, response => {
        if (response.blocking === 'disabled') {
            log(`[toggle] enabling blocking`);
            setBlockingStatus(settings, session, true);
            setState(context, 0);
        } else if (response.blocking === 'enabled') {
            log(`[toggle] disabling blocking`);
            setBlockingStatus(settings, session, false);
            setState(context, 1);
        }
    });
}

// event handler for ca.froggmaster.pihole.disable
function disable(context) {
    log(`[disable] button pressed`);
    const { settings, session } = instances[context];
    setBlockingStatus(settings, session, false);
}

// event handler for ca.froggmaster.pihole.enable
function enable(context) {
    log(`[enable] button pressed`);
    const { settings, session } = instances[context];
    setBlockingStatus(settings, session, true);
}

// poll p-h and set the state and button text appropriately
// (called once per second per instance)
function pollPihole(context) {
    const { settings, session } = instances[context];
    getBlockingStatus(settings, session, response => {
        if ('error' in response) { // couldn't reach p-h, display a warning
            log(`[pollPihole] error: ${JSON.stringify(response)}`);
            send({ event: 'showAlert', context });
        } else {
            // set state according to whether p-h is enabled or disabled
            if (response.blocking === 'disabled' && settings.show_status) {
                setState(context, 1);
            } else if (response.blocking === 'enabled' && settings.show_status) {
                setState(context, 0);
            }

            // display stat, if desired
            if (settings.stat === 'timer') {
                const title = process_timer(response.timer);
                send({ event: 'setTitle', context, payload: { title } });
            } else if (settings.stat !== 'none') {
                getStatsSummary(settings, session, response => {
                    if ('error' in response) {
                        log(`[pollPihole] stats error: ${JSON.stringify(response)}`);
                        send({ event: 'showAlert', context });
                    } else {
                        const stat = process_stat(response, settings.stat);
                        send({ event: 'setTitle', context, payload: { title: stat } });
                    }
                });
            }
        }
    });
}

// process the pi-hole stats to make them more human-readable,
// then cast to string
function process_stat(stats, type) {
    switch (type) {
        case 'domains_being_blocked': return stats.gravity.domains_being_blocked.toLocaleString();
        case 'dns_queries_today':     return stats.queries.total.toLocaleString();
        case 'ads_blocked_today':     return stats.queries.blocked.toLocaleString();
        case 'ads_percentage_today':  return stats.queries.percent_blocked.toFixed(2) + '%';
        case 'unique_domains':        return stats.queries.unique_domains.toLocaleString();
        case 'queries_forwarded':     return stats.queries.forwarded.toLocaleString();
        case 'queries_cached':        return stats.queries.cached.toLocaleString();
        case 'clients_ever_seen':     return stats.clients.total.toLocaleString();
        case 'unique_clients':        return stats.clients.active.toLocaleString();
    }
}

// format remaining timer seconds into a human-readable string
function process_timer(seconds) {
    if (!seconds) return '';
    const m = Math.floor(seconds / 60);
    const s = Math.floor(seconds % 60);
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

// change the state of a button (param "state" should be either 0 or 1)
function setState(context, state) {
    send({ event: 'setState', context, payload: { state } });
}

// write settings
function writeSettings(context, action, settings) {
    log(`[writeSettings] action=${action} settings=${JSON.stringify(settings)}`);
    if (!(context in instances)) {
        instances[context] = { action };
    }
    instances[context].settings = settings;
    if (instances[context].settings.ph_addr === '') {
        instances[context].settings.ph_addr = 'pi.hole';
    }
    if (instances[context].settings.stat === 'none') {
        send({ event: 'setTitle', context, payload: { title: '' } });
    }

    // clean up old p-h instance
    if ('poller' in instances[context]) {
        clearInterval(instances[context].poller);
    }
    pihole_end(instances[context]);

    // poll p-h to get status
    instances[context].settings.show_status = true;
    const onReady = response => {
        log(`[writeSettings] auth response: ${JSON.stringify(response)}`);
        if ('error' in response || !response.session?.valid) {
            log(`[writeSettings] auth failed: ${JSON.stringify(response)}`);
            instances[context].session = null;
            send({ event: 'showAlert', context });
            setTimeout(() => {
                if (context in instances) {
                    pihole_connect_once(instances[context].settings, onReady);
                }
            }, 30000);
            return;
        }
        instances[context].session = response.session;
        instances[context].poller = setInterval(() => {
            const timeNow = Math.floor(Date.now() / 1000);
            const sessionExpired = 'lastUpdateTime' in instances[context] &&
                (timeNow - instances[context].lastUpdateTime) > instances[context].session.validity;
            instances[context].lastUpdateTime = timeNow;
            if (sessionExpired) {
                clearInterval(instances[context].poller);
                pihole_connect_once(instances[context].settings, onReady);
            } else {
                pollPihole(context);
            }
        }, 1000);
        log(`[writeSettings] session established: ${JSON.stringify(instances[context].session)}`);
    };
    pihole_connect_once(instances[context].settings, onReady);
}

// parse Stream Deck launch arguments (-port, -pluginUUID, -registerEvent, -info)
const args = process.argv.slice(2);
const argMap = {};
for (let i = 0; i < args.length - 1; i++) {
    if (args[i].startsWith('-')) {
        argMap[args[i].slice(1)] = args[i + 1];
    }
}

const port = argMap['port'];
const pluginUUID = argMap['pluginUUID'];
const registerEvent = argMap['registerEvent'];

log(`[main] starting, port=${port} pluginUUID=${pluginUUID}`);

websocket = new WebSocket(`ws://localhost:${port}`);

websocket.on('open', () => {
    websocket.send(JSON.stringify({ event: registerEvent, uuid: pluginUUID }));
    log(`[main] websocket connected and plugin registered`);
});

websocket.on('close', () => {
    log(`[main] websocket closed`);
});

websocket.on('error', err => {
    log(`[main] websocket error: ${err.message}`);
});

// message handler
websocket.on('message', data => {
    const jsonObj = JSON.parse(data.toString());
    const { event, action, context } = jsonObj;

    log(`[onmessage] action=${action} event=${event}`);

    // update settings for this instance
    if (event === 'didReceiveSettings') {
        writeSettings(context, action, jsonObj.payload.settings);
    }

    // apply settings when the action appears
    else if (event === 'willAppear') {
        writeSettings(context, action, jsonObj.payload.settings);
    }

    // stop polling and delete settings when the action disappears
    else if (event === 'willDisappear') {
        if ('poller' in instances[context]) {
            clearInterval(instances[context].poller);
        }
        pihole_end(instances[context]);
        delete instances[context];
    }

    // handle a keypress
    else if (event === 'keyUp') {
        if (action === 'ca.froggmaster.pihole.toggle') {
            toggle(context);
        } else if (action === 'ca.froggmaster.pihole.temporarily-disable') {
            temporarily_disable(context);
        } else if (action === 'ca.froggmaster.pihole.disable') {
            disable(context);
        } else if (action === 'ca.froggmaster.pihole.enable') {
            enable(context);
        }
    }
});
