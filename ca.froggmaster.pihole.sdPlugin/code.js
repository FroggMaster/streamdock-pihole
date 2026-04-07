var websocket = null;
var instances = {};
var pendingAuth = {}; // deduplicates simultaneous auth calls to the same server

// send some data over the websocket
function send(data){
    websocket.send(JSON.stringify(data));
}

// write to the log
function log(message){
    const entry = `${new Date().toISOString()} ${message}`;
    console.log(entry);
    // post to local log server (run Start-LogServer.ps1 to receive)
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "http://localhost:9999/", true);
    xhr.send(entry);
    if (websocket && websocket.readyState === WebSocket.OPEN){
        send({
            "event": "logMessage",
            "payload": {
                "message": message
            }
        });
    }
}

// get auth token from pi-hole API that is valid until 5 min of inactivity
function pihole_connect(settings, handler){
    let req_addr = `${settings.protocol}://${settings.ph_addr}/api/auth`;
    log(`[pihole_connect] POST ${req_addr}`);
    let xhr = new XMLHttpRequest();
    xhr.timeout = 30000;
    xhr.open("POST", req_addr);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = function(){
        let data = JSON.parse(xhr.response);
        log(`[pihole_connect] response: ${JSON.stringify(data)}`);
        handler(data);
    }
    xhr.onerror = xhr.ontimeout = function(){
        log(`[pihole_connect] error or timeout connecting to ${req_addr}`);
        handler({"error": "couldn't authenticate to Pi-hole"});
    }
    xhr.send(JSON.stringify({ password: settings.ph_key }));
}

// delete pi-hole session since API seats are limited
function pihole_end({ settings, session }){
    if (session == null) return;
    let req_addr = `${settings.protocol}://${settings.ph_addr}/api/auth`;
    log(`[pihole_end] DELETE ${req_addr}`);
    let xhr = new XMLHttpRequest();
    xhr.open("DELETE", req_addr);
    xhr.setRequestHeader("X-FTL-SID", session.sid);
    xhr.send();
}

// wraps pihole_connect to collapse simultaneous calls to the same server into one,
// and retries automatically when pi-hole rate-limits login attempts
function pihole_connect_once(settings, handler){
    const key = `${settings.protocol}://${settings.ph_addr}`;
    if (key in pendingAuth){
        pendingAuth[key].push(handler);
        log(`[pihole_connect_once] queued for ${key} (${pendingAuth[key].length} waiting)`);
        return;
    }
    pendingAuth[key] = [handler];
    function attempt(){
        pihole_connect(settings, response => {
            if (response.error && response.error.key === "rate_limiting"){
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
function getBlockingStatus(settings, session, handler){
    if (!session) {
        log(`[getBlockingStatus] no active session, skipping`);
        handler({"error": "no active session"});
        return;
    }
    let req_addr = `${settings.protocol}://${settings.ph_addr}/api/dns/blocking`;
    log(`[getBlockingStatus] GET ${req_addr}`);
    let xhr = new XMLHttpRequest();
    xhr.open("GET", req_addr);
    xhr.setRequestHeader("X-FTL-SID", session.sid);
    xhr.onload = function(){
        let data = JSON.parse(xhr.response);
        log(`[getBlockingStatus] response: ${JSON.stringify(data)}`);
        handler(data);
    }
    xhr.onerror = function(){
        log(`[getBlockingStatus] error connecting to ${req_addr}`);
        handler({"error": "couldn't reach Pi-hole"});
    }
    xhr.send();
}

// make a call to enable or disable pi-hole
function setBlockingStatus(settings, session, enabled, timer){
    if (!session) {
        log(`[setBlockingStatus] no active session, skipping`);
        return;
    }
    let req_addr = `${settings.protocol}://${settings.ph_addr}/api/dns/blocking`;
    let body = JSON.stringify({ blocking: enabled, timer });
    log(`[setBlockingStatus] POST ${req_addr} body=${body}`);
    let xhr = new XMLHttpRequest();
    xhr.open("POST", req_addr);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.setRequestHeader("X-FTL-SID", session.sid);
    xhr.send(body);
}

// get stats for the pi-hole (# queries, # clients, etc.) and pass to a handler function
function getStatsSummary(settings, session, handler){
    if (!session) {
        log(`[getStatsSummary] no active session, skipping`);
        handler({"error": "no active session"});
        return;
    }
    let req_addr = `${settings.protocol}://${settings.ph_addr}/api/stats/summary`;
    log(`[getStatsSummary] GET ${req_addr}`);
    let xhr = new XMLHttpRequest();
    xhr.open("GET", req_addr);
    xhr.setRequestHeader("X-FTL-SID", session.sid);
    xhr.onload = function(){
        let data = JSON.parse(xhr.response);
        log(`[getStatsSummary] response: ${JSON.stringify(data)}`);
        handler(data);
    }
    xhr.onerror = function(){
        log(`[getStatsSummary] error connecting to ${req_addr}`);
        handler({"error": "couldn't reach Pi-hole"});
    }
    xhr.send();
}

// event handler for ca.froggmaster.pihole.temporarily-disable
function temporarily_disable(context){
    log(`[temporarily_disable] button pressed`);
    let { settings, session } = instances[context];
    getBlockingStatus(settings, session, response => {
        if (response.blocking == "enabled"){  // it only makes sense to temporarily disable p-h if it's currently enabled
            log(`[temporarily_disable] disabling for ${settings.disable_time}s`);
            setBlockingStatus(settings, session, false, parseInt(settings.disable_time))
        }
        else {
            log(`[temporarily_disable] skipping - blocking is already ${response.blocking}`);
        }
    });
}

// event handler for ca.froggmaster.pihole.toggle
function toggle(context){
    log(`[toggle] button pressed`);
    let { settings, session } = instances[context];
    getBlockingStatus(settings, session, response => {
        if (response.blocking == "disabled"){
            log(`[toggle] enabling blocking`);
            setBlockingStatus(settings, session, true);
            setState(context, 0);
        }
        else if (response.blocking == "enabled"){
            log(`[toggle] disabling blocking`);
            setBlockingStatus(settings, session, false);
            setState(context, 1);
        }
    });
}

// event handler for ca.froggmaster.pihole.disable
function disable(context){
    log(`[disable] button pressed`);
    let { settings, session } = instances[context];
    setBlockingStatus(settings, session, false);
}

// event handler for ca.froggmaster.pihole.enable
function enable(context){
    log(`[enable] button pressed`);
    let { settings, session } = instances[context];
    setBlockingStatus(settings, session, true);
}

// poll p-h and set the state and button text appropriately
// (called once per second per instance)
function pollPihole(context){
    let { settings, session } = instances[context];
    getBlockingStatus(settings, session, response => {
        if ("error" in response){ // couldn't reach p-h, display a warning
            log(`[pollPihole] error: ${JSON.stringify(response)}`);
            send({
                "event": "showAlert",
                "context": context
            });
        }
        else{
            // set state according to whether p-h is enabled or disabled
            if (response.blocking == "disabled" && settings.show_status){
                setState(context, 1);
            }
            else if (response.blocking == "enabled" && settings.show_status){
                setState(context, 0);
            }

            // display stat, if desired
            if (settings.stat != "none"){
                getStatsSummary(settings, session, response => {
                    if ("error" in response){
                        log(`[pollPihole] stats error: ${JSON.stringify(response)}`);
                        send({
                            "event": "showAlert",
                            "context": context
                        });
                    }
                    else{
                        let stat = process_stat(response, settings.stat);
                        send({
                            "event": "setTitle",
                            "context": context,
                            "payload": {
                                "title": stat
                            }
                        });
                    }
                });
            }
        }
    });
}

// process the pi-hole stats to make them more human-readable,
// then cast to string
function process_stat(stats, type){
    switch (type){
        case "domains_being_blocked":
            return stats.gravity.domains_being_blocked.toLocaleString();
        case "dns_queries_today":
            return stats.queries.total.toLocaleString();
        case "ads_blocked_today":
            return stats.queries.blocked.toLocaleString();
        case "ads_percentage_today":
            return stats.queries.percent_blocked.toFixed(2) + "%";
        case "unique_domains":
            return stats.queries.unique_domains.toLocaleString();
        case "queries_forwarded":
            return stats.queries.forwarded.toLocaleString();
        case "queries_cached":
            return stats.queries.cached.toLocaleString();
        case "clients_ever_seen":
            return stats.clients.total.toLocaleString();
        case "unique_clients":
            return stats.clients.active.toLocaleString();
    }
}

// change the state of a button (param "state" should be either 0 or 1)
function setState(context, state){
    let json = {
        "event" : "setState",
        "context" : context,
        "payload" : {
            "state" : state
        }
    };
    websocket.send(JSON.stringify(json));
}

// update the p-h address, API key, or disable time
function updateSettings(payload){
    if ("disable_time" in payload){
        let time = payload.disable_time;
    }
    if ("ph_key" in payload){
        let ph_key = payload.ph_key;
    }
    if ("ph_addr" in payload){
        let ph_addr = payload.ph_addr;
    }
}

// write settings
function writeSettings(context, action, settings){
    log(`[writeSettings] action=${action} settings=${JSON.stringify(settings)}`);
    // write the settings
    if (!(context in instances)){
        instances[context] = {"action": action};
    }
    instances[context].settings = settings;
    if (instances[context].settings.ph_addr == ""){
        instances[context].settings.ph_addr = "pi.hole";
    }
    if (instances[context].settings.stat == "none"){
        send({
            "event": "setTitle",
            "context": context,
            "payload": {
                "title": ""
            }
        });
    }

    // clean up old p-h instance
    if ("poller" in instances[context]){
        clearInterval(instances[context].poller);
    }
    pihole_end(instances[context]);

    // poll p-h to get status
    instances[context].settings.show_status = true;
    const onReady = (response) => {
        log(`[writeSettings] auth response: ${JSON.stringify(response)}`);
        if ("error" in response){
            log(`[writeSettings] auth error: ${JSON.stringify(response)}`);
            send({
                "event": "showAlert",
                "context": context
            });
        } else{
            instances[context].session = response.session;
            instances[context].poller = setInterval(() => {
                const timeNow = Math.floor(Date.now() / 1000);
                const sessionExpired = "lastUpdateTime" in instances[context] &&
                    (timeNow - instances[context].lastUpdateTime) > instances[context].session.validity;
                instances[context].lastUpdateTime = timeNow;
                if (sessionExpired){
                    clearInterval(instances[context].poller);
                    pihole_connect_once(instances[context].settings, onReady);
                } else{
                    pollPihole(context);
                }
            }, 1000);
        }
        log(`[writeSettings] session established: ${JSON.stringify(instances[context].session)}`);
    }
    pihole_connect_once(instances[context].settings, onReady);
}

// called by the stream deck software when the plugin is initialized
function connectElgatoStreamDeckSocket(inPort, inPluginUUID, inRegisterEvent, inInfo){
    // create the websocket
    websocket = new WebSocket("ws://localhost:" + inPort);
    websocket.onopen = function(){
        // WebSocket is connected, register the plugin
        var json = {
            "event": inRegisterEvent,
            "uuid": inPluginUUID
        };
        websocket.send(JSON.stringify(json));
        log(`[connectElgatoStreamDeckSocket] websocket connected and plugin registered`);
    };
    websocket.onclose = function(){
        console.log('[connectElgatoStreamDeckSocket] websocket closed');
    };

    // message handler
    websocket.onmessage = function(evt){
        let jsonObj = JSON.parse(evt.data);
        let event = jsonObj.event;
        let action = jsonObj.action;
        let context = jsonObj.context;

        log(`[onmessage] action=${action} event=${event}`);

        // update settings for this instance
        if (event == "didReceiveSettings"){
            writeSettings(context, action, jsonObj.payload.settings);
        }

        // apply settings when the action appears
        else if (event == "willAppear"){
            writeSettings(context, action, jsonObj.payload.settings);
        }

        // stop polling and delete settings when the action disappears
        else if (event == "willDisappear"){
            if ("poller" in instances[context]){
                clearInterval(instances[context].poller);
            }
            pihole_end(instances[context]);
            delete instances[context];
        }

        // handle a keypress
        else if (event == "keyUp"){
            if (action == "ca.froggmaster.pihole.toggle"){
                toggle(context);
            }
            else if (action == "ca.froggmaster.pihole.temporarily-disable"){
                temporarily_disable(context);
            }
            else if (action == "ca.froggmaster.pihole.disable"){
                disable(context);
            }
            else if (action == "ca.froggmaster.pihole.enable"){
                enable(context);
            }
        }
    }
}
