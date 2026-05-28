// ==========================================
// KUI Serverless 聚合网关后端 - 完美融合版
// (包含：自动建表 + 极速8合1协议生成 + CF Monitor Pro API化子系统)
// ==========================================

async function sha256(text) {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function ensureDbSchema(db) {
    // --- KUI 核心表 ---
    const initQueries = [
        `CREATE TABLE IF NOT EXISTS servers (ip TEXT PRIMARY KEY, name TEXT NOT NULL, cpu INTEGER DEFAULT 0, mem REAL DEFAULT 0, last_report INTEGER DEFAULT 0, alert_sent INTEGER DEFAULT 0, disk INTEGER DEFAULT 0, load TEXT DEFAULT "", uptime TEXT DEFAULT "", net_in_speed INTEGER DEFAULT 0, net_out_speed INTEGER DEFAULT 0, tcp_conn INTEGER DEFAULT 0, udp_conn INTEGER DEFAULT 0)`,
        `CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, traffic_limit INTEGER DEFAULT 0, traffic_used INTEGER DEFAULT 0, expire_time INTEGER DEFAULT 0, enable INTEGER DEFAULT 1, sub_token TEXT)`,
        `CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, uuid TEXT NOT NULL, vps_ip TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL, sni TEXT, private_key TEXT, public_key TEXT, short_id TEXT, relay_type TEXT, target_ip TEXT, target_port INTEGER, target_id TEXT, enable INTEGER DEFAULT 1, traffic_used INTEGER DEFAULT 0, traffic_limit INTEGER DEFAULT 0, expire_time INTEGER DEFAULT 0, username TEXT DEFAULT 'admin', FOREIGN KEY(vps_ip) REFERENCES servers(ip) ON DELETE CASCADE)`,
        `CREATE TABLE IF NOT EXISTS traffic_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, delta_bytes INTEGER DEFAULT 0, timestamp INTEGER NOT NULL, FOREIGN KEY(ip) REFERENCES servers(ip) ON DELETE CASCADE)`,
        `CREATE INDEX IF NOT EXISTS idx_traffic_ip_time ON traffic_stats(ip, timestamp)`,
        `CREATE TABLE IF NOT EXISTS sys_config (key TEXT PRIMARY KEY, val TEXT, ts INTEGER)`
    ];
    for (let query of initQueries) { try { await db.prepare(query).run(); } catch (e) {} }

    // --- 探针监控子系统表 ---
    const probeQueries = [
        `CREATE TABLE IF NOT EXISTS probe_settings (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS probe_servers (
            id TEXT PRIMARY KEY, name TEXT, cpu TEXT, ram TEXT, disk TEXT, load_avg TEXT, uptime TEXT, last_updated INTEGER,
            ram_total TEXT, net_rx TEXT, net_tx TEXT, net_in_speed TEXT, net_out_speed TEXT,
            os TEXT, cpu_info TEXT, arch TEXT, boot_time TEXT, ram_used TEXT, swap_total TEXT, 
            swap_used TEXT, disk_total TEXT, disk_used TEXT, processes TEXT, tcp_conn TEXT, udp_conn TEXT, 
            country TEXT, ip_v4 TEXT, ip_v6 TEXT, server_group TEXT DEFAULT '默认分组', price TEXT DEFAULT '', 
            expire_date TEXT DEFAULT '', bandwidth TEXT DEFAULT '', traffic_limit TEXT DEFAULT '', agent_os TEXT DEFAULT 'debian',
            ping_ct TEXT DEFAULT '0', ping_cu TEXT DEFAULT '0', ping_cm TEXT DEFAULT '0', ping_bd TEXT DEFAULT '0',
            monthly_rx TEXT DEFAULT '0', monthly_tx TEXT DEFAULT '0', last_rx TEXT DEFAULT '0', last_tx TEXT DEFAULT '0', 
            reset_month TEXT DEFAULT '', history TEXT DEFAULT '{}', is_hidden TEXT DEFAULT 'false', virt TEXT DEFAULT ''
        )`
    ];
    for (let query of probeQueries) { try { await db.prepare(query).run(); } catch (e) {} }

    // 自动补充 KUI 历史字段
    try { await db.prepare("SELECT username FROM nodes LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE nodes ADD COLUMN username TEXT DEFAULT 'admin'").run(); } catch(e){} }
    try { await db.prepare("SELECT disk FROM servers LIMIT 1").first(); } catch (e) { const newCols = ['disk INTEGER DEFAULT 0', 'load TEXT DEFAULT ""', 'uptime TEXT DEFAULT ""', 'net_in_speed INTEGER DEFAULT 0', 'net_out_speed INTEGER DEFAULT 0', 'tcp_conn INTEGER DEFAULT 0', 'udp_conn INTEGER DEFAULT 0']; for (let col of newCols) { try { await db.prepare(`ALTER TABLE servers ADD COLUMN ${col}`).run(); } catch(err){} } }
    try { await db.prepare("SELECT sub_token FROM users LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE users ADD COLUMN sub_token TEXT").run(); } catch(err){} }
}

async function verifyAuth(authHeader, db, env) {
    if (!authHeader) return null;
    const adminUser = env.ADMIN_USERNAME || "admin";
    const adminPass = env.ADMIN_PASSWORD || "admin";
    if (authHeader === adminPass || authHeader === await sha256(adminPass)) return adminUser;
    const parts = authHeader.split('.');
    if (parts.length !== 3) return null;
    const [b64User, timestamp, clientSig] = parts;
    if (Math.abs(Date.now() - parseInt(timestamp)) > 300000) return null; 
    const username = atob(b64User);
    let baseKeyHex;
    if (username === adminUser) { baseKeyHex = await sha256(adminPass); } 
    else { const u = await db.prepare("SELECT password FROM users WHERE username = ?").bind(username).first(); if (!u) return null; baseKeyHex = u.password; }
    const keyBytes = new Uint8Array(baseKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username + timestamp));
    const expectedSig = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
    return clientSig === expectedSig ? username : null;
}

// ==============================================
// 探针纯净 API 子系统处理
// ==============================================
async function handleProbeAPI(request, env, context, pathArray) {
    const subPath = pathArray ? pathArray.join('/') : '';
    const url = new URL(request.url);
    const method = request.method;
    const db = env.DB;
    const PROBE_SECRET = env.ADMIN_PASSWORD || "admin";

    // 1. 探针公共大盘数据拉取 (无密码/公开)
    if (method === 'GET' && subPath === 'public') {
        const settings = { theme: 'theme1', is_public: 'true', site_title: '⚡ Server Monitor Pro', show_price: 'true', show_expire: 'true', show_bw: 'true', show_tf: 'true', custom_css: '', custom_bg: '', custom_head: '', custom_script: '' };
        try { const { results } = await db.prepare('SELECT * FROM probe_settings').all(); if (results) results.forEach(r => settings[r.key] = r.value); } catch(e){}
        
        // 访问量更新逻辑
        const isAjax = url.searchParams.get('ajax') === '1';
        if (!isAjax) {
            const localNow = new Date(new Date().getTime() + 8 * 60 * 60000); const todayStr = `${localNow.getFullYear()}-${localNow.getMonth() + 1}-${localNow.getDate()}`;
            let vTotal = parseInt(settings.visits_total || '0') + 1; let vToday = parseInt(settings.visits_today || '0'); let vDate = settings.visits_date || '';
            if (vDate !== todayStr) { vToday = 1; vDate = todayStr; } else vToday++;
            settings.visits_total = vTotal.toString(); settings.visits_today = vToday.toString(); settings.visits_date = todayStr;
            context.waitUntil(db.prepare(`INSERT INTO probe_settings (key, value) VALUES ('visits_total', ?), ('visits_today', ?), ('visits_date', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(vTotal.toString(), vToday.toString(), todayStr).run().catch(()=>{}));
        }

        const authHeader = request.headers.get("Authorization");
        const isLoggedIn = await verifyAuth(authHeader, db, env);
        
        if (settings.is_public !== 'true' && !isLoggedIn) {
            return Response.json({ error: "Private Dashboard" }, { status: 401 });
        }

        const servers = (await db.prepare('SELECT id, name, cpu, ram, disk, load_avg, uptime, last_updated, net_in_speed, net_out_speed, os, arch, virt, tcp_conn, udp_conn, country, ip_v4, ip_v6, server_group, price, expire_date, bandwidth, traffic_limit, ping_ct, ping_cu, ping_cm, ping_bd, monthly_rx, monthly_tx, net_rx, net_tx, cpu_info, ram_used, ram_total, disk_used, disk_total FROM probe_servers WHERE is_hidden != "true"').all()).results;
        return Response.json({ settings, servers });
    }

    // 2. 探针单机详情数据拉取
    if (method === 'GET' && subPath === 'detail') {
        const id = url.searchParams.get('id');
        const server = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(id).first();
        if (!server || server.is_hidden === 'true') return Response.json({ error: "Not found" }, { status: 404 });
        return Response.json(server);
    }

    // 3. 探针节点后台上报心跳
    if (method === 'POST' && subPath === 'update') {
        try {
            const data = await request.json(); const { id, secret, metrics } = data;
            if (secret !== PROBE_SECRET) return new Response('Unauthorized', { status: 401 });
            let countryCode = request.cf && request.cf.country ? request.cf.country : 'XX'; if (countryCode.toUpperCase() === 'TW') countryCode = 'CN';
            const serverExists = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(id).first();
            if (!serverExists) return new Response('Server not found', { status: 404 });
            
            // 系统设置拉取(用于流量重置与TG告警)
            let sys = { auto_reset_traffic: 'false', report_interval: '5', tg_notify: 'false', tg_bot_token: '', tg_chat_id: '' };
            try { const { results } = await db.prepare('SELECT * FROM probe_settings').all(); if (results) results.forEach(r => sys[r.key] = r.value); } catch(e){}

            const localNow = new Date(new Date().getTime() + 8 * 60 * 60000); const currentMonthStr = `${localNow.getFullYear()}-${localNow.getMonth() + 1}`;
            let monthly_rx = parseFloat(serverExists.monthly_rx || '0'); let monthly_tx = parseFloat(serverExists.monthly_tx || '0');
            let last_rx = parseFloat(serverExists.last_rx || '0'); let last_tx = parseFloat(serverExists.last_tx || '0');
            let reset_month = serverExists.reset_month || currentMonthStr;
            if (sys.auto_reset_traffic === 'true' && currentMonthStr !== reset_month) { monthly_rx = 0; monthly_tx = 0; reset_month = currentMonthStr; }
            const current_rx = parseFloat(metrics.net_rx || '0'); const current_tx = parseFloat(metrics.net_tx || '0');
            if (current_rx >= last_rx) monthly_rx += (current_rx - last_rx); else monthly_rx += current_rx;
            if (current_tx >= last_tx) monthly_tx += (current_tx - last_tx); else monthly_tx += current_tx;
            last_rx = current_rx; last_tx = current_tx;
            
            let history = {}; try { history = JSON.parse(serverExists.history || '{}'); } catch(e) {}
            const nowMs = Date.now(); const lastHistTime = history.last_time || 0;
            if (nowMs - lastHistTime >= 300000 || !history.time) {
                const maxPoints = 288; const updateArr = (arr, val) => { if (!Array.isArray(arr)) arr = []; arr.push(val); if (arr.length > maxPoints) arr.shift(); return arr; };
                const updateLabels = (arr) => { if (!Array.isArray(arr)) arr = []; const d = new Date(nowMs + 8 * 60 * 60000); arr.push(d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0')); if (arr.length > maxPoints) arr.shift(); return arr; };
                history.cpu = updateArr(history.cpu, parseFloat(metrics.cpu) || 0); history.ram = updateArr(history.ram, parseFloat(metrics.ram) || 0); history.proc = updateArr(history.proc, parseInt(metrics.processes) || 0); history.net_in = updateArr(history.net_in, parseFloat(metrics.net_in_speed) || 0); history.net_out = updateArr(history.net_out, parseFloat(metrics.net_out_speed) || 0); history.tcp = updateArr(history.tcp, parseInt(metrics.tcp_conn) || 0); history.udp = updateArr(history.udp, parseInt(metrics.udp_conn) || 0); history.ping_ct = updateArr(history.ping_ct, parseInt(metrics.ping_ct) || 0); history.ping_cu = updateArr(history.ping_cu, parseInt(metrics.ping_cu) || 0); history.ping_cm = updateArr(history.ping_cm, parseInt(metrics.ping_cm) || 0); history.ping_bd = updateArr(history.ping_bd, parseInt(metrics.ping_bd) || 0); history.time = updateLabels(history.time); history.last_time = nowMs;
            }
            await db.prepare(`UPDATE probe_servers SET cpu=?, ram=?, disk=?, load_avg=?, uptime=?, last_updated=?, ram_total=?, net_rx=?, net_tx=?, net_in_speed=?, net_out_speed=?, os=?, cpu_info=?, arch=?, boot_time=?, ram_used=?, swap_total=?, swap_used=?, disk_total=?, disk_used=?, processes=?, tcp_conn=?, udp_conn=?, country=?, ip_v4=?, ip_v6=?, ping_ct=?, ping_cu=?, ping_cm=?, ping_bd=?, monthly_rx=?, monthly_tx=?, last_rx=?, last_tx=?, reset_month=?, history=?, virt=? WHERE id=?`).bind(metrics.cpu, metrics.ram, metrics.disk, metrics.load, metrics.uptime, Date.now(), metrics.ram_total || '0', metrics.net_rx || '0', metrics.net_tx || '0', metrics.net_in_speed || '0', metrics.net_out_speed || '0', metrics.os || '', metrics.cpu_info || '', metrics.arch || '', metrics.boot_time || '', metrics.ram_used || '0', metrics.swap_total || '0', metrics.swap_used || '0', metrics.disk_total || '0', metrics.disk_used || '0', metrics.processes || '0', metrics.tcp_conn || '0', metrics.udp_conn || '0', countryCode, metrics.ip_v4 || '0', metrics.ip_v6 || '0', metrics.ping_ct || '0', metrics.ping_cu || '0', metrics.ping_cm || '0', metrics.ping_bd || '0', monthly_rx.toString(), monthly_tx.toString(), last_rx.toString(), last_tx.toString(), reset_month, JSON.stringify(history), metrics.virt || '', id).run();
            
            // TG 掉线检测
            if (sys.tg_notify === 'true') {
                context.waitUntil((async () => {
                    const { results: allServers } = await db.prepare('SELECT id, name, last_updated FROM probe_servers').all();
                    let alertState = {}; const stateRes = await db.prepare("SELECT value FROM probe_settings WHERE key = 'alert_state'").first();
                    if (stateRes) alertState = JSON.parse(stateRes.value);
                    let stateChanged = false; const now = Date.now();
                    for (const s of allServers) {
                        const isOffline = (now - s.last_updated) > 120000; 
                        if (isOffline && !alertState[s.id]) {
                            await fetch(`https://api.telegram.org/bot${sys.tg_bot_token}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: sys.tg_chat_id, text: `⚠️ <b>节点离线告警</b>\n\n<b>节点名称:</b> ${s.name}\n<b>状态:</b> 离线 (超过2分钟未上报)\n<b>时间:</b> ${new Date().toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'})}`, parse_mode: 'HTML' }) });
                            alertState[s.id] = true; stateChanged = true;
                        } else if (!isOffline && alertState[s.id]) {
                            await fetch(`https://api.telegram.org/bot${sys.tg_bot_token}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: sys.tg_chat_id, text: `✅ <b>节点恢复通知</b>\n\n<b>节点名称:</b> ${s.name}\n<b>状态:</b> 恢复在线\n<b>时间:</b> ${new Date().toLocaleString('zh-CN', {timeZone: 'Asia/Shanghai'})}`, parse_mode: 'HTML' }) });
                            delete alertState[s.id]; stateChanged = true;
                        }
                    }
                    if (stateChanged) await db.prepare('INSERT INTO probe_settings (key, value) VALUES ("alert_state", ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(JSON.stringify(alertState)).run();
                })());
            }
            return new Response('OK', { status: 200 });
        } catch (e) { return new Response('Error', { status: 400 }); }
    }

    // 4. 下发探针安装脚本
    if (method === 'GET' && subPath === 'install.sh') {
        const osType = url.searchParams.get('os') || 'debian';
        const sh_bin = osType === 'alpine' ? "/bin/sh" : "/bin/bash";
        const cmdApp = "curl"; const sh_sys = "systemctl";
        let reportInterval = '5'; try { const res = await db.prepare("SELECT value FROM probe_settings WHERE key = 'report_interval'").first(); if(res) reportInterval = res.value; } catch(e){}

        let bashScript = `#!${sh_bin}\nSERVER_ID=$1\nSECRET=$2\nWORKER_URL="${url.origin}/api/probe/update"\nif [ -z "$SERVER_ID" ] || [ -z "$SECRET" ]; then echo "错误: 缺少参数。"; exit 1; fi\necho "开始安装全面增强版 CF Probe Agent (${osType === 'alpine' ? 'Alpine/OpenRC' : 'Systemd'})..."\n`;
        if (osType === 'alpine') bashScript += `rc-service cf-probe stop 2>/dev/null\n`; else bashScript += `${sh_sys} stop cf-probe.service 2>/dev/null\n`;
        bashScript += `pkill -f cf-probe.sh 2>/dev/null\ncat << EOF > /usr/local/bin/cf-probe.sh\n#!${sh_bin}\nSERVER_ID="$SERVER_ID"\nSECRET="$SECRET"\nWORKER_URL="$WORKER_URL"\nget_net_bytes() { awk 'NR>2 {rx+=\\$2; tx+=\\$10} END {printf "%.0f %.0f", rx, tx}' /proc/net/dev; }\nget_cpu_stat() { awk '/^cpu / {print \\$2+\\$3+\\$4+\\$5+\\$6+\\$7+\\$8+\\$9, \\$5+\\$6}' /proc/stat; }\nget_http_ping() { rtt=\\$(${cmdApp} -o /dev/null -s -m 2 -w "%{time_total}" "http://\\$1" 2>/dev/null | awk '{printf "%.0f", \\$1*1000}'); echo "\\\${rtt:-0}"; }\nNET_STAT=\\$(get_net_bytes)\nRX_PREV=\\$(echo \\$NET_STAT | awk '{print \\$1}')\nTX_PREV=\\$(echo \\$NET_STAT | awk '{print \\$2}')\nif [ -z "\\$RX_PREV" ]; then RX_PREV=0; fi\nif [ -z "\\$TX_PREV" ]; then TX_PREV=0; fi\nCPU_STAT=\\$(get_cpu_stat)\nPREV_CPU_TOTAL=\\$(echo \\$CPU_STAT | awk '{print \\$1}')\nPREV_CPU_IDLE=\\$(echo \\$CPU_STAT | awk '{print \\$2}')\nLOOP_COUNT=0\nIPV4="0"; IPV6="0"\nPING_CT="0"; PING_CU="0"; PING_CM="0"; PING_BD="0"\nwhile true; do\n  if [ \\$((LOOP_COUNT % 60)) -eq 0 ]; then\n    ${cmdApp} -s -4 -m 3 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "ip=" && IPV4="1" || IPV4="0"\n    ${cmdApp} -s -6 -m 3 https://cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "ip=" && IPV6="1" || IPV6="0"\n  fi\n  if [ \\$((LOOP_COUNT % 6)) -eq 0 ]; then\n    idx=\\$((LOOP_COUNT % 3))\n    case \\$idx in\n      0) CT_NODE="bj-ct-dualstack.ip.zstaticcdn.com"; CU_NODE="bj-cu-dualstack.ip.zstaticcdn.com"; CM_NODE="bj-cm-dualstack.ip.zstaticcdn.com" ;;\n      1) CT_NODE="sh-ct-dualstack.ip.zstaticcdn.com"; CU_NODE="sh-cu-dualstack.ip.zstaticcdn.com"; CM_NODE="sh-cm-dualstack.ip.zstaticcdn.com" ;;\n      2) CT_NODE="gd-ct-dualstack.ip.zstaticcdn.com"; CU_NODE="gd-cu-dualstack.ip.zstaticcdn.com"; CM_NODE="gd-cm-dualstack.ip.zstaticcdn.com" ;;\n    esac\n    PING_CT=\\$(get_http_ping "\\$CT_NODE")\n    PING_CU=\\$(get_http_ping "\\$CU_NODE")\n    PING_CM=\\$(get_http_ping "\\$CM_NODE")\n    PING_BD=\\$(get_http_ping "lf3-ips.zstaticcdn.com")\n  fi\n  LOOP_COUNT=\\$((LOOP_COUNT + 1))\n  OS=\\$(awk -F= '/^PRETTY_NAME/{print \\$2}' /etc/os-release 2>/dev/null | tr -d '"')\n  if [ -z "\\$OS" ]; then OS=\\$(uname -srm); fi\n  ARCH=\\$(uname -m)\n  BOOT_TIME=\\$(uptime -s 2>/dev/null || stat -c %y / 2>/dev/null | cut -d'.' -f1 || echo "Unknown")\n  CPU_INFO=\\$(grep -m 1 'model name' /proc/cpuinfo | awk -F: '{print \\$2}' | xargs | tr -d '"')\n  VIRT=""\n  if command -v systemd-detect-virt >/dev/null 2>&1; then VIRT=\\$(systemd-detect-virt 2>/dev/null); fi\n  if [ -z "\\$VIRT" ] || [ "\\$VIRT" = "none" ]; then\n    if grep -q "lxc" /proc/1/environ 2>/dev/null; then VIRT="lxc"\n    elif grep -q "docker" /proc/1/environ 2>/dev/null; then VIRT="docker"\n    elif [ -f /proc/user_beancounters ]; then VIRT="openvz"\n    elif grep -qi "kvm" /proc/cpuinfo 2>/dev/null; then VIRT="kvm"\n    elif grep -qi "qemu" /proc/cpuinfo 2>/dev/null; then VIRT="qemu"\n    elif [ -f /sys/class/dmi/id/product_name ]; then VIRT=\\$(cat /sys/class/dmi/id/product_name | head -n1 | cut -d' ' -f1)\n    else VIRT="Unknown"\n    fi\n  fi\n  VIRT=\\$(echo "\\$VIRT" | tr '[:lower:]' '[:upper:]')\n  CPU_STAT=\\$(get_cpu_stat)\n  CPU_TOTAL=\\$(echo \\$CPU_STAT | awk '{print \\$1}')\n  CPU_IDLE=\\$(echo \\$CPU_STAT | awk '{print \\$2}')\n  DIFF_TOTAL=\\$((CPU_TOTAL - PREV_CPU_TOTAL))\n  DIFF_IDLE=\\$((CPU_IDLE - PREV_CPU_IDLE))\n  CPU=\\$(awk -v t=\\$DIFF_TOTAL -v i=\\$DIFF_IDLE 'BEGIN {if (t<=0) print 0; else {pct=(1 - i/t)*100; if(pct<0) print 0; else if(pct>100) print 100; else printf "%.2f", pct}}')\n  PREV_CPU_TOTAL=\\$CPU_TOTAL; PREV_CPU_IDLE=\\$CPU_IDLE\n  MEM_INFO=\\$(free -m 2>/dev/null)\n  RAM_TOTAL=\\$(echo "\\$MEM_INFO" | awk '/Mem:/ {print \\$2}')\n  RAM_USED=\\$(echo "\\$MEM_INFO" | awk '/Mem:/ {print \\$3}')\n  RAM=\\$(awk "BEGIN {if(\\$RAM_TOTAL>0) printf \\"%.2f\\", \\$RAM_USED/\\$RAM_TOTAL * 100.0; else print 0}")\n  SWAP_TOTAL=\\$(echo "\\$MEM_INFO" | awk '/Swap:/ {print \\$2}')\n  SWAP_USED=\\$(echo "\\$MEM_INFO" | awk '/Swap:/ {print \\$3}')\n  if [ -z "\\$SWAP_TOTAL" ]; then SWAP_TOTAL=0; fi\n  if [ -z "\\$SWAP_USED" ]; then SWAP_USED=0; fi\n  DISK_INFO=\\$(df -m / 2>/dev/null | tail -n1 | awk '{print \\$2, \\$3, \\$5}')\n  DISK_TOTAL=\\$(echo "\\$DISK_INFO" | awk '{print \\$1}')\n  DISK_USED=\\$(echo "\\$DISK_INFO" | awk '{print \\$2}')\n  DISK=\\$(echo "\\$DISK_INFO" | awk '{print \\$3}' | tr -d '%')\n  LOAD=\\$(cat /proc/loadavg | awk '{print \\$1, \\$2, \\$3}')\n  UPTIME=\\$(awk '{d=int(\\$1/86400); h=int((\\$1%86400)/3600); m=int((\\$1%3600)/60); if(d>0) printf "%d days, %02d:%02d\\n", d, h, m; else printf "%02d:%02d\\n", h, m}' /proc/uptime 2>/dev/null || uptime -p 2>/dev/null | sed 's/up //')\n  PROCESSES=\\$(ps -e 2>/dev/null | grep -v "PID" | wc -l)\n  if command -v ss >/dev/null 2>&1; then TCP_CONN=\\$(ss -ant 2>/dev/null | grep -v "State" | wc -l); UDP_CONN=\\$(ss -anu 2>/dev/null | grep -v "State" | wc -l); else TCP_CONN=\\$(netstat -ant 2>/dev/null | grep -c "^tcp"); UDP_CONN=\\$(netstat -anu 2>/dev/null | grep -c "^udp"); fi\n  if [ -z "\\$TCP_CONN" ]; then TCP_CONN=0; fi\n  if [ -z "\\$UDP_CONN" ]; then UDP_CONN=0; fi\n  NET_STAT=\\$(get_net_bytes)\n  RX_NOW=\\$(echo \\$NET_STAT | awk '{print \\$1}')\n  TX_NOW=\\$(echo \\$NET_STAT | awk '{print \\$2}')\n  if [ -z "\\$RX_NOW" ]; then RX_NOW=0; fi\n  if [ -z "\\$TX_NOW" ]; then TX_NOW=0; fi\n  RX_SPEED=\\$(((RX_NOW - RX_PREV) / ${reportInterval}))\n  TX_SPEED=\\$(((TX_NOW - TX_PREV) / ${reportInterval}))\n  RX_PREV=\\$RX_NOW; TX_PREV=\\$TX_NOW\n  PAYLOAD="{\\"id\\": \\"\\$SERVER_ID\\", \\"secret\\": \\"\\$SECRET\\", \\"metrics\\": { \\"cpu\\": \\"\\$CPU\\", \\"ram\\": \\"\\$RAM\\", \\"ram_total\\": \\"\\$RAM_TOTAL\\", \\"ram_used\\": \\"\\$RAM_USED\\", \\"swap_total\\": \\"\\$SWAP_TOTAL\\", \\"swap_used\\": \\"\\$SWAP_USED\\", \\"disk\\": \\"\\$DISK\\", \\"disk_total\\": \\"\\$DISK_TOTAL\\", \\"disk_used\\": \\"\\$DISK_USED\\", \\"load\\": \\"\\$LOAD\\", \\"uptime\\": \\"\\$UPTIME\\", \\"boot_time\\": \\"\\$BOOT_TIME\\", \\"net_rx\\": \\"\\$RX_NOW\\", \\"net_tx\\": \\"\\$TX_NOW\\", \\"net_in_speed\\": \\"\\$RX_SPEED\\", \\"net_out_speed\\": \\"\\$TX_SPEED\\", \\"os\\": \\"\\$OS\\", \\"arch\\": \\"\\$ARCH\\", \\"cpu_info\\": \\"\\$CPU_INFO\\", \\"processes\\": \\"\\$PROCESSES\\", \\"tcp_conn\\": \\"\\$TCP_CONN\\", \\"udp_conn\\": \\"\\$UDP_CONN\\", \\"ip_v4\\": \\"\\$IPV4\\", \\"ip_v6\\": \\"\\$IPV6\\", \\"ping_ct\\": \\"\\$PING_CT\\", \\"ping_cu\\": \\"\\$PING_CU\\", \\"ping_cm\\": \\"\\$PING_CM\\", \\"ping_bd\\": \\"\\$PING_BD\\", \\"virt\\": \\"\\$VIRT\\" }}"\n  ${cmdApp} -s -X POST -H "Content-Type: application/json" -d "\\$PAYLOAD" "\\$WORKER_URL" > /dev/null\n  sleep ${reportInterval}\ndone\nEOF\nchmod +x /usr/local/bin/cf-probe.sh\n`;
        if (osType === 'alpine') { bashScript += `cat << 'EOF' > /etc/init.d/cf-probe\n#!/sbin/openrc-run\nname="cf-probe"\ncommand="/usr/local/bin/cf-probe.sh"\ncommand_background="yes"\npidfile="/run/cf-probe.pid"\nEOF\nchmod +x /etc/init.d/cf-probe\nrc-update add cf-probe default\nrc-service cf-probe restart\necho "✅ Alpine 探针安装成功！"\n`; } 
        else { bashScript += `cat << EOF > /etc/systemd/system/cf-probe.service\n[Unit]\nDescription=Cloudflare Worker Probe Agent\nAfter=network.target\n[Service]\nExecStart=/usr/local/bin/cf-probe.sh\nRestart=always\nUser=root\n[Install]\nWantedBy=multi-user.target\nEOF\n${sh_sys} daemon-reload\n${sh_sys} enable cf-probe.service\n${sh_sys} restart cf-probe.service\necho "✅ Linux 探针安装成功！"\n`; }
        return new Response(bashScript, { headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
    }

    // --- 以下为需要管理员权限的 API ---
    if (!(await verifyAuth(request.headers.get("Authorization"), db, env))) return Response.json({error: "Unauthorized"}, {status: 401});

    // 5. 探针后台管理：拉取所有数据(含隐藏)
    if (method === 'GET' && subPath === 'admin/data') {
        const settings = {};
        try { const { results } = await db.prepare('SELECT * FROM probe_settings').all(); if (results) results.forEach(r => settings[r.key] = r.value); } catch(e){}
        const servers = (await db.prepare('SELECT id, name, last_updated, server_group, price, expire_date, bandwidth, traffic_limit, agent_os, is_hidden FROM probe_servers').all()).results;
        return Response.json({ settings, servers });
    }
    
    // 6. 探针后台管理：修改设置
    if (method === 'POST' && subPath === 'admin/settings') {
        const { settings } = await request.json();
        for (const [k, v] of Object.entries(settings)) { await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v).run(); }
        return Response.json({ success: true });
    }

    // 7. 探针后台管理：增删改节点
    if (method === 'POST' && subPath === 'admin/server') {
        const data = await request.json(); const id = crypto.randomUUID();
        await db.prepare(`INSERT INTO probe_servers (id, name, cpu, ram, disk, load_avg, uptime, last_updated, ram_total, net_rx, net_tx, net_in_speed, net_out_speed, os, cpu_info, arch, boot_time, ram_used, swap_total, swap_used, disk_total, disk_used, processes, tcp_conn, udp_conn, country, ip_v4, ip_v6, server_group, price, expire_date, bandwidth, traffic_limit, ping_ct, ping_cu, ping_cm, ping_bd, monthly_rx, monthly_tx, last_rx, last_tx, reset_month, agent_os, history, is_hidden) VALUES (?, ?, '0', '0', '0', '0', '0', 0, '0', '0', '0', '0', '0', '', '', '', '', '0', '0', '0', '0', '0', '0', '0', '0', '', '0', '0', '默认分组', '免费', '', '', '', '0', '0', '0', '0', '0', '0', '0', '0', '', ?, '{}', 'false')`).bind(id, data.name || 'New Server', data.agent_os || 'debian').run();
        return Response.json({ success: true });
    }
    if (method === 'PUT' && subPath === 'admin/server') {
        const data = await request.json();
        await db.prepare(`UPDATE probe_servers SET name=?, server_group=?, price=?, expire_date=?, bandwidth=?, traffic_limit=?, agent_os=?, is_hidden=? WHERE id=?`).bind(data.name || 'Unnamed', data.server_group || '默认分组', data.price || '', data.expire_date || '', data.bandwidth || '', data.traffic_limit || '', data.agent_os || 'debian', data.is_hidden || 'false', data.id).run();
        return Response.json({ success: true });
    }
    if (method === 'DELETE' && subPath === 'admin/server') {
        await db.prepare('DELETE FROM probe_servers WHERE id = ?').bind(url.searchParams.get('id')).run();
        return Response.json({ success: true });
    }

    return Response.json({error: "Not Found"}, {status: 404});
}

// ==============================================
// KUI 主体接口路由
// ==============================================
export async function onRequest(context) {
    const { request, env, params } = context;
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    const db = env.DB; 

    // 🌟 路由探针子系统 API
    if (action === "probe") {
        await ensureDbSchema(db);
        return await handleProbeAPI(request, env, context, params.path.slice(1));
    }

    if (action === "ui_ping" && method === "POST") {
        if (!(await verifyAuth(request.headers.get("Authorization"), db, env))) return new Response("Unauthorized", { status: 401 });
        await db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('ui_active', '1', ?)").bind(Date.now()).run();
        return Response.json({ success: true });
    }

    if (action === "report" && method === "POST") {
        if (!(await verifyAuth(request.headers.get("Authorization"), db, env))) return new Response("Unauthorized", { status: 401 });
        const data = await request.json(); 
        const nowMs = Date.now();
        try { await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?").bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, data.ip).run(); } catch (e) { await ensureDbSchema(db); await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?").bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, data.ip).run(); }
        const stmts = []; let totalDelta = 0;
        if (data.node_traffic && data.node_traffic.length > 0) { for (let nt of data.node_traffic) { stmts.push(db.prepare("UPDATE nodes SET traffic_used = traffic_used + ? WHERE id = ?").bind(nt.delta_bytes, nt.id)); stmts.push(db.prepare(`UPDATE users SET traffic_used = traffic_used + ? WHERE username = (SELECT username FROM nodes WHERE id = ?)`).bind(nt.delta_bytes, nt.id)); totalDelta += nt.delta_bytes; } }
        if (data.argo_urls && data.argo_urls.length > 0) { for (let argo of data.argo_urls) { stmts.push(db.prepare("UPDATE nodes SET sni = ? WHERE id = ? AND protocol = 'VLESS-Argo' AND sni != ?").bind(argo.url, argo.id, argo.url)); } }
        if (totalDelta > 0) { stmts.push(db.prepare("INSERT INTO traffic_stats (ip, delta_bytes, timestamp) VALUES (?, ?, ?)").bind(data.ip, totalDelta, nowMs)); }
        if (stmts.length > 0) await db.batch(stmts);
        let fastMode = false; try { const uiActive = await db.prepare("SELECT ts FROM sys_config WHERE key = 'ui_active'").first(); if (uiActive && (nowMs - uiActive.ts < 20000)) fastMode = true; } catch(e) {}
        return Response.json({ success: true, fast_mode: fastMode });
    }

    if (action === "config" && method === "GET") {
        if (!(await verifyAuth(request.headers.get("Authorization"), db, env))) return new Response("Unauthorized", { status: 401 });
        const ip = new URL(request.url).searchParams.get("ip"); const now = Date.now(); const adminUser = env.ADMIN_USERNAME || "admin";
        const query = `SELECT n.* FROM nodes n LEFT JOIN users u ON n.username = u.username WHERE n.vps_ip = ? AND n.enable = 1 AND (n.traffic_limit = 0 OR n.traffic_used < n.traffic_limit) AND (n.expire_time = 0 OR n.expire_time > ?) AND (n.username = ? OR n.username = 'admin' OR (u.username IS NOT NULL AND u.enable = 1 AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit) AND (u.expire_time = 0 OR u.expire_time > ?)))`;
        const { results: machineNodes } = await db.prepare(query).bind(ip, now, adminUser, now).all();
        for (let node of machineNodes) { if (node.protocol === "dokodemo-door" && node.relay_type === "internal") { const targetNode = await db.prepare("SELECT * FROM nodes WHERE id = ?").bind(node.target_id).first(); if (targetNode) node.chain_target = { ip: targetNode.vps_ip, port: targetNode.port, protocol: targetNode.protocol, uuid: targetNode.uuid, sni: targetNode.sni, public_key: targetNode.public_key, short_id: targetNode.short_id }; } }
        return Response.json({ success: true, configs: machineNodes });
    }

    if (action === "sub" && method === "GET") {
        const urlObj = new URL(request.url); const ip = urlObj.searchParams.get("ip"); const reqUser = urlObj.searchParams.get("user"); const token = urlObj.searchParams.get("token"); const adminUser = env.ADMIN_USERNAME || "admin";
        let isValid = false;
        if (reqUser === adminUser) { let adminSubToken = await sha256(env.ADMIN_PASSWORD || "admin"); try { const r = await db.prepare("SELECT val FROM sys_config WHERE key='admin_sub_token'").first(); if(r && r.val) adminSubToken = r.val; } catch(e){} isValid = (token === adminSubToken) || (token === await sha256(env.ADMIN_PASSWORD || "admin")); } 
        else { const u = await db.prepare("SELECT password, sub_token FROM users WHERE username = ?").bind(reqUser).first(); if (u) isValid = (token === u.sub_token) || (!u.sub_token && token === u.password); }
        if (!isValid) return new Response("Forbidden", { status: 403 });
        const now = Date.now(); let query; let sqlParams = [now];
        if (reqUser === adminUser) { query = `SELECT * FROM nodes WHERE enable = 1 AND (traffic_limit = 0 OR traffic_used < traffic_limit) AND (expire_time = 0 OR expire_time > ?) AND (username = ? OR username = 'admin')`; sqlParams.push(adminUser); if (ip) { query += " AND vps_ip = ?"; sqlParams.push(ip); } } 
        else { query = `SELECT n.* FROM nodes n JOIN users u ON n.username = u.username WHERE n.enable = 1 AND (n.traffic_limit = 0 OR n.traffic_used < n.traffic_limit) AND (n.expire_time = 0 OR n.expire_time > ?) AND n.username = ? AND u.enable = 1 AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit) AND (u.expire_time = 0 OR u.expire_time > ?)`; sqlParams.push(reqUser, now); if (ip) { query += " AND n.vps_ip = ?"; sqlParams.push(ip); } }
        const { results } = await db.prepare(query).bind(...sqlParams).all(); let subLinks = [];
        for (let node of results) {
            const vpsInfo = await db.prepare("SELECT name FROM servers WHERE ip = ?").bind(node.vps_ip).first(); const rawRemark = `${vpsInfo ? vpsInfo.name : 'KUI'} | ${node.protocol}_${node.port}`; const remark = encodeURIComponent(rawRemark); let link = "";
            switch (node.protocol) {
                case "VLESS": link = `vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&security=none&type=tcp#${remark}`; break;
                case "XTLS-Reality": case "Reality": link = `vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${node.sni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=tcp&headerType=none#${remark}`; break;
                case "Hysteria2": link = `hysteria2://${node.uuid}@${node.vps_ip}:${node.port}/?insecure=1&sni=${node.sni}&alpn=h3#${remark}`; break;
                case "TUIC": link = `tuic://${node.uuid}:${node.private_key}@${node.vps_ip}:${node.port}?sni=${node.sni}&congestion_control=bbr&alpn=h3&allow_insecure=1#${remark}`; break;
                case "Trojan": link = `trojan://${node.private_key}@${node.vps_ip}:${node.port}?security=tls&sni=${node.sni}&allowInsecure=1&type=tcp#${remark}`; break;
                case "H2-Reality": link = `vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&security=reality&sni=${node.sni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=http#${remark}`; break;
                case "gRPC-Reality": link = `vless://${node.uuid}@${node.vps_ip}:${node.port}?encryption=none&security=reality&sni=${node.sni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=grpc&serviceName=grpc#${remark}`; break;
                case "AnyTLS": link = `anytls://${node.private_key}@${node.vps_ip}:${node.port}?security=tls&sni=${node.sni}&insecure=1#${remark}`; break;
                case "Naive": link = `naive+https://${node.uuid}:${node.private_key}@${node.vps_ip}:${node.port}?security=tls&sni=${node.sni}#${remark}`; break;
                case "Socks5": link = `socks5://${btoa(`${node.uuid}:${node.private_key}`)}@${node.vps_ip}:${node.port}#${remark}`; break;
                case "VLESS-Argo": if (!node.sni.includes('等待')) link = `vless://${node.uuid}@${node.sni}:443?encryption=none&security=tls&type=ws&host=${node.sni}&path=%2F#${remark}-Argo`; break;
            }
            if (link) subLinks.push(link);
        }
        return new Response(btoa(unescape(encodeURIComponent(subLinks.join('\n')))), { headers: { "Content-Type": "text/plain; charset=utf-8" }});
    }

    if (action === "login" && method === "POST") {
        await ensureDbSchema(db); const username = await verifyAuth(request.headers.get("Authorization"), db, env);
        if (username) return Response.json({ success: true, role: username === (env.ADMIN_USERNAME || "admin") ? 'admin' : 'user' });
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const currentUser = await verifyAuth(request.headers.get("Authorization"), db, env);
    const isAdmin = currentUser === (env.ADMIN_USERNAME || "admin");
    if (!currentUser) return Response.json({ error: "Unauthorized" }, { status: 401 });

    try {
        if (action === "data") {
            const servers = (await db.prepare("SELECT * FROM servers").all()).results;
            const nodes = isAdmin ? (await db.prepare("SELECT * FROM nodes").all()).results : (await db.prepare("SELECT * FROM nodes WHERE username = ?").bind(currentUser).all()).results;
            const users = isAdmin ? (await db.prepare("SELECT * FROM users").all()).results : (await db.prepare("SELECT * FROM users WHERE username = ?").bind(currentUser).all()).results;
            let siteTitle = "Cluster Gateway"; try { const r = await db.prepare("SELECT val FROM sys_config WHERE key='site_title'").first(); if(r && r.val) siteTitle = r.val; } catch(e){}
            let mySubToken = "";
            if (isAdmin) { try { const r = await db.prepare("SELECT val FROM sys_config WHERE key='admin_sub_token'").first(); if(r && r.val) mySubToken = r.val; } catch(e){} } 
            else { const u = await db.prepare("SELECT sub_token FROM users WHERE username = ?").bind(currentUser).first(); if(u && u.sub_token) mySubToken = u.sub_token; }
            return Response.json({ servers, nodes, users, siteTitle, mySubToken });
        }
        
        if (action === "settings" && method === "POST" && isAdmin) { const { site_title } = await request.json(); await db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('site_title', ?, ?)").bind(site_title, Date.now()).run(); return Response.json({ success: true }); }
        if (action === "user" && params.path[1] === "password" && method === "PUT") { const { password } = await request.json(); if (isAdmin) return Response.json({error: "管理员密码受绝对安全保护，仅可通过 Cloudflare Pages 环境变量修改！"}, {status: 400}); const hash = await sha256(password); await db.prepare("UPDATE users SET password = ? WHERE username = ?").bind(hash, currentUser).run(); return Response.json({ success: true }); }
        if (action === "user" && params.path[1] === "sub_token" && method === "PUT") { const newToken = crypto.randomUUID(); if (isAdmin) await db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('admin_sub_token', ?, ?)").bind(newToken, Date.now()).run(); else await db.prepare("UPDATE users SET sub_token = ? WHERE username = ?").bind(newToken, currentUser).run(); return Response.json({ success: true, token: newToken }); }
        if (action === "stats" && method === "GET" && isAdmin) { const query = `SELECT strftime('%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) as day, SUM(delta_bytes) as total_bytes FROM traffic_stats WHERE ip = ? AND timestamp > ? GROUP BY day ORDER BY day ASC`; const { results } = await db.prepare(query).bind(new URL(request.url).searchParams.get("ip"), Date.now() - 604800000).all(); return Response.json(results || []); }
        
        if (action === "users" && isAdmin) {
            if (method === "POST") { const { username, password, traffic_limit, expire_time } = await request.json(); const hash = await sha256(password); const subToken = crypto.randomUUID(); await db.prepare("INSERT INTO users (username, password, traffic_limit, expire_time, sub_token) VALUES (?, ?, ?, ?, ?)").bind(username, hash, traffic_limit, expire_time, subToken).run(); return Response.json({ success: true }); }
            if (method === "PUT") { const { username, enable, reset_traffic } = await request.json(); if (reset_traffic) await db.prepare("UPDATE users SET traffic_used = 0 WHERE username = ?").bind(username).run(); else if (enable !== undefined) await db.prepare("UPDATE users SET enable = ? WHERE username = ?").bind(enable, username).run(); return Response.json({ success: true }); }
            if (method === "DELETE") { const target = new URL(request.url).searchParams.get("username"); await db.prepare("DELETE FROM users WHERE username = ?").bind(target).run(); await db.prepare("UPDATE nodes SET username = ? WHERE username = ?").bind(currentUser, target).run(); return Response.json({ success: true }); }
        }
        
        if (action === "vps" && isAdmin) {
            if (method === "POST") { const { ip, name } = await request.json(); await db.prepare("INSERT OR IGNORE INTO servers (ip, name, alert_sent) VALUES (?, ?, 0)").bind(ip, name).run(); return Response.json({ success: true }); }
            if (method === "DELETE") { const ip = new URL(request.url).searchParams.get("ip"); await db.batch([ db.prepare("DELETE FROM nodes WHERE vps_ip = ?").bind(ip), db.prepare("DELETE FROM traffic_stats WHERE ip = ?").bind(ip), db.prepare("DELETE FROM servers WHERE ip = ?").bind(ip) ]); return Response.json({ success: true }); }
        }

        if (action === "nodes" && isAdmin) {
            if (method === "POST") { const n = await request.json(); let nodeUser = n.username || currentUser; if (nodeUser === 'admin') nodeUser = currentUser; await db.prepare(`INSERT INTO nodes (id, uuid, vps_ip, protocol, port, sni, private_key, public_key, short_id, relay_type, target_ip, target_port, target_id, enable, traffic_used, traffic_limit, expire_time, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(n.id, n.uuid, n.vps_ip, n.protocol, n.port, n.sni||null, n.private_key||null, n.public_key||null, n.short_id||null, n.relay_type||null, n.target_ip||null, n.target_port||null, n.target_id||null, 1, 0, n.traffic_limit||0, n.expire_time||0, nodeUser).run(); return Response.json({ success: true }); }
            if (method === "PUT") { const { id, enable, reset_traffic } = await request.json(); if (reset_traffic) await db.prepare("UPDATE nodes SET traffic_used = 0 WHERE id = ?").bind(id).run(); else if (enable !== undefined) await db.prepare("UPDATE nodes SET enable = ? WHERE id = ?").bind(enable, id).run(); return Response.json({ success: true }); }
            if (method === "DELETE") { await db.prepare("DELETE FROM nodes WHERE id = ?").bind(new URL(request.url).searchParams.get("id")).run(); return Response.json({ success: true }); }
        }

        return new Response("Not Found", { status: 404 });
    } catch (err) { return Response.json({ error: err.message }, { status: 500 }); }
}

export async function onRequestScheduled(context) {
    const { env } = context; const db = env.DB; const nowMs = Date.now();
    try {
        const { results } = await db.prepare(`SELECT ip, name, last_report FROM servers WHERE last_report < ? AND alert_sent = 0`).bind(nowMs - 180000).all();
        if (results && results.length > 0) {
            const tgBotToken = env.TG_BOT_TOKEN; const tgChatId = env.TG_CHAT_ID; const updateStmts = [];
            for (let vps of results) {
                if (tgBotToken && tgChatId) { const text = `⚠️ [KUI 节点失联告警]\n\n节点别名: ${vps.name}\n公网IP: ${vps.ip}\n最后在线: ${new Date(vps.last_report).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`; await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: tgChatId, text }) }); }
                updateStmts.push(db.prepare("UPDATE servers SET alert_sent = 1 WHERE ip = ?").bind(vps.ip));
            }
            if (updateStmts.length > 0) await db.batch(updateStmts);
        }
    } catch (error) {}
}
