document.addEventListener('DOMContentLoaded', () => {
    fetchSystemStats();
    fetchSettings();
    setInterval(fetchSystemStats, 5000);

    const riskThreshold = document.getElementById('risk-threshold');
    const riskVal = document.getElementById('risk-val');
    if (riskThreshold && riskVal) {
        riskThreshold.addEventListener('input', (e) => {
            riskVal.innerText = `${e.target.value}pts`;
        });
    }

    const saveBtn = document.getElementById('save-settings');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveSettings);
    }

    const testDiscordBtn = document.getElementById('test-discord');
    if (testDiscordBtn) {
        testDiscordBtn.addEventListener('click', testDiscord);
    }

    const testTelegramBtn = document.getElementById('test-telegram');
    if (testTelegramBtn) {
        testTelegramBtn.addEventListener('click', testTelegram);
    }

    // Clear Listeners
    setupClearButton('clear-discord', 'discord-webhook', 'Discord Webhook');
    setupClearButton('clear-telegram-token', 'telegram-token', 'Telegram Token');
    setupClearButton('clear-telegram-chat', 'telegram-chat-id', 'Telegram Chat ID');
});

function switchTab(tabId) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Deactivate all sidebar items
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.classList.remove('active');
        item.classList.add('text-gh-muted');
    });
    
    // Show selected tab
    document.getElementById(tabId).classList.add('active');
    
    // Find and activate the clicked sidebar item
    const clickedBtn = Array.from(document.querySelectorAll('.sidebar-item')).find(btn => 
        btn.getAttribute('onclick') === `switchTab('${tabId}')`
    );
    if (clickedBtn) {
        clickedBtn.classList.add('active');
        clickedBtn.classList.remove('text-gh-muted');
    }
    
    // Update Header Title & Description
    const titles = {
        'analytics': { t: 'System Analytics', d: 'Real-time hardware & resource monitoring' },
        'security': { t: 'Security & Shields', d: 'Configure threat detection and alert thresholds' },
        'integrations': { t: 'Service Connections', d: 'Manage Discord, Telegram, and external webhooks' },
        'maintenance': { t: 'Data Foundry', d: 'Database optimization and storage maintenance' }
    };
    
    if (titles[tabId]) {
        document.getElementById('tab-title').innerText = titles[tabId].t;
        document.getElementById('tab-desc').innerText = titles[tabId].d;
    }
}

function setupClearButton(btnId, inputId, label) {
    const btn = document.getElementById(btnId);
    const input = document.getElementById(inputId);
    if (btn && input) {
        btn.addEventListener('click', () => {
            if (input.value && confirm(`Are you sure you want to revoke and clear the ${label}?`)) {
                input.value = '';
                showSnakeModal("REVOKED", `${label} has been cleared from the local buffer. Save to commit changes.`, "yellow");
            }
        });
    }
}

async function fetchSystemStats() {
    try {
        const res = await fetch('/api/system/stats');
        const data = await res.json();
        
        // Update Uptime
        document.getElementById('uptime').innerText = data.uptime || '--';
        document.getElementById('pid-status').innerText = `Process: Running (PID ${data.pid})`;
        
        // Update CPU
        const cpu = parseFloat(data.cpu_usage || 0).toFixed(1);
        document.getElementById('cpu-usage').innerText = `${cpu}%`;
        document.getElementById('cpu-progress').style.width = `${cpu}%`;
        
        // Update RAM
        const ramUsed = (data.ram_usage).toFixed(1);
        const ramTotal = (data.ram_total || 0).toFixed(0);
        document.getElementById('ram-usage').innerText = `${ramUsed} MB`;
        document.getElementById('ram-progress').style.width = `${Math.min(data.ram_percent, 100)}%`;
        
        // Update DB
        const dbSize = (data.db_size / 1024 / 1024).toFixed(2);
        document.getElementById('db-size').innerText = `${dbSize} MB`;
        document.getElementById('db-stats').innerText = `SQLite Rows: ${data.db_rows.toLocaleString()} | Total Size: ${dbSize} MB`;
        
        const dbWarn = document.getElementById('db-warning');
        if (data.db_size > 500 * 1024 * 1024) { // 500MB threshold
            dbWarn.classList.remove('hidden');
            dbWarn.classList.add('flex');
        } else {
            dbWarn.classList.add('hidden');
            dbWarn.classList.remove('flex');
        }

        // Global Load Status
        const cpuVal = parseFloat(data.cpu_usage || 0);
        const ramPct = parseFloat(data.ram_percent || 0);
        const totalLoad = Math.min(cpuVal + ramPct, 100);
        const progressV = document.getElementById('load-progress-v');
        if (progressV) progressV.style.height = `${totalLoad}%`;
        
        const healthStatus = document.getElementById('health-status');
        if (healthStatus) {
            if (totalLoad > 80) {
                healthStatus.innerText = "CRITICAL";
                healthStatus.className = "text-[10px] mt-2 text-gh-red font-black font-mono";
            } else if (totalLoad > 50) {
                healthStatus.innerText = "MODERATE";
                healthStatus.className = "text-[10px] mt-2 text-gh-yellow font-black font-mono";
            } else {
                healthStatus.innerText = "OPTIMAL";
                healthStatus.className = "text-[10px] mt-2 text-gh-muted font-bold font-mono";
            }
        }

    } catch (e) {
        console.error("Failed to fetch system stats", e);
    }
}

async function fetchSettings() {
    try {
        const res = await fetch('/api/settings');
        const data = await res.json();
        
        document.getElementById('alert-login').checked = data.alert_on_login;
        document.getElementById('alert-high-risk').checked = data.alert_on_high_risk;
        document.getElementById('risk-threshold').value = data.risk_threshold;
        document.getElementById('risk-val').innerText = `${data.risk_threshold}pts`;
        document.getElementById('discord-webhook').value = data.discord_webhook || '';
        document.getElementById('alert-email').value = data.email_alias || '';
        document.getElementById('admin-user').value = data.admin_user || 'root';
        document.getElementById('admin-pass').value = data.admin_pass || 'root';
        document.getElementById('telegram-token').value = data.telegram_token || '';
        document.getElementById('telegram-chat-id').value = data.telegram_chat_id || '';
    } catch (e) {
        console.error("Failed to fetch settings", e);
    }
}

async function saveSettings() {
    const settings = {
        alert_on_login: document.getElementById('alert-login').checked,
        alert_on_high_risk: document.getElementById('alert-high-risk').checked,
        risk_threshold: parseInt(document.getElementById('risk-threshold').value),
        discord_webhook: document.getElementById('discord-webhook').value,
        email_alias: document.getElementById('alert-email').value,
        admin_user: document.getElementById('admin-user').value,
        admin_pass: document.getElementById('admin-pass').value,
        telegram_token: document.getElementById('telegram-token').value,
        telegram_chat_id: document.getElementById('telegram-chat-id').value
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });
        if (res.ok) {
            showSnakeModal("CONFIG SAVED", "Administrative settings have been successfully synchronized with the database.", "green");
        } else {
            showSnakeModal("SAVE FAILED", "The server rejected the configuration update. Please verify field formatting.", "red");
        }
    } catch (e) {
        console.error("Save failed", e);
        showSnakeModal("SYNC ERROR", "Could not transmit settings to the backend engine. Check connectivity.", "red");
    }
}

async function testDiscord() {
    const webhook = document.getElementById('discord-webhook').value;
    if (!webhook) {
        showSnakeModal("INPUT REQUIRED", "Please specify a valid Discord Webhook URL before initiating a test.", "blue");
        return;
    }
    const btn = document.getElementById('test-discord');
    const originalContent = btn.innerHTML;
    
    try {
        btn.disabled = true;
        btn.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">sync</span>';
        
        const res = await fetch('/api/test/discord', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: webhook })
        });
        
        btn.disabled = false;
        btn.innerHTML = originalContent;

        if (res.ok) {
            showSnakeModal("DISCORD SUCCESS", "The test payload was successfully delivered to your Discord channel.", "green");
        } else {
            showSnakeModal("DISCORD FAILURE", "Verification failed. Please ensure the Webhook URL is active and valid.", "red");
        }
    } catch (e) {
        console.error("Discord test failed", e);
        showSnakeModal("NETWORK ERROR", "Communication with the Discord API service was interrupted.", "red");
    }
}

async function testTelegram() {
    const token = document.getElementById('telegram-token').value;
    const chatId = document.getElementById('telegram-chat-id').value;
    if (!token || !chatId) {
        showSnakeModal("CREDENTIALS MISSING", "Both Bot Token and Chat ID are required for specialized Telegram testing.", "blue");
        return;
    }
    const btn = document.getElementById('test-telegram');
    const originalContent = btn.innerHTML;

    try {
        btn.disabled = true;
        btn.innerHTML = '<span class="material-symbols-outlined text-sm animate-spin">sync</span>';

        const res = await fetch('/api/test/telegram', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: token, chat_id: chatId })
        });
        
        btn.disabled = false;
        btn.innerHTML = originalContent;
        
        const data = await res.text();
        if (res.ok) {
            showSnakeModal("TELEGRAM VERIFIED", "Honeypot transmission received! Your Telegram integration is fully operational.", "green");
        } else {
            showSnakeModal("TELEGRAM FAILED", `API Feedback: ${data}`, "red");
        }
    } catch (e) {
        console.error("Telegram test failed", e);
        showSnakeModal("ENGINE ERROR", "The backend failed to process the Telegram request. Check terminal logs.", "red");
    }
}

async function maintenanceAction(action) {
    if (action === 'clear' && !confirm("CRITICAL: This will permanently delete ALL honeypot history. Continue?")) {
        return;
    }
    try {
        const res = await fetch(`/api/db/maintenance?action=${action}`, { method: 'POST' });
        if (res.ok) {
            showSnakeModal("SUCCESS", `${action.toUpperCase()} operation completed successfully. System integrity verified.`, "green");
            fetchSystemStats();
        } else {
            showSnakeModal("OPERATION FAILED", `The ${action.toUpperCase()} task encountered an error. Check server logs.`, "red");
        }
    } catch (e) {
        console.error("Maintenance failed", e);
        showSnakeModal("PERSISTENCE ERROR", "Could not connect to the database engine. Verify service status.", "red");
    }
}

// UI Hub: Premium Windows
function showSnakeModal(title, message, theme = "blue") {
    const modal = document.getElementById('snakesec-modal');
    const content = document.getElementById('modal-content');
    const accent = document.getElementById('modal-accent');
    const titleEl = document.getElementById('modal-title');
    const msgEl = document.getElementById('modal-message');
    const iconBg = document.getElementById('modal-icon-bg');
    const icon = iconBg.querySelector('.material-symbols-outlined');

    titleEl.innerText = title;
    msgEl.innerText = message;
    
    // Theme mapping
    const themes = {
        blue: { border: 'border-gh-blue', text: 'text-gh-blue', bg: 'bg-gh-blue/10', line: 'bg-gh-blue', icon: 'info' },
        green: { border: 'border-gh-green', text: 'text-gh-green', bg: 'bg-gh-green/10', line: 'bg-gh-green', icon: 'check_circle' },
        red: { border: 'border-gh-red', text: 'text-gh-red', bg: 'bg-gh-red/10', line: 'bg-gh-red', icon: 'warning' },
        yellow: { border: 'border-gh-yellow', text: 'text-gh-yellow', bg: 'bg-gh-yellow/10', line: 'bg-gh-yellow', icon: 'database' }
    };

    const t = themes[theme] || themes.blue;
    accent.className = `h-1 w-full ${t.line}`;
    icon.innerText = t.icon;
    icon.className = `material-symbols-outlined text-4xl ${t.text}`;
    iconBg.className = `size-16 rounded-full bg-gh-bg border ${t.border} flex items-center justify-center mb-2`;

    modal.classList.remove('invisible', 'opacity-0');
    content.classList.remove('scale-90');
}

function closeSnakeModal() {
    const modal = document.getElementById('snakesec-modal');
    const content = document.getElementById('modal-content');
    modal.classList.add('opacity-0');
    content.classList.add('scale-90');
    setTimeout(() => {
        modal.classList.add('invisible');
    }, 300);
}
