let map;
let markers = {}; // Store markers by session ID
let attackLines = []; // Store active attack lines
let hubMarker = null;
let HOME_COORDS = [31.7917, -7.0926]; // Default Morocco (Rabat/Casablanca region)

let timelineChart = null;
let currentPeriod = '24h';

document.addEventListener('DOMContentLoaded', () => {
    // Inject hub pulse CSS
    const style = document.createElement('style');
    style.innerHTML = `
        .hub-pulse {
            animation: hub-glow 3s infinite;
        }
        @keyframes hub-glow {
            0% { filter: drop-shadow(0 0 2px #58a6ff); opacity: 0.8; }
            50% { filter: drop-shadow(0 0 10px #58a6ff); opacity: 1; }
            100% { filter: drop-shadow(0 0 2px #58a6ff); opacity: 0.8; }
        }
    `;
    document.head.appendChild(style);

    initMap();
    initWebSocket();
    initTimeline();
    initCommandIntelligence();
    updateData();
    setInterval(updateData, 2000); // Throttled to 2s for better UI stability
});

let isAutoScrollPaused = false;
let commandIntelData = [];

function initMap() {
    // Initialize Leaflet map with CartoDB Dark Matter tiles
    map = L.map('world-map', {
        center: [31.7917, -7.0926],
        zoom: 2,
        minZoom: 2,
        maxZoom: 14,
        zoomControl: false,
        scrollWheelZoom: true,
        attributionControl: false
    });

    map.on('zoomend', updateMarkerSizes);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);

    // Initial Hub Marker at default location
    updateHubMarker();

    // Fetch real server location to update the "Hub"
    fetch('/api/hub-location')
        .then(res => res.json())
        .then(data => {
            if (data && data.lat !== undefined && data.lon !== undefined && data.lat !== 0 && data.lon !== 0) {
                HOME_COORDS = [data.lat, data.lon];
                map.setView(HOME_COORDS, 3);
                updateHubMarker();
            }
        });
}

function updateHubMarker() {
    if (!map) return;
    if (hubMarker) map.removeLayer(hubMarker);
    
    hubMarker = L.circleMarker(HOME_COORDS, {
        radius: 8,
        fillColor: '#58a6ff',
        color: '#fff',
        weight: 2,
        fillOpacity: 1,
        className: 'hub-pulse'
    }).addTo(map).bindPopup("<b>SnakeSec Honeypot Hub</b><br>Your Detection Sensor is Active");
    
    updateMarkerSizes();
}

function updateMarkerSizes() {
    const zoom = map.getZoom();
    
    // Scale Hub: 2->6px, 14->18px
    const hubRadius = zoom + 4;
    if (hubMarker) hubMarker.setRadius(hubRadius);

    // Scale Attack Pulses via CSS: 2->10px, 14->34px
    const pulseSize = (zoom * 2) + 6;
    document.documentElement.style.setProperty('--pulse-size', `${pulseSize}px`);

    // Optionally update iconSize for markers to keep popups centered
    Object.values(markers).forEach(m => {
        const icon = m.getIcon();
        if (icon && icon.options) {
            icon.options.iconSize = [pulseSize, pulseSize];
            m.setIcon(icon);
        }
    });
}

let logBuffer = [];
const LOG_BATCH_INTERVAL = 200; // ms

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'log') {
            logBuffer.push(data.message);
        } else if (data.type === 'ping') {
            // Immediate map ping and line for a new connection
            if (map && data.lat && data.lon) {
                renderAttack(data.lat, data.lon, data.ip);
            }
        }
    };

    socket.onclose = () => {
        console.log('WS Disconnected. Retrying in 5s...');
        setTimeout(initWebSocket, 5000);
    };

    // Periodically flush logs to DOM
    setInterval(flushLogs, LOG_BATCH_INTERVAL);

    // Smart Scroll: Detect if user has scrolled away from bottom
    const logRoot = document.getElementById('live-log');
    const scrollBtn = document.getElementById('scrollToBottom');

    if (logRoot) {
        logRoot.addEventListener('scroll', () => {
            const isAtBottom = logRoot.scrollHeight - logRoot.clientHeight <= logRoot.scrollTop + 50;
            isAutoScrollPaused = !isAtBottom;
            
            if (scrollBtn) {
                if (isAutoScrollPaused) {
                    scrollBtn.classList.remove('hidden');
                } else {
                    scrollBtn.classList.add('hidden');
                }
            }
        });
    }

    if (scrollBtn) {
        scrollBtn.addEventListener('click', () => {
            logRoot.scrollTop = logRoot.scrollHeight;
        });
    }
}

function flushLogs() {
    if (logBuffer.length === 0) return;
    
    const logRoot = document.getElementById('live-log');
    if (!logRoot) return;

    const fragment = document.createDocumentFragment();
    const batch = logBuffer.splice(0, 50); 
    
    batch.forEach(msg => {
        const line = document.createElement('div');
        line.className = 'log-line';
        if (msg.includes('AUTH ACCEPTED')) line.style.color = '#3fb950';
        if (msg.includes('REJECTED')) line.style.color = '#f85149';
        if (msg.includes('COMMAND')) line.style.color = '#58a6ff';
        if (msg.includes('DISCONNECT')) line.style.color = '#8b949e';
        line.innerText = msg;
        fragment.appendChild(line);
    });

    logRoot.appendChild(fragment);

    if (!isAutoScrollPaused) {
        logRoot.scrollTop = logRoot.scrollHeight;
    }

    while (logRoot.children.length > 200) {
        logRoot.removeChild(logRoot.firstChild);
    }
}

async function renderAttack(lat, lon, ip, country = "Unknown") {
    if (!map) return;

    const start = [lat, lon];
    const end = [...HOME_COORDS]; // Use a copy to prevent any weird mutation issues

    // 1. Arc line from attacker to Hub
    const line = drawCurve(start, end);
    
    // Auto-remove line effect after 5 seconds for better performance
    setTimeout(() => {
        if (map.hasLayer(line)) map.removeLayer(line);
    }, 5000);

    // 2. Pulse effect at origin (Transient)
    const icon = L.divIcon({
        className: 'pulse-container',
        html: `<div class="pulse" title="${ip}"></div>`,
        iconSize: [20, 20]
    });

    const marker = L.marker(start, { icon: icon }).addTo(map);
    marker.bindPopup(`<b>Threat Origin:</b> ${ip}<br><b>Location:</b> ${country}<br><b>Status:</b> Attacking SnakeSec...`);

    // Clean up transient marker after 15 seconds UNLESS it becomes a persistent session
    setTimeout(() => {
        // We only remove if it's not in the persistent 'markers' set
        // Actually, for simplicity, let's just track transient markers separately
        if (map.hasLayer(marker)) map.removeLayer(marker);
    }, 15000);
}

function drawCurve(start, end) {
    const offsetX = (end[1] - start[1]) / 4;
    const offsetY = (end[0] - start[0]) / 4;
    const midpoint = [
        (start[0] + end[0]) / 2 + offsetX,
        (start[1] + end[1]) / 2 + offsetY
    ];
    const points = getCurvePoints(start, midpoint, end, 30);
    return L.polyline(points, {
        color: '#f85149',
        weight: 1.5,
        opacity: 0.7,
        className: 'attack-line'
    }).addTo(map);
}

function getCurvePoints(p1, p2, p3, segments) {
    const points = [];
    for (let i = 0; i <= segments; i++) {
        const t = i / segments;
        const lat = (1 - t) * (1 - t) * p1[0] + 2 * (1 - t) * t * p2[0] + t * t * p3[0];
        const lng = (1 - t) * (1 - t) * p1[1] + 2 * (1 - t) * t * p2[1] + t * t * p3[1];
        points.push([lat, lng]);
    }
    return points;
}

function initTimeline() {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    // Red Gradient for Bruteforce
    const redGradient = ctx.createLinearGradient(0, 0, 0, 400);
    redGradient.addColorStop(0, 'rgba(248, 81, 73, 0.3)');
    redGradient.addColorStop(1, 'rgba(248, 81, 73, 0)');

    // Blue Gradient (unused but kept for consistency)
    const blueGradient = ctx.createLinearGradient(0, 0, 0, 400);
    blueGradient.addColorStop(0, 'rgba(88, 166, 255, 0.3)');
    blueGradient.addColorStop(1, 'rgba(88, 166, 255, 0)');

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Bruteforce',
                data: [],
                borderColor: '#f85149',
                backgroundColor: redGradient,
                fill: true,
                tension: 0.4,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointBackgroundColor: '#f85149'
            }, {
                label: 'Commands',
                data: [],
                borderColor: '#58a6ff',
                backgroundColor: 'transparent',
                fill: false,
                tension: 0.4,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointBackgroundColor: '#58a6ff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index',
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#161b22',
                    titleColor: '#e6edf3',
                    bodyColor: '#e6edf3',
                    borderColor: '#30363d',
                    borderWidth: 1,
                    displayColors: false,
                    titleFont: { family: 'JetBrains Mono', size: 10 },
                    bodyFont: { family: 'JetBrains Mono', size: 10 }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { 
                        color: '#8b949e', 
                        font: { family: 'JetBrains Mono', size: 9 },
                        maxRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 12
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(48, 54, 61, 0.2)' },
                    ticks: { 
                        color: '#8b949e', 
                        font: { family: 'JetBrains Mono', size: 9 },
                        precision: 0
                    }
                }
            }
        }
    });
    fetchTimeline();
}

function updateTimeline(period) {
    currentPeriod = period;
    
    // Update active button state
    document.querySelectorAll('.timeline-btn').forEach(btn => {
        btn.classList.remove('font-bold', 'text-gh-blue', 'border-gh-blue/50');
    });
    const activeBtn = document.getElementById(`btn-${period}`);
    if (activeBtn) activeBtn.classList.add('font-bold', 'text-gh-blue', 'border-gh-blue/50');

    fetchTimeline();
}

async function fetchTimeline() {
    if (!timelineChart) return;
    try {
        const res = await fetch(`/api/timeline?period=${currentPeriod}`);
        if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
        const data = await res.json();
        
        if (!data || !Array.isArray(data.labels)) {
            console.warn("Timeline data invalid", data);
            return;
        }

        // Map labels to display format
        timelineChart.data.labels = data.labels.map(l => {
            if (!l) return "";
            if (currentPeriod === '24h') {
                return l.split(' ')[1] || l;
            }
            // For longer periods, show Month/Day
            const parts = l.split('-');
            return parts.length >= 3 ? `${parts[1]}/${parts[2]}` : l;
        });

        timelineChart.data.datasets[0].data = data.counts || [];
        timelineChart.data.datasets[1].data = data.command_counts || [];
        timelineChart.update('none');
    } catch (e) {
        console.error("Timeline refresh failed", e);
    }
}

function initCommandIntelligence() {
    const searchInput = document.getElementById('command-search');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            renderCommandIntelligence(e.target.value);
        });
    }
    fetchCommandIntelligence();
}

async function fetchCommandIntelligence() {
    try {
        const res = await fetch('/api/commands');
        commandIntelData = await res.json();
        renderCommandIntelligence();
    } catch (e) {
        console.error("Failed to fetch command intel", e);
    }
}

function renderCommandIntelligence(search = '') {
    const tbody = document.getElementById('commandIntelBody');
    if (!tbody) return;

    const filtered = commandIntelData.filter(c => 
        c.command.toLowerCase().includes(search.toLowerCase()) || 
        c.category.toLowerCase().includes(search.toLowerCase())
    );

    tbody.innerHTML = '';
    filtered.forEach(c => {
        const row = document.createElement('tr');
        row.className = 'hover:bg-gh-bg/50 border-b border-gh-border/50';
        if (c.risk === 'HIGH') row.classList.add('bg-gh-red/10');
        
        const riskColor = c.risk === 'HIGH' ? 'text-gh-red' : (c.risk === 'MEDIUM' ? 'text-gh-yellow' : 'text-gh-green');
        row.innerHTML = `
            <td class="px-4 py-3 font-mono text-[10px] text-gh-text max-w-md truncate" title="${escapeHtml(c.command)}">
                ${escapeHtml(c.command)}
            </td>
            <td class="px-4 py-3 text-gh-muted">${c.count.toLocaleString()}</td>
            <td class="px-4 py-3">
                <span class="px-1.5 py-0.5 rounded text-[9px] font-bold border ${riskColor} border-current/20">${c.risk}</span>
            </td>
            <td class="px-4 py-3 text-gh-muted uppercase text-[9px]">${escapeHtml(c.category)}</td>
        `;
        tbody.appendChild(row);
    });
}

function exportCommandsCSV() {
    let csv = 'Command,Count,Risk,Category\n';
    commandIntelData.forEach(c => {
        csv += `"${c.command.replace(/"/g, '""')}",${c.count},${c.risk},"${c.category}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `snakesec_command_intelligence_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
}

async function updateData() {
    try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        
        document.getElementById('total-hits').innerText = stats.total_sessions.toLocaleString();
        document.getElementById('total-bruteforce').innerText = stats.total_credentials.toLocaleString();
        document.getElementById('total-commands').innerText = stats.total_commands.toLocaleString();

        const passRoot = document.getElementById('topPasswordsList');
        if (passRoot && stats.top_passwords_only) {
            passRoot.innerHTML = '';
            const max = stats.top_passwords_only[0]?.count || 1;
            stats.top_passwords_only.forEach(p => {
                const percent = (p.count / max) * 100;
                passRoot.innerHTML += `
                    <div class="space-y-1">
                        <div class="flex justify-between text-[10px] font-mono">
                            <span class="text-gh-text">${escapeHtml(p.value)}</span> 
                            <span class="text-gh-muted">${p.count}</span>
                        </div>
                        <div class="w-full bg-gh-bg h-1.5 rounded-full overflow-hidden">
                            <div class="bg-gh-red h-full" style="width: ${percent}%"></div>
                        </div>
                    </div>`;
            });
        }

        const userRoot = document.getElementById('topUsernamesList');
        if (userRoot && stats.top_usernames) {
            userRoot.innerHTML = '';
            const max = stats.top_usernames[0]?.count || 1;
            stats.top_usernames.forEach(u => {
                const percent = (u.count / max) * 100;
                userRoot.innerHTML += `
                    <div class="space-y-1">
                        <div class="flex justify-between text-[10px] font-mono">
                            <span class="text-gh-text">${escapeHtml(u.value)}</span> 
                            <span class="text-gh-muted">${u.count}</span>
                        </div>
                        <div class="w-full bg-gh-bg h-1.5 rounded-full overflow-hidden">
                            <div class="bg-gh-blue h-full" style="width: ${percent}%"></div>
                        </div>
                    </div>`;
            });
        }

        const countryRoot = document.getElementById('topCountriesList');
        if (countryRoot && stats.top_countries) {
            countryRoot.innerHTML = '';
            const max = stats.top_countries[0]?.count || 1;
            stats.top_countries.forEach(c => {
                const percent = (c.count / max) * 100;
                countryRoot.innerHTML += `
                    <div class="space-y-1">
                        <div class="flex justify-between text-[10px] font-mono">
                            <span class="text-gh-text">${escapeHtml(c.value)}</span> 
                            <span class="text-gh-muted">${c.count}</span>
                        </div>
                        <div class="w-full bg-gh-bg h-1.5 rounded-full overflow-hidden">
                            <div class="bg-gh-yellow h-full" style="width: ${percent}%"></div>
                        </div>
                    </div>`;
            });
        }

        const sessionsRes = await fetch('/api/sessions');
        const sessions = await sessionsRes.json();
        document.getElementById('active-now').innerText = sessions.length;
        
        const activeIds = new Set(sessions.map(s => s.id));
        
        // Remove markers for sessions that are no longer active
        Object.keys(markers).forEach(id => {
            if (!activeIds.has(parseInt(id))) {
                map.removeLayer(markers[id]);
                delete markers[id];
            }
        });

        const tbody = document.querySelector('#sessionsTable tbody');
        if (tbody) {
            tbody.innerHTML = '';
            sessions.forEach(s => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-gh-bg/50';
                row.innerHTML = `
                    <td class="px-4 py-2">${s.ip}</td>
                    <td class="px-4 py-2">
                        <span class="px-1.5 py-0.5 rounded text-[9px] font-bold border ${getThreatClass(s.threat)}">${s.threat}</span>
                    </td>
                    <td class="px-4 py-2">
                        <button onclick="blockIP('${s.ip}')" class="text-gh-red hover:underline">Block</button>
                    </td>
                `;
                tbody.appendChild(row);

                // Add or update map marker
                if (s.lat && s.lon) {
                    if (!markers[s.id]) {
                        const icon = L.divIcon({
                            className: 'pulse-container',
                            html: `<div class="pulse" title="${s.ip}"></div>`,
                            iconSize: [20, 20]
                        });
                        const m = L.marker([s.lat, s.lon], { icon }).addTo(map);
                        markers[s.id] = m;
                    }
                    
                    // Update popup with latest stats
                    const popupHtml = `
                        <div class="space-y-1">
                            <div class="text-gh-blue font-bold border-b border-gh-border pb-1 mb-1">${s.ip}</div>
                            <div><b>Origin:</b> ${s.city || 'Unknown'}, ${s.country}</div>
                            <div><b>Threat Level:</b> <span class="${getThreatClass(s.threat).split(' ')[1]}">${s.threat}</span></div>
                            <div><b>Credentials:</b> ${s.total_creds} Attempted</div>
                            <div><b>Commands:</b> ${s.total_cmds} Executed</div>
                        </div>
                    `;
                    markers[s.id].setPopupContent(popupHtml);
                }
            });
        }

        const reportsRes = await fetch('/api/reports');
        const reports = await reportsRes.json();
        const reportsList = document.getElementById('reportsList');
        if (reportsList) {
            reportsList.innerHTML = '';
            // Reverse so latest is at the top
            const reversedReports = [...reports].reverse();
            reversedReports.forEach(r => {
                reportsList.innerHTML += `
                    <div class="flex items-center justify-between p-2.5 bg-gh-bg/50 border border-gh-border rounded-lg text-[10px] group hover:border-gh-blue/30 transition-all">
                        <div class="flex items-center gap-2 overflow-hidden">
                            <span class="material-symbols-outlined text-gh-muted text-sm group-hover:text-gh-blue transition-colors">description</span>
                            <span class="font-mono text-gh-muted truncate">${r}</span>
                        </div>
                        <a href="/api/download/${r}" class="flex items-center gap-1.5 px-2.5 py-1 bg-gh-blue/10 text-gh-blue rounded border border-gh-blue/20 hover:bg-gh-blue hover:text-white hover:border-gh-blue transition-all" download>
                            <span class="material-symbols-outlined text-[14px]">download</span>
                            <span class="font-bold uppercase tracking-wider text-[9px]">Download</span>
                        </a>
                    </div>`;
            });
        }
        
        fetchTimeline(); // Keep chart synced with periodic updates
        fetchCommandIntelligence(); // Update command intel too

    } catch (e) {
        console.error("Failed to fetch data", e);
    }
}

let currentIPToBlock = null;

function blockIP(ip) {
    currentIPToBlock = ip;
    const modal = document.getElementById('blockModal');
    const ipSpan = document.getElementById('modal-ip');
    if (modal && ipSpan) {
        ipSpan.innerText = ip;
        modal.classList.remove('hidden');
    }
}

function closeBlockModal() {
    const modal = document.getElementById('blockModal');
    if (modal) modal.classList.add('hidden');
    currentIPToBlock = null;
}

async function confirmBlock() {
    if (!currentIPToBlock) return;
    try {
        const res = await fetch('/api/block', {
            method: 'POST',
            body: JSON.stringify({ ip: currentIPToBlock })
        });
        if (res.ok) {
            closeBlockModal();
            updateData();
        }
    } catch (e) {
        console.error("Block failed", e);
    }
}

function getThreatClass(threat) {
    switch (threat) {
        case 'CRITICAL': return 'bg-gh-red/10 text-gh-red border-gh-red/30';
        case 'HIGH':     return 'bg-gh-yellow/10 text-gh-yellow border-gh-yellow/30';
        default:         return 'bg-gh-blue/10 text-gh-blue border-gh-blue/30';
    }
}

function openReportModal() {
    const modal = document.getElementById('reportModal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
        
        const now = new Date();
        const yesterday = new Date(now.getTime() - (24 * 60 * 60 * 1000));
        
        // Populate and set values for 24h logic
        const setupPicker = (prefix, dateObj) => {
            const dateInput = document.getElementById(`${prefix}-date`);
            const hourSelect = document.getElementById(`${prefix}-hour`);
            const minSelect = document.getElementById(`${prefix}-minute`);

            if (dateInput) dateInput.value = dateObj.toISOString().slice(0, 10);
            
            if (hourSelect) {
                hourSelect.innerHTML = '';
                for(let i=0; i<24; i++) {
                    const h = i.toString().padStart(2, '0');
                    hourSelect.innerHTML += `<option value="${h}">${h}:00</option>`;
                }
                hourSelect.value = dateObj.getHours().toString().padStart(2, '0');
            }

            if (minSelect) {
                minSelect.innerHTML = '';
                for(let i=0; i<60; i+=5) {
                    const m = i.toString().padStart(2, '0');
                    minSelect.innerHTML += `<option value="${m}">${m}</option>`;
                }
                minSelect.value = (Math.floor(dateObj.getMinutes()/5)*5).toString().padStart(2, '0');
            }
        };

        const sixHoursAgo = new Date(now.getTime() - 6 * 60 * 60 * 1000);
        const oneHourHence = new Date(now.getTime() + 1 * 60 * 60 * 1000);

        setupPicker('report-start', sixHoursAgo);
        setupPicker('report-end', oneHourHence);
    }
}

function closeReportModal() {
    const modal = document.getElementById('reportModal');
    if (modal) modal.classList.add('hidden');
}

async function generateReport() {
    const btn = document.getElementById('btn-generate');
    const startDate = document.getElementById('report-start-date').value;
    const startHour = document.getElementById('report-start-hour').value;
    const startMin = document.getElementById('report-start-minute').value;
    const endDate = document.getElementById('report-end-date').value;
    const endHour = document.getElementById('report-end-hour').value;
    const endMin = document.getElementById('report-end-minute').value;
    const format = document.getElementById('report-format').value;
    const geo = document.getElementById('include-geo').checked;
    const threat = document.getElementById('include-threat').checked;
    const creds = document.getElementById('include-creds').checked;
    const cmds = document.getElementById('include-cmds').checked;

    if (!startDate || !endDate) {
        alert("Please select both start and end dates.");
        return;
    }

    const startISO = `${startDate}T${startHour}:${startMin}:00Z`;
    const endISO = `${endDate}T${endHour}:${endMin}:00Z`;

    btn.disabled = true;
    btn.innerText = "GENERATING...";
    btn.classList.add('opacity-50');

    try {
        const res = await fetch('/api/generate-report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                start: startISO,
                end: endISO,
                format: format,
                includes: {
                    creds: creds,
                    commands: cmds,
                    geo: geo,
                    threat: threat
                }
            })
        });

        if (res.ok) {
            const data = await res.json();
            // Show new report in the list immediately
            addReportToList(data.filename);
            closeReportModal();
        } else {
            alert("Report generation failed. Check server logs.");
        }
    } catch (e) {
        console.error("Report error:", e);
        alert("Network error during report generation.");
    } finally {
        btn.disabled = false;
        btn.innerText = "BUILD REPORT";
        btn.classList.remove('opacity-50');
    }
}

function addReportToList(filename) {
    const reportsList = document.getElementById('reportsList');
    if (!reportsList) return;

    // Remove empty state message if it exists
    const emptyMsg = reportsList.querySelector('div.italic');
    if (emptyMsg) emptyMsg.remove();

    const reportDiv = document.createElement('div');
    reportDiv.className = 'flex items-center justify-between p-2.5 bg-gh-bg/50 border border-gh-border rounded-lg text-[10px] group hover:border-gh-green/30 transition-all';
    reportDiv.innerHTML = `
        <div class="flex items-center gap-2 overflow-hidden">
            <span class="material-symbols-outlined text-gh-muted text-sm group-hover:text-gh-green transition-colors">description</span>
            <span class="font-mono text-gh-muted truncate">${filename}</span>
        </div>
        <a href="/api/download/${filename}" class="flex items-center gap-1.5 px-2.5 py-1 bg-gh-green/10 text-gh-green rounded border border-gh-green/20 hover:bg-gh-green hover:text-white hover:border-gh-green transition-all" download>
            <span class="material-symbols-outlined text-[14px]">download</span>
            <span class="font-bold uppercase tracking-wider text-[9px]">Download</span>
        </a>
    `;
    
    // Add to top of list
    reportsList.prepend(reportDiv);
}

async function clearReports() {
    if (!confirm("Are you sure you want to clear all generated reports? This will delete files from the server disk.")) {
        return;
    }

    try {
        const res = await fetch('/api/clear-reports', { method: 'POST' });
        if (res.ok) {
            updateData(); // Refresh the list
        } else {
            alert("Failed to clear reports.");
        }
    } catch (e) {
        console.error("Clear reports error:", e);
        alert("Network error while clearing reports.");
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.innerText = text || "";
    return div.innerHTML;
}
