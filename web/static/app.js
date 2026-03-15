document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initCharts();
    updateData();
    setInterval(updateData, 3000);
});

let countryChart, passwordChart;

function initNavigation() {
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', (e) => {
            const pageId = link.getAttribute('data-page');
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById(pageId).classList.add('active');
            
            document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
            link.classList.add('active');
        });
    });
}

function initCharts() {
    const ctx1 = document.getElementById('countryChart').getContext('2d');
    countryChart = new Chart(ctx1, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#00ffff', '#00ffaa', '#ffaa00', '#ff3333', '#888'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'right', labels: { color: '#b0b0b0' } } }
        }
    });

    const ctx2 = document.getElementById('passwordChart').getContext('2d');
    passwordChart = new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attempts',
                data: [],
                backgroundColor: 'rgba(0, 255, 255, 0.2)',
                borderColor: '#00ffff',
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#b0b0b0' } },
                x: { grid: { display: false }, ticks: { color: '#b0b0b0' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

async function updateData() {
    try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        
        document.getElementById('total-hits').innerText = stats.total_sessions;
        document.getElementById('unique-ips').innerText = stats.unique_ips;

        // Update Charts
        if (stats.top_countries) {
            countryChart.data.labels = stats.top_countries.map(c => c.value);
            countryChart.data.datasets[0].data = stats.top_countries.map(c => c.count);
            countryChart.update();
        }

        if (stats.top_passwords) {
            passwordChart.data.labels = stats.top_passwords.map(p => p.value);
            passwordChart.data.datasets[0].data = stats.top_passwords.map(p => p.count);
            passwordChart.update();
        }

        const sessionsRes = await fetch('/api/sessions');
        const sessions = await sessionsRes.json();
        document.getElementById('active-now').innerText = sessions.length;
        
        const tbody = document.querySelector('#sessionsTable tbody');
        tbody.innerHTML = '';
        sessions.forEach(s => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${s.ip}</td>
                <td>${s.country}</td>
                <td><span class="threat-label ${s.threat}">${s.threat}</span></td>
                <td>${s.duration}</td>
                <td><button class="btn-block" onclick="blockIP('${s.ip}')">Block</button></td>
            `;
            tbody.appendChild(row);
        });

        // Update Reports
        const reportsRes = await fetch('/api/reports');
        const reports = await reportsRes.json();
        const reportsList = document.getElementById('reportsList');
        reportsList.innerHTML = '';
        reports.forEach(r => {
            const item = document.createElement('div');
            item.className = 'report-item';
            item.innerHTML = `
                <div class="report-info">
                    <h4>${r}</h4>
                    <p>Generated Report</p>
                </div>
                <a href="/api/download/${r}" class="btn-download" download>📥</a>
            `;
            reportsList.appendChild(item);
        });

    } catch (e) {
        console.error("Failed to fetch data", e);
    }
}

async function blockIP(ip) {
    if (!confirm(`Are you sure you want to PERMANENTLY block IP ${ip}?`)) return;
    
    try {
        const res = await fetch('/api/block', {
            method: 'POST',
            body: JSON.stringify({ ip })
        });
        if (res.ok) {
            alert(`IP ${ip} has been blocked and disconnected.`);
            updateData();
        }
    } catch (e) {
        alert("Blocking failed. Check console.");
    }
}
