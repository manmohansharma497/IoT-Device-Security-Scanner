
function debugLog(message) {
    const debugOutput = document.getElementById('debug-output');
    if (debugOutput) {
        debugOutput.innerHTML += `<div>${new Date().toLocaleTimeString()}: ${message}</div>`;
    }
    console.log(message);
}

// Then replace all console.log() calls with debugLog()

// Global variables
let vulnerabilityChart, portChart;
let currentPage = 1;
const rowsPerPage = 10;

// Initialize the dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Set up event listeners
    setupEventListeners();
    
    // Load initial data
    refreshData();
    
    // Set up auto-refresh every 10 seconds
    setInterval(refreshData, 10000);
    
    // Initialize Socket.IO for real-time updates
    initSocketIO();
    
    // Initialize dark mode toggle
    initDarkMode();
});

// Add click handlers for device detail icons
document.addEventListener('click', function(e) {
    if (e.target.closest('[data-feather="eye"]')) {
        const ip = e.target.getAttribute('data-ip');
        openDeviceModal(ip);
    }
    
    if (e.target.closest('#close-modal')) {
        document.getElementById('device-modal').style.display = 'none';
    }
});

function initCharts() {
    // Vulnerability Chart (Doughnut)
    const vulnerabilityCtx = document.getElementById('vulnerabilityChart').getContext('2d');
    vulnerabilityChart = new Chart(vulnerabilityCtx, {
    type: 'doughnut',
    data: {
        labels: ['Low', 'Medium', 'High', 'Critical'],
        datasets: [{
            data: [0, 0, 0, 0], // Initial values
            backgroundColor: ['#10B981', '#F59E0B', '#EF4444', '#7C3AED']
        }]
    }
});

const portCtx = document.getElementById('portChart').getContext('2d');
portChart = new Chart(portCtx, {
    type: 'bar',
    data: {
        labels: ['HTTP (80)', 'SSH (22)', 'Telnet (23)', 'Other'],
        datasets: [{
            data: [0, 0, 0, 0], // Initial values
            backgroundColor: ['#6366F1', '#10B981', '#F59E0B', '#9CA3AF']
        }]
    }
});
}

function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('search');
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            const term = e.target.value.toLowerCase();
            const rows = document.querySelectorAll('#devices-table-body tr');
            rows.forEach(row => {
                row.style.display = row.innerText.toLowerCase().includes(term) ? '' : 'none';
            });
        });
    }

    // Manual refresh button
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshData);
    }

    // Export buttons
    document.querySelectorAll('.export-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            alert('Export functionality would go here');
        });
    });
}

// Call this when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
    refreshData();
});

function initSocketIO() {
    const socket = io();
    
    socket.on('new_scan', (scan) => {
        showNotification(`New device scanned: ${scan.ip_address}`);
        refreshData();
    });
}

function initDarkMode() {
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    // Set initial mode based on preference
    if (prefersDark) {
        document.body.classList.add('dark-mode');
        darkModeToggle.querySelector('i').setAttribute('data-feather', 'sun');
        feather.replace();
    }
    
    // Toggle dark/light mode
    darkModeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        const icon = darkModeToggle.querySelector('i');
        if (document.body.classList.contains('dark-mode')) {
            icon.setAttribute('data-feather', 'sun');
        } else {
            icon.setAttribute('data-feather', 'moon');
        }
        feather.replace();
    });
}

// async function refreshData() {
//     try {
//         // 1. First verify connection
//         const isConnected = await testConnection();
//         if (!isConnected) return;

//         // 2. Show loading state
//         showLoadingState();

//         // 3. Fetch data
//         const [scans, vulnStats, portStats] = await Promise.all([
//             fetch('/api/scans').then(handleResponse),
//             fetch('/api/vulnerability-stats').then(handleResponse),
//             fetch('/api/port-stats').then(handleResponse)
//         ]);

//         // 4. Update UI
//         updateUI(scans, vulnStats, portStats);

//     } catch (error) {
//         handleRefreshError(error);
//     }
// }

function handleResponse(response) {
    if (!response.ok) {
        throw new Error(`API request failed with status ${response.status}`);
    }
    return response.json();
}

function showLoadingState() {
    document.querySelectorAll('.stat-card h3').forEach(el => {
        el.innerHTML = '<div class="skeleton"></div>';
    });
    document.getElementById('devices-table-body').innerHTML = `
        <tr><td colspan="7" style="text-align:center">Loading data...</td></tr>
    `;
}

function updateUI(scans, vulnStats, portStats) {
    updateStatsCards(scans);
    updateCharts(vulnStats, portStats);
    updateTable(scans);
    showNotification('Data refreshed successfully');
}

function handleRefreshError(error) {
    console.error('Refresh failed:', error);
    showNotification(`Refresh failed: ${error.message}`, 'error');
    document.getElementById('devices-table-body').innerHTML = `
        <tr><td colspan="7" style="text-align:center;color:red">Failed to load data</td></tr>
    `;
}

function updateStatsCards(scans) {
    let secureCount = 0;
    let warningCount = 0;
    let criticalCount = 0;
    
    scans.forEach(scan => {
        try {
            const cveData = scan[7] ? JSON.parse(scan[7]) : null;
            const vulnCount = cveData?.result?.CVE_Items?.length || 0;
            
            if (vulnCount === 0) {
                secureCount++;
            } else if (vulnCount > 3) {
                criticalCount++;
            } else {
                warningCount++;
            }
        } catch (e) {
            console.error('Error parsing CVE data:', e);
        }
    });
    
    document.getElementById('device-count').textContent = scans.length;
    document.getElementById('secure-count').textContent = secureCount;
    document.getElementById('warning-count').textContent = warningCount;
    document.getElementById('critical-count').textContent = criticalCount;
}

function updateCharts(vulnStats, portStats) {
    if (!vulnerabilityChart || !portChart) {
        console.error('Charts not initialized');
        return;
    }
    
    try {
        vulnerabilityChart.data.datasets[0].data = [
            vulnStats?.low || 0,
            vulnStats?.medium || 0,
            vulnStats?.high || 0,
            vulnStats?.critical || 0
        ];
        vulnerabilityChart.update();
    } catch (e) {
        console.error('Error updating vulnerability chart:', e);
    }

    try {
        portChart.data.datasets[0].data = portStats || [0, 0, 0, 0];
        portChart.update();
    } catch (e) {
        console.error('Error updating port chart:', e);
    }
}

// In script.js - Enhance the updateTable function
function updateTable(data) {
    const tbody = document.getElementById('devices-table-body');
    tbody.innerHTML = '';

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center">No devices found</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(scan => {
        let openPorts = [];
        let cveData = null;
        let vulnCount = 0;
        let status = 'safe';
        let credentialsFound = false;
        
        try {
            openPorts = scan[5] ? JSON.parse(scan[5]) : [];
            cveData = scan[6] ? JSON.parse(scan[6]) : null;
            credentialsFound = cveData && cveData.length > 0;
            vulnCount = scan[7] ? JSON.parse(scan[7])?.result?.CVE_Items?.length || 0 : 0;
            status = credentialsFound ? 'critical' : 
                    vulnCount > 3 ? 'critical' : 
                    vulnCount > 0 ? 'warning' : 'safe';
        } catch (e) {
            console.error('Error parsing scan data:', e);
        }
        
        return `
            <tr>
                <td>
                    <div class="device-info">
                        <i data-feather="${getDeviceIcon(scan[1])}"></i>
                        <span>${scan[1] || 'Unknown'}</span>
                    </div>
                </td>
                <td>${scan[2]}</td>
                <td><span class="status-badge status-${status}">${status.toUpperCase()}</span></td>
                <td>
                    ${openPorts.length > 0 ? 
                        `<span class="ports-summary" title="${openPorts.map(p => p.port).join(', ')}">
                            ${openPorts.length} ports
                            ${openPorts.some(p => [22, 23, 80, 443].includes(p.port)) ? '⚠️' : ''}
                        </span>` : 
                        'None'}
                </td>
                <td>
                    ${vulnCount > 0 ? 
                        `<span class="vuln-summary ${status}">
                            ${vulnCount} vulns
                            ${credentialsFound ? '🔑' : ''}
                        </span>` : 
                        'None'}
                </td>
                <td>${scan[9] ? formatTimeAgo(scan[9]) : 'N/A'}</td>
                <td class="actions-cell">
                    <button class="btn-icon" data-ip="${scan[2]}" title="View details">
                        <i data-feather="eye"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    feather.replace();
}

function getDeviceIcon(deviceName) {
    if (!deviceName) return 'cpu';
    const lowerName = deviceName.toLowerCase();
    if (lowerName.includes('camera')) return 'video';
    if (lowerName.includes('thermostat')) return 'thermometer';
    if (lowerName.includes('router') || lowerName.includes('access point')) return 'wifi';
    if (lowerName.includes('printer')) return 'printer';
    return 'cpu';
}

function formatTimeAgo(timestamp) {
    if (!timestamp) return 'Just now';
    
    const now = new Date();
    const scanTime = new Date(timestamp);
    const diffSeconds = Math.floor((now - scanTime) / 1000);
    
    if (diffSeconds < 60) return 'Just now';
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds/60)} min ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds/3600)} hours ago`;
    return `${Math.floor(diffSeconds/86400)} days ago`;
}

function updatePagination(totalItems) {
    const totalPages = Math.ceil(totalItems / rowsPerPage);
    document.getElementById('page-info').textContent = `Page ${currentPage} of ${totalPages}`;
    document.getElementById('prev-page').disabled = currentPage === 1;
    document.getElementById('next-page').disabled = currentPage === totalPages || totalPages === 0;
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        refreshData();
    }
}

function nextPage() {
    const totalItems = document.getElementById('devices-table-body').children.length;
    const totalPages = Math.ceil(totalItems / rowsPerPage);
    if (currentPage < totalPages) {
        currentPage++;
        refreshData();
    }
}

// In script.js - Enhance the openDeviceModal function
async function openDeviceModal(ipAddress) {
    try {
        // Show loading state
        const modal = document.getElementById('device-modal');
        modal.style.display = 'flex';
        
        // Fetch device details
        const response = await fetch(`/api/device-details?ip=${ipAddress}`);
        if (!response.ok) throw new Error('Device not found');
        
        const device = await response.json();
        
        // Update modal with enhanced details
        document.getElementById('detail-device-name').textContent = device.device_name || 'Unknown';
        document.getElementById('detail-ip').textContent = device.ip_address;
        document.getElementById('detail-mac').textContent = device.mac_address;
        document.getElementById('detail-vendor').textContent = device.vendor_name || 'Unknown';
        document.getElementById('detail-timestamp').textContent = formatTimeAgo(device.timestamp);
        
        // Enhanced ports list with more details
        const portsList = document.getElementById('ports-list');
        if (device.open_ports && device.open_ports.length > 0) {
            portsList.innerHTML = device.open_ports.map(port => `
                <li>
                    <div class="port-detail">
                        <strong>Port ${port.port}</strong>
                        <span>${port.protocol.toUpperCase()}</span>
                        <span>Service: ${port.service}</span>
                        ${port.version ? `<span>Version: ${port.version}</span>` : ''}
                    </div>
                    <div class="port-risk">
                        ${getPortRiskIndicator(port.port)}
                    </div>
                </li>
            `).join('');
        } else {
            portsList.innerHTML = '<li>No open ports found</li>';
        }
        
        // Enhanced vulnerabilities list
        const vulnList = document.getElementById('vulnerabilities-list');
        if (device.cve_data?.result?.CVE_Items) {
            vulnList.innerHTML = device.cve_data.result.CVE_Items.map(vuln => {
                const severity = vuln.impact?.baseMetricV2?.severity || 'LOW';
                const cvss = vuln.impact?.baseMetricV2?.cvssV2?.baseScore || 'N/A';
                return `
                    <li class="${severity.toLowerCase()}">
                        <div class="vuln-header">
                            <strong>${vuln.cve.CVE_data_meta.ID}</strong>
                            <span class="cvss-score">CVSS: ${cvss}</span>
                        </div>
                        <div class="vuln-desc">${vuln.cve.description.description_data[0].value}</div>
                        <div class="vuln-meta">
                            <span>Published: ${vuln.publishedDate}</span>
                            <a href="https://nvd.nist.gov/vuln/detail/${vuln.cve.CVE_data_meta.ID}" target="_blank">More info</a>
                        </div>
                    </li>
                `;
            }).join('');
        } else {
            vulnList.innerHTML = '<li>No vulnerabilities found</li>';
        }
        
    } catch (error) {
        console.error('Error loading device details:', error);
        showNotification('Failed to load device details', 'error');
    } finally {
        feather.replace();
    }
}

function getPortRiskIndicator(port) {
    const riskyPorts = {
        22: 'SSH - Secure Shell',
        23: 'Telnet - Insecure',
        80: 'HTTP - Web',
        443: 'HTTPS - Secure Web',
        21: 'FTP - File Transfer',
        3389: 'RDP - Remote Desktop'
    };
    
    if (riskyPorts[port]) {
        return `<span class="port-warning">⚠️ ${riskyPorts[port]}</span>`;
    }
    return '<span class="port-safe">✅ Standard</span>';
}

async function exportCSV() {
    try {
        const scans = await fetch('/api/scans').then(res => res.json());
        
        let csv = 'Device Name,IP Address,MAC Address,Vendor,Open Ports,Vulnerabilities,Last Scan\n';
        scans.forEach(scan => {
            const openPorts = scan[5] ? JSON.parse(scan[5]).length : 0;
            const vulnerabilities = scan[7] ? JSON.parse(scan[7]).result?.CVE_Items?.length || 0 : 0;
            
            csv += `"${scan[1] || ''}","${scan[2]}","${scan[3]}","${scan[4] || ''}",${openPorts},${vulnerabilities},"${scan[9]}"\n`;
        });
        
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `iot_scan_report_${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        
        showNotification('CSV export started');
    } catch (error) {
        console.error('Export failed:', error);
        showNotification('Export failed. Please try again.', 'error');
    }
}

fetch('/api/scans')
    .then(response => response.json())
    .then(data => {
        console.log("Scans data:", data);  // Add this line
        updateTable(data);
    })
    .catch(error => {
        console.error("Error fetching scans:", error);
    });

function printReport() {
    window.print();
}

function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <i data-feather="${type === 'error' ? 'alert-circle' : 'check-circle'}"></i>
        <span>${message}</span>
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
    
    feather.replace();
}



// Test the connection first
async function testConnection() {
    try {
        const response = await fetch('/api/test');  // Add this test endpoint
        if (!response.ok) throw new Error('Network response was not ok');
        return true;
    } catch (error) {
        console.error('Connection test failed:', error);
        showNotification('Cannot connect to server', 'error');
        return false;
    }
}



// In script.js - Add new functions
async function updateRiskOverview() {
    try {
        const scans = await fetch('/api/scans').then(res => res.json());
        
        let highRiskCount = 0;
        let exposedServices = new Set();
        let credentialRisks = 0;
        
        scans.forEach(scan => {
            try {
                const ports = scan[5] ? JSON.parse(scan[5]) : [];
                const creds = scan[6] ? JSON.parse(scan[6]) : [];
                const vulns = scan[7] ? JSON.parse(scan[7])?.result?.CVE_Items?.length || 0 : 0;
                
                ports.forEach(port => exposedServices.add(port.service));
                if (creds.length > 0 || vulns > 3) highRiskCount++;
                if (creds.length > 0) credentialRisks++;
            } catch (e) {
                console.error('Error parsing scan:', e);
            }
        });
        
        document.getElementById('high-risk-count').textContent = highRiskCount;
        document.getElementById('exposed-services').textContent = exposedServices.size;
        document.getElementById('credential-risks').textContent = credentialRisks;
        
        // Update risk meter
        const totalDevices = scans.length;
        const riskPercentage = totalDevices > 0 ? Math.min(100, (highRiskCount / totalDevices) * 150) : 0;
        document.getElementById('risk-level-indicator').style.width = `${riskPercentage}%`;
        document.getElementById('risk-level-indicator').className = 
            `risk-level ${riskPercentage > 60 ? 'high' : riskPercentage > 30 ? 'medium' : 'low'}`;
            
        // Update vulnerable services list
        updateVulnerableServicesList(scans);
    } catch (error) {
        console.error('Error updating risk overview:', error);
    }
}

function updateVulnerableServicesList(scans) {
    const serviceList = document.getElementById('vulnerable-services-list');
    const serviceMap = new Map();
    
    scans.forEach(scan => {
        try {
            const ports = scan[5] ? JSON.parse(scan[5]) : [];
            ports.forEach(port => {
                if (!serviceMap.has(port.service)) {
                    serviceMap.set(port.service, {
                        count: 0,
                        vulnerable: false
                    });
                }
                const service = serviceMap.get(port.service);
                service.count++;
                
                // Mark as vulnerable if associated with vulnerabilities
                const vulns = scan[7] ? JSON.parse(scan[7])?.result?.CVE_Items?.length || 0 : 0;
                if (vulns > 0) {
                    service.vulnerable = true;
                }
            });
        } catch (e) {
            console.error('Error parsing ports:', e);
        }
    });
    
    // Sort by count descending
    const sortedServices = [...serviceMap.entries()].sort((a, b) => b[1].count - a[1].count);
    
    serviceList.innerHTML = sortedServices.map(([service, data]) => `
        <li class="${data.vulnerable ? 'vulnerable' : ''}">
            <span>${service}</span>
            <span class="service-count">${data.count} devices</span>
        </li>
    `).join('');
}

// Call this in your refreshData function
async function refreshData() {
    try {
        showLoadingState();
        const [scans, vulnStats, portStats] = await Promise.all([
            fetch('/api/scans').then(handleResponse),
            fetch('/api/vulnerability-stats').then(handleResponse),
            fetch('/api/port-stats').then(handleResponse)
        ]);
        
        updateUI(scans, vulnStats, portStats);
        updateRiskOverview(); // Add this line
    } catch (error) {
        handleRefreshError(error);
    }
}