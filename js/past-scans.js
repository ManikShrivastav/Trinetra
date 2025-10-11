const menuToggle = document.getElementById('menuToggle');
const sidebar = document.getElementById('sidebar');
const loginBtn = document.getElementById('loginBtn');
const signupBtn = document.getElementById('signupBtn');
const authButtons = document.getElementById('authButtons');
const profileSection = document.getElementById('profileSection');
const profileBtn = document.getElementById('profileBtn');
const dropdownMenu = document.getElementById('dropdownMenu');
const logoutBtn = document.getElementById('logoutBtn');

const searchInput = document.getElementById('searchInput');
const severityFilter = document.getElementById('severityFilter');
const detailsModal = document.getElementById('detailsModal');
const modalClose = document.getElementById('modalClose');

// Load scan history on page load
let allScans = [];
let currentScanDetails = null;

async function loadScanHistory() {
  try {
    // Use authenticated fetch from Auth module
    allScans = await Auth.authenticatedFetch('/api/scans/history', {
      method: 'GET'
    });
    
    console.log('Loaded scan history:', allScans);
    renderScanHistory(allScans);
  } catch (error) {
    console.error('Error loading scan history:', error);
    const container = document.querySelector('.scans-container');
    if (container) {
      container.innerHTML = '<p style="padding: 20px; text-align: center;">Failed to load scan history. Please refresh the page.</p>';
    }
  }
}

function renderScanHistory(scans) {
  const container = document.querySelector('.scans-container');
  if (!container) return;
  
  if (scans.length === 0) {
    container.innerHTML = '<p style="padding: 20px; text-align: center;">No scan history found. Run your first scan!</p>';
    return;
  }
  
  container.innerHTML = scans.map((scan, index) => {
    const severityClass = scan.status === 'completed' ? 'completed' : 
                         scan.status === 'failed' ? 'critical' : 'medium';
    const severityText = scan.status.charAt(0).toUpperCase() + scan.status.slice(1);
    
    // Get risk summary data
    const riskSummary = scan.risk_summary || {
      total_vulnerabilities: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      highest_severity: 'none',
      average_cvss: 0
    };
    
    // Determine highest severity badge
    const highestSeverity = riskSummary.highest_severity || 'none';
    const severityBadgeClass = highestSeverity !== 'none' ? highestSeverity : 'low';
    const severityBadgeText = highestSeverity.toUpperCase();
    
    return `
      <div class="scan-card" data-scan-id="${scan.scan_id}">
        <div class="scan-info">
          <h3>${scan.target}</h3>
          <p class="scan-date">${new Date(scan.timestamp).toLocaleString()}</p>
          <div class="scan-meta">
            <span>Targets: ${scan.total_targets}</span>
            <span>Tools: ${(scan.workers || ['nmap', 'nikto', 'nuclei']).join(', ')}</span>
          </div>
        </div>
        <div class="scan-summary">
          <div class="summary-stats">
            <div class="stat-item">
              <span class="stat-count">${riskSummary.total_vulnerabilities}</span>
              <span class="stat-label">Total</span>
            </div>
            <div class="stat-item critical">
              <span class="stat-count">${riskSummary.critical_count}</span>
              <span class="stat-label">Critical</span>
            </div>
            <div class="stat-item high">
              <span class="stat-count">${riskSummary.high_count}</span>
              <span class="stat-label">High</span>
            </div>
            <div class="stat-item medium">
              <span class="stat-count">${riskSummary.medium_count}</span>
              <span class="stat-label">Medium</span>
            </div>
            <div class="stat-item low">
              <span class="stat-count">${riskSummary.low_count}</span>
              <span class="stat-label">Low</span>
            </div>
          </div>
          ${riskSummary.average_cvss > 0 ? `
            <div class="cvss-average">
              Avg CVSS: <strong>${riskSummary.average_cvss}</strong>
            </div>
          ` : ''}
          <span class="severity-badge ${severityBadgeClass}">${severityBadgeText}</span>
        </div>
        <div class="scan-actions">
          <span class="scan-badge ${severityClass}">${severityText}</span>
          <button class="view-details" data-scan-id="${scan.scan_id}">View Details</button>
          <button class="download-csv" data-scan-id="${scan.scan_id}">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            CSV
          </button>
        </div>
      </div>
    `;
  }).join('');
  
  // Re-attach event listeners
  attachViewDetailsListeners();
  attachDownloadCsvListeners();
}

function attachDownloadCsvListeners() {
  const downloadButtons = document.querySelectorAll('.download-csv');
  downloadButtons.forEach(button => {
    button.addEventListener('click', async (e) => {
      e.stopPropagation();
      const scanId = e.currentTarget.dataset.scanId;
      await downloadCsv(scanId);
    });
  });
}

async function downloadCsv(scanId) {
  try {
    // Use authenticated fetch from Auth module (returns Response object for file downloads)
    const response = await Auth.authenticatedFetch(`/api/export/csv/${scanId}`, {
      method: 'GET'
    });
    
    // Create blob from response
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan_${scanId}_results.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    
    console.log('CSV downloaded successfully');
  } catch (error) {
    console.error('Error downloading CSV:', error);
    alert('Failed to download CSV: ' + error.message);
  }
}

function attachViewDetailsListeners() {
  const viewDetailsButtons = document.querySelectorAll('.view-details');
  viewDetailsButtons.forEach(button => {
    button.addEventListener('click', async (e) => {
      const scanId = e.target.dataset.scanId;
      await loadScanDetails(scanId);
    });
  });
}

async function loadScanDetails(scanId) {
  try {
    // Use authenticated fetch from Auth module
    const scanDetails = await Auth.authenticatedFetch(`/api/scan/results/${scanId}`, {
      method: 'GET'
    });
    
    displayScanDetails(scanDetails);
  } catch (error) {
    console.error('Error loading scan details:', error);
    alert('Failed to load scan details: ' + error.message);
  }
}

function displayScanDetails(scanDetails) {
  const targets = scanDetails.results.map(r => r.target).join(', ');
  document.getElementById('modalTarget').textContent = targets;
  document.getElementById('modalDate').textContent = new Date(scanDetails.scan_timestamp).toLocaleString();
  
  // Get vulnerabilities and risk summary
  const vulnerabilities = scanDetails.vulnerabilities || [];
  const riskSummary = scanDetails.risk_summary || {
    total_vulnerabilities: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0
  };
  
  // Display detailed results
  const modalBody = document.querySelector('#detailsModal .modal-body');
  
  if (modalBody) {
    let detailsHTML = '<div class="scan-details">';
    
    // Add risk summary section
    detailsHTML += `
      <div class="risk-summary-section">
        <h4>Risk Summary</h4>
        <div class="summary-stats">
          <div class="stat-item">
            <span class="stat-count">${riskSummary.total_vulnerabilities}</span>
            <span class="stat-label">Total Vulnerabilities</span>
          </div>
          <div class="stat-item critical">
            <span class="stat-count">${riskSummary.critical_count}</span>
            <span class="stat-label">Critical</span>
          </div>
          <div class="stat-item high">
            <span class="stat-count">${riskSummary.high_count}</span>
            <span class="stat-label">High</span>
          </div>
          <div class="stat-item medium">
            <span class="stat-count">${riskSummary.medium_count}</span>
            <span class="stat-label">Medium</span>
          </div>
          <div class="stat-item low">
            <span class="stat-count">${riskSummary.low_count}</span>
            <span class="stat-label">Low</span>
          </div>
        </div>
        ${riskSummary.average_cvss ? `
          <p style="margin-top: 12px;">Average CVSS Score: <strong>${riskSummary.average_cvss}</strong></p>
        ` : ''}
      </div>
    `;
    
    // Add vulnerabilities section
    if (vulnerabilities.length > 0) {
      detailsHTML += '<h4 style="margin-top: 24px;">Vulnerabilities</h4>';
      
      vulnerabilities.forEach(vuln => {
        const severityClass = vuln.severity ? vuln.severity.toLowerCase() : 'low';
        const severityBadge = vuln.severity ? vuln.severity.toUpperCase() : 'UNKNOWN';
        
        detailsHTML += `
          <div class="vulnerability-item ${severityClass}-item">
            <div class="vuln-header">
              <div>
                <strong>${vuln.cve_id || 'Unknown CVE'}</strong>
                <span class="severity-badge ${severityClass}">${severityBadge}</span>
              </div>
              <div class="cvss-scores">
                ${vuln.cvss_v3 && vuln.cvss_v3 !== 'N/A' ? `<span class="cvss-badge">CVSS v3: ${vuln.cvss_v3}</span>` : ''}
                ${vuln.cvss_v2 && vuln.cvss_v2 !== 'N/A' ? `<span class="cvss-badge">CVSS v2: ${vuln.cvss_v2}</span>` : ''}
              </div>
            </div>
            <p><strong>Source:</strong> ${vuln.source_tool || 'Unknown'} | <strong>Target:</strong> ${vuln.target || 'N/A'}</p>
            <p class="vuln-description"><strong>Description:</strong> ${vuln.description || 'No description available'}</p>
            ${vuln.recommendation && vuln.recommendation !== 'See NVD for details' ? `
              <p class="vuln-recommendation"><strong>Recommendation:</strong> ${vuln.recommendation}</p>
            ` : ''}
          </div>
        `;
      });
    } else {
      detailsHTML += `
        <div class="no-vulnerabilities" style="margin-top: 24px;">
          <p>No enriched vulnerabilities found in this scan.</p>
        </div>
      `;
    }
    
    // Add scan results section
    detailsHTML += '<h4 style="margin-top: 24px;">Scan Results</h4>';
    scanDetails.results.forEach(targetResult => {
      detailsHTML += `<h5>Target: ${targetResult.target}</h5>`;
      detailsHTML += '<div class="worker-results">';
      
      Object.entries(targetResult.results).forEach(([worker, result]) => {
        const statusIcon = result.ok ? '✓' : '✗';
        const statusClass = result.ok ? 'success' : 'error';
        
        detailsHTML += `
          <div class="worker-result ${statusClass}">
            <strong>${statusIcon} ${worker.toUpperCase()}</strong>
            ${result.ok ? 
              `<p>Output: <code>${result.output}</code></p>` : 
              `<p>Error: ${result.error}</p>`
            }
          </div>
        `;
      });
      
      detailsHTML += '</div>';
    });
    
    detailsHTML += '</div>';
    
    // Clear existing content and add new
    const existingDetails = modalBody.querySelector('.scan-details');
    if (existingDetails) {
      existingDetails.remove();
    }
    modalBody.insertAdjacentHTML('beforeend', detailsHTML);
  }
  
  detailsModal.classList.remove('hidden');
}

// Load history on page load
window.addEventListener('DOMContentLoaded', loadScanHistory);

menuToggle.addEventListener('click', () => {
  sidebar.classList.toggle('open');
});

profileBtn.addEventListener('click', () => {
  dropdownMenu.classList.toggle('hidden');
});

document.addEventListener('click', (e) => {
  if (!profileBtn.contains(e.target)) {
    dropdownMenu.classList.add('hidden');
  }
});

logoutBtn.addEventListener('click', () => {
  localStorage.removeItem('isLoggedIn');
  localStorage.removeItem('userEmail');
  window.location.reload();
});

function showProfile(email) {
  const username = email.split('@')[0];
  document.getElementById('username').textContent = username;
  authButtons.classList.add('hidden');
  profileSection.classList.remove('hidden');
}

if (localStorage.getItem('isLoggedIn') === 'true') {
  const email = localStorage.getItem('userEmail');
  showProfile(email);
}

searchInput.addEventListener('input', filterScans);
severityFilter.addEventListener('change', filterScans);

function filterScans() {
  const searchTerm = searchInput.value.toLowerCase();
  const severity = severityFilter.value;
  
  let filteredScans = allScans;
  
  // Filter by search term
  if (searchTerm) {
    filteredScans = filteredScans.filter(scan => 
      scan.target.toLowerCase().includes(searchTerm) ||
      scan.scan_id.toLowerCase().includes(searchTerm)
    );
  }
  
  // Filter by status/severity
  if (severity !== 'all') {
    filteredScans = filteredScans.filter(scan => 
      scan.status.toLowerCase() === severity.toLowerCase()
    );
  }
  
  renderScanHistory(filteredScans);
}

// Kept for compatibility, but now handled in attachViewDetailsListeners()
const viewDetailsButtons = document.querySelectorAll('.view-details');

modalClose.addEventListener('click', () => {
  detailsModal.classList.add('hidden');
});

detailsModal.addEventListener('click', (e) => {
  if (e.target === detailsModal) {
    detailsModal.classList.add('hidden');
  }
});



/* Mode toggle: persist mode in localStorage and apply body class */
const modeToggleBtn = document.getElementById('modeToggle');
function applyMode(mode) {
  document.body.classList.remove('mode-1', 'mode-2');
  document.body.classList.add(mode === 'mode-2' ? 'mode-2' : 'mode-1');
  if (modeToggleBtn) modeToggleBtn.textContent = mode === 'mode-2' ? 'Mode 2' : 'Mode 1';
}

function initMode() {
  const saved = localStorage.getItem('uiMode');
  const mode = saved === 'mode-2' ? 'mode-2' : 'mode-1';
  applyMode(mode);
}

if (modeToggleBtn) {
  modeToggleBtn.addEventListener('click', () => {
    const current = document.body.classList.contains('mode-2') ? 'mode-2' : 'mode-1';
    const next = current === 'mode-1' ? 'mode-2' : 'mode-1';
    applyMode(next);
    localStorage.setItem('uiMode', next);
  });
}

// initialize on load

// Theme toggle logic
const themeToggle = document.getElementById('themeToggle');
function applyTheme(theme) {
  document.body.classList.remove('theme-dark', 'theme-light');
  document.body.classList.add(theme === 'light' ? 'theme-light' : 'theme-dark');
  if (themeToggle) themeToggle.checked = theme === 'light';
}

function initTheme() {
  const saved = localStorage.getItem('theme');
  const theme = saved === 'light' ? 'light' : 'dark';
  applyTheme(theme);
}

if (themeToggle) {
  themeToggle.addEventListener('change', () => {
    const theme = themeToggle.checked ? 'light' : 'dark';
    applyTheme(theme);
    localStorage.setItem('theme', theme);
  });
}

initTheme();
