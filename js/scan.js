const menuToggle = document.getElementById('menuToggle');
const sidebar = document.getElementById('sidebar');
const loginBtn = document.getElementById('loginBtn');
const signupBtn = document.getElementById('signupBtn');
const authButtons = document.getElementById('authButtons');
const profileSection = document.getElementById('profileSection');
const profileBtn = document.getElementById('profileBtn');
const dropdownMenu = document.getElementById('dropdownMenu');
const logoutBtn = document.getElementById('logoutBtn');

const scanForm = document.getElementById('scanForm');
const scanInputSection = document.getElementById('scanInputSection');
const scanProgressSection = document.getElementById('scanProgressSection');
const scanResultsSection = document.getElementById('scanResultsSection');
const newScanBtn = document.getElementById('newScanBtn');

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

// Global scan state
let currentScanId = null;
let pollInterval = null;

scanForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const targetIp = document.getElementById('targetIp').value;

  // Parse targets (support comma-separated)
  const targets = targetIp.split(',').map(t => t.trim()).filter(t => t);
  
  if (targets.length === 0) {
    alert('Please enter at least one target');
    return;
  }

  document.getElementById('scanTarget').textContent = targets.join(', ');

  scanInputSection.classList.add('hidden');
  scanProgressSection.classList.remove('hidden');

  // Start the scan via API
  await startScan(targets);
});

// API Integration Functions

async function startScan(targets) {
  try {
    // Use authenticated fetch from Auth module
    const data = await Auth.authenticatedFetch('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify({
        targets: targets,
        workers: ['nmap', 'nikto', 'nuclei']
      })
    });

    currentScanId = data.scan_id;
    
    console.log('Scan started:', data);
    
    // Start polling for status updates
    updateStatus();
  } catch (error) {
    console.error('Error starting scan:', error);
    alert('Failed to start scan: ' + error.message);
    // Reset UI
    scanProgressSection.classList.add('hidden');
    scanInputSection.classList.remove('hidden');
  }
}

async function updateStatus() {
  if (!currentScanId) return;

  try {
    // Use authenticated fetch from Auth module
    const data = await Auth.authenticatedFetch(`/api/scan/status/${currentScanId}`, {
      method: 'GET'
    });
    
    console.log('Scan status:', data);
    
    // Update progress UI
    renderProgress(data.progress);

    if (data.status === 'completed') {
      // Scan finished, fetch results
      if (pollInterval) {
        clearTimeout(pollInterval);
        pollInterval = null;
      }
      setTimeout(() => fetchResults(), 1000);
    } else if (data.status === 'failed') {
      // Scan failed
      if (pollInterval) {
        clearTimeout(pollInterval);
        pollInterval = null;
      }
      alert('Scan failed. Please try again.');
      scanProgressSection.classList.add('hidden');
      scanInputSection.classList.remove('hidden');
    } else {
      // Still running, poll again in 3 seconds
      pollInterval = setTimeout(updateStatus, 3000);
    }
  } catch (error) {
    console.error('Error fetching scan status:', error);
    if (pollInterval) {
      clearTimeout(pollInterval);
      pollInterval = null;
    }
  }
}

function renderProgress(progress) {
  const progressElements = document.querySelectorAll('.scanner-progress');
  const workers = ['nmap', 'nuclei', 'nikto'];
  
  // Handle new progress structure with workers object
  const workersData = progress.workers || {};
  const overallProgress = progress.overall || 0;
  
  workers.forEach((worker, index) => {
    if (index >= progressElements.length) return;
    
    const element = progressElements[index];
    const progressBar = element.querySelector('.progress-fill');
    const status = element.querySelector('.progress-status');
    const spinner = element.querySelector('.spinner');
    
    // Get worker status from new structure
    const workerData = workersData[worker] || {};
    const workerStatus = workerData.status || 'queued';
    const workerProgress = workerData.progress || 0;
    
    switch (workerStatus) {
      case 'queued':
        progressBar.style.width = '0%';
        status.textContent = 'Queued';
        spinner.style.display = 'block';
        progressBar.style.backgroundColor = '';
        break;
      case 'running':
        progressBar.style.width = `${workerProgress}%`;
        status.textContent = 'Scanning...';
        spinner.style.display = 'block';
        progressBar.style.backgroundColor = '';
        break;
      case 'done':
        progressBar.style.width = '100%';
        status.textContent = 'Completed';
        spinner.style.display = 'none';
        progressBar.style.backgroundColor = '#2ecc71';
        break;
      case 'failed':
      case 'error':
        progressBar.style.width = '100%';
        status.textContent = 'Failed';
        spinner.style.display = 'none';
        progressBar.style.backgroundColor = '#e74c3c';
        break;
      default:
        // Fallback for old progress format
        if (workerStatus === 'done') {
          progressBar.style.width = '100%';
          status.textContent = 'Completed';
          spinner.style.display = 'none';
          progressBar.style.backgroundColor = '#2ecc71';
        } else {
          progressBar.style.width = '50%';
          status.textContent = 'Scanning...';
          spinner.style.display = 'block';
        }
    }
  });
  
  // Log overall progress for debugging
  console.log(`Overall progress: ${overallProgress}%`);
}

async function fetchResults() {
  if (!currentScanId) return;

  try {
    // Use authenticated fetch from Auth module
    const data = await Auth.authenticatedFetch(`/api/scan/results/${currentScanId}`, {
      method: 'GET'
    });
    
    console.log('Scan results:', data);
    
    showResults(data);
  } catch (error) {
    console.error('Error fetching results:', error);
    alert('Failed to fetch results: ' + error.message);
  }
}

function showResults(scanData) {
  scanProgressSection.classList.add('hidden');
  scanResultsSection.classList.remove('hidden');

  // Display target information
  const targets = scanData.results.map(r => r.target).join(', ');
  document.getElementById('resultTarget').textContent = targets;

  // Get vulnerabilities and risk summary from enriched data
  const vulnerabilities = scanData.vulnerabilities || [];
  const riskSummary = scanData.risk_summary || {
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0
  };

  // Update counts with risk summary data and persist to localStorage
  document.getElementById('criticalCount').textContent = riskSummary.critical_count;
  document.getElementById('highCount').textContent = riskSummary.high_count;
  document.getElementById('mediumCount').textContent = riskSummary.medium_count;
  document.getElementById('lowCount').textContent = riskSummary.low_count;

  localStorage.setItem('criticalCount', riskSummary.critical_count);
  localStorage.setItem('highCount', riskSummary.high_count);
  localStorage.setItem('mediumCount', riskSummary.medium_count);
  localStorage.setItem('lowCount', riskSummary.low_count);

  // Update totalScans count and persist
  let totalScans = Number(localStorage.getItem('totalScans')) || 0;
  totalScans += 1;
  localStorage.setItem('totalScans', totalScans);

  // Render vulnerabilities list with enriched data
  const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
  if (vulnerabilities.length > 0) {
    vulnerabilitiesList.innerHTML = vulnerabilities.map(vuln => {
      const severityClass = vuln.severity ? vuln.severity.toLowerCase() : 'low';
      const severityBadge = vuln.severity ? vuln.severity.toUpperCase() : 'UNKNOWN';
      
      return `
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
          <p class="vuln-recommendation"><strong>Recommendation:</strong> ${vuln.recommendation || 'See NVD for details'}</p>
          <p class="vuln-timestamp"><small>Detected: ${vuln.timestamp || 'N/A'}</small></p>
        </div>
      `;
    }).join('');
    
    // Add CSV download button if vulnerabilities exist
    const downloadSection = document.createElement('div');
    downloadSection.className = 'csv-download-section';
    downloadSection.innerHTML = `
      <button id="downloadCsvBtn" class="btn-primary">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
          <polyline points="7 10 12 15 17 10"></polyline>
          <line x1="12" y1="15" x2="12" y2="3"></line>
        </svg>
        Download CSV Report
      </button>
    `;
    vulnerabilitiesList.insertAdjacentElement('afterend', downloadSection);
    
    // Add event listener for CSV download
    document.getElementById('downloadCsvBtn').addEventListener('click', () => {
      downloadCsv(scanData.scan_id);
    });
  } else {
    vulnerabilitiesList.innerHTML = `
      <div class="no-vulnerabilities">
        <p>No enriched vulnerabilities found in this scan.</p>
        <p>Scan outputs may still contain useful information - check the raw scan files.</p>
      </div>
    `;
  }
}

async function downloadCsv(scanId) {
  try {
    // Get the auth token from localStorage
    const authData = localStorage.getItem('trinetra_auth');
    if (!authData) {
      alert('Authentication required. Please login again.');
      return;
    }
    
    const { token } = JSON.parse(authData);
    
    // Use fetch with authentication header for file download
    const response = await fetch(`/api/export/csv/${scanId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Failed to download CSV');
    }
    
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

newScanBtn.addEventListener('click', () => {
  // Clear poll interval if running
  if (pollInterval) {
    clearTimeout(pollInterval);
    pollInterval = null;
  }
  
  currentScanId = null;
  
  scanResultsSection.classList.add('hidden');
  scanInputSection.classList.remove('hidden');
  scanForm.reset();

  const progressBars = document.querySelectorAll('.progress-fill');
  const statuses = document.querySelectorAll('.progress-status');
  const spinners = document.querySelectorAll('.spinner');

  progressBars.forEach(bar => {
    bar.style.width = '0%';
    bar.style.backgroundColor = ''; // Reset color
  });
  statuses.forEach(status => status.textContent = 'Initializing...');
  spinners.forEach(spinner => spinner.style.display = 'block');
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
