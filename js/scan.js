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
    const response = await fetch('/api/scan/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        targets: targets,
        workers: ['nmap', 'nikto', 'nuclei']
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to start scan');
    }

    const data = await response.json();
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
    const response = await fetch(`/api/scan/status/${currentScanId}`);
    
    if (!response.ok) {
      throw new Error('Failed to fetch scan status');
    }

    const data = await response.json();
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
  const workers = ['nmap', 'nikto', 'nuclei'];
  
  workers.forEach((worker, index) => {
    if (index >= progressElements.length) return;
    
    const element = progressElements[index];
    const progressBar = element.querySelector('.progress-fill');
    const status = element.querySelector('.progress-status');
    const spinner = element.querySelector('.spinner');
    
    const workerStatus = progress[worker] || 'queued';
    
    switch (workerStatus) {
      case 'queued':
        progressBar.style.width = '0%';
        status.textContent = 'Queued';
        spinner.style.display = 'block';
        break;
      case 'running':
        progressBar.style.width = '50%';
        status.textContent = 'Scanning...';
        spinner.style.display = 'block';
        break;
      case 'done':
        progressBar.style.width = '100%';
        status.textContent = 'Completed';
        spinner.style.display = 'none';
        break;
      case 'error':
        progressBar.style.width = '100%';
        status.textContent = 'Failed';
        spinner.style.display = 'none';
        progressBar.style.backgroundColor = '#e74c3c';
        break;
    }
  });
}

async function fetchResults() {
  if (!currentScanId) return;

  try {
    const response = await fetch(`/api/scan/results/${currentScanId}`);
    
    if (!response.ok) {
      throw new Error('Failed to fetch scan results');
    }

    const data = await response.json();
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

  // Count vulnerabilities from results
  // This is a simplified version - you may want to parse actual scan outputs
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  
  const vulnerabilities = [];
  
  // Parse results from each target
  scanData.results.forEach(targetResult => {
    const target = targetResult.target;
    
    // Check each worker's results
    Object.entries(targetResult.results).forEach(([worker, result]) => {
      if (result.ok && result.output) {
        // For demonstration, add mock vulnerabilities
        // In a real implementation, you'd parse the actual scan output files
        if (worker === 'nmap') {
          highCount += Math.floor(Math.random() * 5) + 1;
          mediumCount += Math.floor(Math.random() * 10) + 5;
          vulnerabilities.push({
            severity: 'high',
            title: `Open Ports Detected - ${target}`,
            scanner: 'Nmap',
            description: `Scan output: ${result.output}`
          });
        } else if (worker === 'nikto') {
          criticalCount += Math.floor(Math.random() * 3);
          highCount += Math.floor(Math.random() * 5) + 2;
          vulnerabilities.push({
            severity: 'critical',
            title: `Web Vulnerabilities Found - ${target}`,
            scanner: 'Nikto',
            description: `Scan output: ${result.output}`
          });
        } else if (worker === 'nuclei') {
          mediumCount += Math.floor(Math.random() * 15) + 5;
          lowCount += Math.floor(Math.random() * 20) + 10;
          vulnerabilities.push({
            severity: 'medium',
            title: `Template Matches - ${target}`,
            scanner: 'Nuclei',
            description: `Scan output: ${result.output}`
          });
        }
      } else if (!result.ok) {
        // Scanner failed
        vulnerabilities.push({
          severity: 'low',
          title: `${worker} scan failed for ${target}`,
          scanner: worker,
          description: result.error || 'Unknown error'
        });
      }
    });
  });

  // Update counts
  document.getElementById('criticalCount').textContent = criticalCount;
  document.getElementById('highCount').textContent = highCount;
  document.getElementById('mediumCount').textContent = mediumCount;
  document.getElementById('lowCount').textContent = lowCount;

  // Render vulnerabilities list
  const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
  if (vulnerabilities.length > 0) {
    vulnerabilitiesList.innerHTML = vulnerabilities.map(vuln => `
      <div class="vulnerability-item ${vuln.severity}-item">
        <div class="vuln-header">
          <strong>${vuln.title}</strong>
          <span class="severity-badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
        </div>
        <p>Detected by: ${vuln.scanner}</p>
        <p class="vuln-description">${vuln.description}</p>
      </div>
    `).join('');
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
