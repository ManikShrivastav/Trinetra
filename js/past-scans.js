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
    const response = await fetch('/api/scans/history');
    if (!response.ok) {
      throw new Error('Failed to load scan history');
    }
    
    allScans = await response.json();
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
    
    return `
      <div class="scan-card" data-scan-id="${scan.scan_id}">
        <div class="scan-info">
          <h3>${scan.target}</h3>
          <p class="scan-date">${new Date(scan.timestamp).toLocaleString()}</p>
          <p>Targets: ${scan.total_targets}</p>
        </div>
        <div class="scan-actions">
          <span class="scan-badge ${severityClass}">${severityText}</span>
          <button class="view-details" data-scan-id="${scan.scan_id}">View Details</button>
        </div>
      </div>
    `;
  }).join('');
  
  // Re-attach event listeners
  attachViewDetailsListeners();
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
    const response = await fetch(`/api/scan/results/${scanId}`);
    if (!response.ok) {
      throw new Error('Failed to load scan details');
    }
    
    const scanDetails = await response.json();
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
  
  // Display detailed results
  const detailsContainer = document.querySelector('#detailsModal .vulnerability-item') || 
                          document.querySelector('#detailsModal .modal-body');
  
  if (detailsContainer) {
    let detailsHTML = '<div class="scan-details">';
    
    scanDetails.results.forEach(targetResult => {
      detailsHTML += `<h4>Target: ${targetResult.target}</h4>`;
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
    
    // Try to find the right container
    const modalBody = document.querySelector('#detailsModal .modal-body');
    if (modalBody) {
      // Clear existing content and add new
      const existingDetails = modalBody.querySelector('.scan-details');
      if (existingDetails) {
        existingDetails.remove();
      }
      modalBody.insertAdjacentHTML('beforeend', detailsHTML);
    }
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
