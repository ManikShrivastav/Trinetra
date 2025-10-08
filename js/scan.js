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

scanForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const targetIp = document.getElementById('targetIp').value;

  document.getElementById('scanTarget').textContent = targetIp;

  scanInputSection.classList.add('hidden');
  scanProgressSection.classList.remove('hidden');

  const scanners = ['Nmap', 'OpenVAS', 'Nessus', 'Qualys', 'Nikto'];
  const progressElements = document.querySelectorAll('.scanner-progress');

  scanners.forEach((scanner, index) => {
    const element = progressElements[index];
    const progressBar = element.querySelector('.progress-fill');
    const status = element.querySelector('.progress-status');

    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 15;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        status.textContent = 'Completed';
        element.querySelector('.spinner').style.display = 'none';

        if (Array.from(progressElements).every(el =>
          el.querySelector('.progress-status').textContent === 'Completed'
        )) {
          setTimeout(() => {
            showResults(targetIp);
          }, 1000);
        }
      } else {
        status.textContent = 'Scanning...';
      }
      progressBar.style.width = progress + '%';
    }, 500 + Math.random() * 1000);
  });
});

function showResults(targetIp) {
  scanProgressSection.classList.add('hidden');
  scanResultsSection.classList.remove('hidden');

  document.getElementById('resultTarget').textContent = targetIp;

  const criticalCount = Math.floor(Math.random() * 15);
  const highCount = Math.floor(Math.random() * 20) + 5;
  const mediumCount = Math.floor(Math.random() * 30) + 10;
  const lowCount = Math.floor(Math.random() * 25) + 5;

  document.getElementById('criticalCount').textContent = criticalCount;
  document.getElementById('highCount').textContent = highCount;
  document.getElementById('mediumCount').textContent = mediumCount;
  document.getElementById('lowCount').textContent = lowCount;

  const vulnerabilities = [
    {
      severity: 'critical',
      title: 'CVE-2024-1234: Remote Code Execution',
      scanner: 'Nessus, OpenVAS',
      description: 'Critical vulnerability allowing remote code execution on unpatched Apache server.'
    },
    {
      severity: 'high',
      title: 'Weak SSL/TLS Configuration',
      scanner: 'Nmap, Qualys',
      description: 'Server supports outdated SSL protocols and weak cipher suites.'
    },
    {
      severity: 'medium',
      title: 'Missing Security Headers',
      scanner: 'Nikto',
      description: 'Web server missing important security headers like X-Frame-Options.'
    }
  ];

  const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
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

newScanBtn.addEventListener('click', () => {
  scanResultsSection.classList.add('hidden');
  scanInputSection.classList.remove('hidden');
  scanForm.reset();

  const progressBars = document.querySelectorAll('.progress-fill');
  const statuses = document.querySelectorAll('.progress-status');
  const spinners = document.querySelectorAll('.spinner');

  progressBars.forEach(bar => bar.style.width = '0%');
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
