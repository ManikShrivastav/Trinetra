const menuToggle = document.getElementById('menuToggle');
const sidebar = document.getElementById('sidebar');
const loginBtn = document.getElementById('loginBtn');
const signupBtn = document.getElementById('signupBtn');
const authButtons = document.getElementById('authButtons');
const profileSection = document.getElementById('profileSection');
const profileBtn = document.getElementById('profileBtn');
const dropdownMenu = document.getElementById('dropdownMenu');
const logoutBtn = document.getElementById('logoutBtn');

const chatForm = document.getElementById('chatForm');
const chatInput = document.getElementById('chatInput');
const chatMessages = document.getElementById('chatMessages');
const quickActionButtons = document.querySelectorAll('.quick-action-btn');

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

chatForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const message = chatInput.value.trim();
  if (!message) return;

  addUserMessage(message);
  chatInput.value = '';

  setTimeout(() => {
    addBotResponse(message);
  }, 1000);
});

quickActionButtons.forEach(button => {
  button.addEventListener('click', () => {
    const question = button.dataset.question;
    addUserMessage(question);
    setTimeout(() => {
      addBotResponse(question);
    }, 1000);
  });
});

function addUserMessage(message) {
  const messageDiv = document.createElement('div');
  messageDiv.className = 'message user-message';
  messageDiv.innerHTML = `
    <div class="message-avatar">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
        <circle cx="12" cy="7" r="4"></circle>
      </svg>
    </div>
    <div class="message-content">
      <p><strong>You</strong></p>
      <p>${message}</p>
    </div>
  `;
  chatMessages.appendChild(messageDiv);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function addBotResponse(userMessage) {
  const responses = {
    'apache': 'To fix Apache vulnerabilities, you should: 1) Update to the latest stable version, 2) Disable unnecessary modules, 3) Configure proper security headers, 4) Review and harden configuration files, 5) Implement regular security updates.',
    'ssl': 'Best practices for SSL/TLS configuration include: 1) Use TLS 1.2 or higher only, 2) Disable weak cipher suites, 3) Enable HSTS, 4) Use strong key lengths (2048-bit minimum), 5) Keep certificates up to date, 6) Implement certificate pinning where appropriate.',
    'patch': 'To effectively patch services: 1) Maintain an inventory of all services and versions, 2) Subscribe to security advisories, 3) Test patches in staging before production, 4) Implement a regular patching schedule, 5) Prioritize critical vulnerabilities, 6) Use automated patch management tools.',
    'cve': 'CVE severity levels are: CRITICAL (9.0-10.0) - Immediate action required, causes significant impact. HIGH (7.0-8.9) - Important to address quickly, serious security risk. MEDIUM (4.0-6.9) - Should be patched in normal cycle. LOW (0.1-3.9) - Minor issues, address as resources permit.',
    'default': 'Based on your scan results, I recommend: 1) Prioritize critical vulnerabilities first, 2) Update outdated software and services, 3) Configure proper firewall rules, 4) Implement security headers on web servers, 5) Review and strengthen authentication mechanisms, 6) Set up regular security scanning. Would you like specific guidance on any of these areas?'
  };

  let response = responses.default;
  const lowerMessage = userMessage.toLowerCase();

  for (const [key, value] of Object.entries(responses)) {
    if (lowerMessage.includes(key)) {
      response = value;
      break;
    }
  }

  const messageDiv = document.createElement('div');
  messageDiv.className = 'message bot-message';
  messageDiv.innerHTML = `
    <div class="message-avatar">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
    </div>
    <div class="message-content">
      <p><strong>Security Bot</strong></p>
      <p>${response}</p>
    </div>
  `;
  chatMessages.appendChild(messageDiv);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}


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
