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
  const scanCards = document.querySelectorAll('.scan-card');

  scanCards.forEach(card => {
    const target = card.querySelector('.scan-info h3').textContent.toLowerCase();
    const badge = card.querySelector('.scan-badge').textContent.toLowerCase();

    const matchesSearch = target.includes(searchTerm);
    const matchesSeverity = severity === 'all' || badge.includes(severity);

    if (matchesSearch && matchesSeverity) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
}

const viewDetailsButtons = document.querySelectorAll('.view-details');
viewDetailsButtons.forEach(button => {
  button.addEventListener('click', (e) => {
    const scanId = e.target.dataset.scanId;
    const card = document.querySelector(`[data-scan-id="${scanId}"]`);
    const target = card.querySelector('.scan-info h3').textContent;
    const date = card.querySelector('.scan-date').textContent;

    document.getElementById('modalTarget').textContent = target;
    document.getElementById('modalDate').textContent = date;

    detailsModal.classList.remove('hidden');
  });
});

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
