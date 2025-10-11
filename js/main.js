const menuToggle = document.getElementById('menuToggle');
const sidebar = document.getElementById('sidebar');
const loginBtn = document.getElementById('loginBtn');
const signupBtn = document.getElementById('signupBtn');
const authModal = document.getElementById('authModal');
const modalClose = document.getElementById('modalClose');
const authForm = document.getElementById('authForm');
const modalTitle = document.getElementById('modalTitle');
const switchMode = document.getElementById('switchMode');
const switchText = document.getElementById('switchText');
const authButtons = document.getElementById('authButtons');
const profileSection = document.getElementById('profileSection');
const profileBtn = document.getElementById('profileBtn');
const dropdownMenu = document.getElementById('dropdownMenu');
const logoutBtn = document.getElementById('logoutBtn');

let isLoginMode = true;

if (menuToggle && sidebar) {
  menuToggle.addEventListener('click', () => {
    sidebar.classList.toggle('open');
  });
}

if (loginBtn && authModal && modalTitle && switchText && switchMode) {
  loginBtn.addEventListener('click', () => {
    isLoginMode = true;
    modalTitle.textContent = 'Login';
    switchText.textContent = "Don't have an account?";
    switchMode.textContent = 'Sign up';
    authModal.classList.remove('hidden');
  });
}

if (signupBtn && authModal && modalTitle && switchText && switchMode) {
  signupBtn.addEventListener('click', () => {
    isLoginMode = false;
    modalTitle.textContent = 'Sign Up';
    switchText.textContent = 'Already have an account?';
    switchMode.textContent = 'Login';
    authModal.classList.remove('hidden');
  });
}

if (modalClose && authModal) {
  modalClose.addEventListener('click', () => {
    authModal.classList.add('hidden');
  });
}

if (authModal) {
  authModal.addEventListener('click', (e) => {
    if (e.target === authModal) {
      authModal.classList.add('hidden');
    }
  });
}

if (switchMode && modalTitle && switchText) {
  switchMode.addEventListener('click', (e) => {
    e.preventDefault();
    isLoginMode = !isLoginMode;
    if (isLoginMode) {
      modalTitle.textContent = 'Login';
      switchText.textContent = "Don't have an account?";
      switchMode.textContent = 'Sign up';
    } else {
      modalTitle.textContent = 'Sign Up';
      switchText.textContent = 'Already have an account?';
      switchMode.textContent = 'Login';
    }
  });
}

if (authForm) {
  authForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const emailEl = document.getElementById('email');
    const email = emailEl ? emailEl.value : '';

    localStorage.setItem('isLoggedIn', 'true');
    localStorage.setItem('userEmail', email);

    if (authModal) authModal.classList.add('hidden');
    showProfile(email);
    authForm.reset();
  });
}

if (profileBtn && dropdownMenu) {
  profileBtn.addEventListener('click', () => {
    dropdownMenu.classList.toggle('hidden');
  });

  document.addEventListener('click', (e) => {
    if (!profileBtn.contains(e.target)) {
      dropdownMenu.classList.add('hidden');
    }
  });
}

if (logoutBtn) {
  logoutBtn.addEventListener('click', () => {
    // Use Auth module logout for proper JWT cleanup
    Auth.logout(false);
  });
}

function showProfile(email) {
  const usernameEl = document.getElementById('username');
  if (usernameEl) usernameEl.textContent = email ? email.split('@')[0] : 'User';
  if (authButtons) authButtons.classList.add('hidden');
  if (profileSection) profileSection.classList.remove('hidden');
}

if (localStorage.getItem('isLoggedIn') === 'true') {
  const email = localStorage.getItem('userEmail');
  showProfile(email);
}

const canvas = document.getElementById('vulnerabilityChart');
if (canvas) {
  const ctx = canvas.getContext('2d');
  const width = canvas.width = canvas.offsetWidth;
  const height = canvas.height = 300;

  const data = [43, 52, 38, 45, 48, 51, 43];
  const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const max = Math.max(...data);
  const padding = 40;
  const graphWidth = width - padding * 2;
  const graphHeight = height - padding * 2;

  ctx.strokeStyle = '#3b82f6';
  ctx.fillStyle = 'rgba(59, 130, 246, 0.1)';
  ctx.lineWidth = 3;

  ctx.beginPath();
  data.forEach((value, index) => {
    const x = padding + (graphWidth / (data.length - 1)) * index;
    const y = height - padding - (value / max) * graphHeight;

    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });
  ctx.stroke();

  ctx.lineTo(width - padding, height - padding);
  ctx.lineTo(padding, height - padding);
  ctx.closePath();
  ctx.fill();

  ctx.fillStyle = '#9ca3af';
  ctx.font = '12px Inter';
  ctx.textAlign = 'center';
  labels.forEach((label, index) => {
    const x = padding + (graphWidth / (data.length - 1)) * index;
    ctx.fillText(label, x, height - 10);
  });
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
