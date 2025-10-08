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

menuToggle.addEventListener('click', () => {
  sidebar.classList.toggle('open');
});

loginBtn.addEventListener('click', () => {
  isLoginMode = true;
  modalTitle.textContent = 'Login';
  switchText.textContent = "Don't have an account?";
  switchMode.textContent = 'Sign up';
  authModal.classList.remove('hidden');
});

signupBtn.addEventListener('click', () => {
  isLoginMode = false;
  modalTitle.textContent = 'Sign Up';
  switchText.textContent = 'Already have an account?';
  switchMode.textContent = 'Login';
  authModal.classList.remove('hidden');
});

modalClose.addEventListener('click', () => {
  authModal.classList.add('hidden');
});

authModal.addEventListener('click', (e) => {
  if (e.target === authModal) {
    authModal.classList.add('hidden');
  }
});

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

authForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;

  localStorage.setItem('isLoggedIn', 'true');
  localStorage.setItem('userEmail', email);

  authModal.classList.add('hidden');
  showProfile(email);
  authForm.reset();
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
  authButtons.classList.remove('hidden');
  profileSection.classList.add('hidden');
  dropdownMenu.classList.add('hidden');
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
