import './bootstrap';
// import './components/captcha.js';

// Optional: keep your matrix effect here
document.addEventListener("DOMContentLoaded", () => {
    const canvas = document.getElementById("matrix");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    canvas.height = window.innerHeight;
    canvas.width = window.innerWidth;
    const chars = "1010101010101010";
    const fontSize = 16;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);
    function draw() {
        ctx.fillStyle = "rgba(0,0,0,0.05)";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = "#3b82f6";
        ctx.font = fontSize + "px monospace";
        for (let i = 0; i < drops.length; i++) {
            const text = chars.charAt(Math.floor(Math.random() * chars.length));
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975)
                drops[i] = 0;
            drops[i]++;
        }
    }
    setInterval(draw, 35);
});


// theme-toggle.js

// const themeButton = document.getElementById('themeToggle');

// function applyTheme(theme) {
//     document.documentElement.classList.toggle('dark', theme === 'dark');
//     localStorage.setItem('theme', theme);
// }

// // Load saved theme
// (function () {
//     const saved = localStorage.getItem('theme') || 'dark';
//     applyTheme(saved);
// })();

// themeButton.addEventListener('click', () => {
//     const current = document.documentElement.classList.contains('dark') ? 'dark' : 'light';
//     applyTheme(current === 'dark' ? 'light' : 'dark');
// });
