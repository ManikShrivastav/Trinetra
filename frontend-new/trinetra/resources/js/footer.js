// footer.js
const footer = document.createElement('footer');
footer.innerHTML = `© ${new Date().getFullYear()} <strong>Team Code Nexus</strong> — All Rights Reserved.`;
footer.style.cssText = `
  position: fixed;
  bottom: 0;
  left: 0;
  width: 100%;
  text-align: center;
  padding: 12px 0;
  background: rgba(10, 25, 47, 0.9);
  color: #00ffff;
  font-family: 'Poppins', sans-serif;
  font-size: 14px;
  letter-spacing: 0.5px;
  border-top: 1px solid rgba(0, 255, 255, 0.3);
  backdrop-filter: blur(6px);
  z-index: 50;
`;

// Append it to body
document.body.appendChild(footer);
