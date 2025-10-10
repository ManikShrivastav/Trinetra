
  let captchaCode = "";

  function generateCaptcha() {
    const canvas = document.getElementById("captchaCanvas");
    const ctx = canvas.getContext("2d");
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // Generate 6-character code
    captchaCode = "";
    for (let i = 0; i < 6; i++) {
      captchaCode += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    // Reset canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // ✅ Make background lighter for better contrast
    const bgGradient = ctx.createLinearGradient(0, 0, 0, 40);
    bgGradient.addColorStop(0, "#0d1b2a");
    bgGradient.addColorStop(1, "#1b263b");
    ctx.fillStyle = bgGradient;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // ✅ Draw the CAPTCHA text (visible neon cyan)
    ctx.font = "bold 24px 'Consolas', monospace";
    ctx.textBaseline = "middle";
    ctx.textAlign = "center";

    for (let i = 0; i < captchaCode.length; i++) {
      const char = captchaCode[i];
      const x = 15 + i * 18;
      const y = 20 + Math.random() * 4;
      const rotation = (Math.random() - 0.5) * 0.3;

      ctx.save();
      ctx.translate(x, y);
      ctx.rotate(rotation);
      ctx.fillStyle = `hsl(${180 + Math.random() * 60}, 100%, 65%)`; // random cyan-blue
      ctx.shadowColor = "#00ffff";
      ctx.shadowBlur = 4;
      ctx.fillText(char, 0, 0);
      ctx.restore();
    }

    // ✅ Add better cross noise lines (clear but visible)
    for (let i = 0; i < 5; i++) {
      ctx.strokeStyle = `rgba(0,255,255,${0.4 + Math.random() * 0.3})`;
      ctx.beginPath();
      ctx.moveTo(Math.random() * 120, Math.random() * 40);
      ctx.lineTo(Math.random() * 120, Math.random() * 40);
      ctx.stroke();
    }

    // ✅ Add visible diagonal crosses
    for (let i = 0; i < 4; i++) {
      ctx.strokeStyle = "rgba(0,255,255,0.35)";
      const x = Math.random() * 120;
      const y = Math.random() * 40;
      ctx.beginPath();
      ctx.moveTo(x - 6, y - 6);
      ctx.lineTo(x + 6, y + 6);
      ctx.moveTo(x + 6, y - 6);
      ctx.lineTo(x - 6, y + 6);
      ctx.stroke();
    }
  }

  // Refresh and load events
  document.getElementById("refreshCaptcha").addEventListener("click", generateCaptcha);
  window.addEventListener("load", generateCaptcha);
