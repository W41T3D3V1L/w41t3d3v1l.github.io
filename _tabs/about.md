---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

### Hey, I'm c3l1kd.

<div id="matrix" style="background: black; color: lime; font-family: monospace; height: 300px; overflow: hidden;"></div>

<script>
const canvas = document.createElement('canvas');
document.getElementById('matrix').appendChild(canvas);

const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = 300; // Adjust height of the matrix effect area

const columns = canvas.width / 15; // Width of each column
const letters = Array.from("celikd".repeat(columns)); // Letters to "rain"
const drops = Array(columns).fill(1);

function drawMatrix() {
  ctx.fillStyle = 'rgba(0, 0, 0, 0.05)'; // Fades the trails
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = '#0F0'; // Lime green text
  ctx.font = '15px monospace';

  for (let i = 0; i < drops.length; i++) {
    const text = letters[Math.floor(Math.random() * letters.length)];
    ctx.fillText(text, i * 15, drops[i] * 15);

    if (drops[i] * 15 > canvas.height && Math.random() > 0.95) {
      drops[i] = 0; // Reset drop to top
    }
    drops[i]++;
  }
  requestAnimationFrame(drawMatrix);
}

drawMatrix();
</script>
