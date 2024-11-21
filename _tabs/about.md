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
canvas.height = window.innerHeight;

const letters = Array(256).fill('1');
const fontSize = 14;

function drawMatrix() {
  ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  ctx.fillStyle = '#0F0';
  ctx.font = `${fontSize}px monospace`;

  letters.forEach((letter, index) => {
    const x = index * fontSize;
    const y = (Math.random() * canvas.height) / fontSize;

    ctx.fillText(letter, x, y * fontSize);

    if (y * fontSize > canvas.height && Math.random() > 0.975) {
      letters[index] = 0;
    }
  });

  requestAnimationFrame(drawMatrix);
}
drawMatrix();
</script>
