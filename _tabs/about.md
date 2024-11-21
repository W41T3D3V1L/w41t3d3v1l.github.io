---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

### Hey, I'm c3l1kd.


<!-- ---
# thm badge
--- -->
<head>
  <link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"
    crossorigin="anonymous"
  />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link
    href="https://fonts.googleapis.com/css2?family=Ubuntu:ital,wght@0,400;0,500;1,400;1,500&display=swap"
    rel="stylesheet"
  />
</head>
<div id="thm-badge" role="button" tabindex="0" aria-label="user avatar">
  <div class="thm-avatar-outer">
    <div class="thm-avatar"></div>
  </div>
  <div class="thm-badge-user-details">
    <div class="thm-title-wrapper">
      <span class="thm-user_name">0XC3L1KD</span>
      <div>
        <i class="fa-solid fa-bolt-lightning thm-rank-icon"></i>
        <span class="thm-rank-title">[0xD]</span>
      </div>
    </div>
    <div class="thm-details-wrapper">
      <div class="thm-details-icon-wrapper">
        <i class="fa-solid fa-trophy thm-detail-icons thm-trophy-icon"></i>
        <span class="thm-details-text">31</span>
      </div>
      <div class="thm-details-icon-wrapper">
        <i class="fa-solid fa-fire thm-detail-icons thm-fire-icon"></i>
        <span class="thm-details-text">0 days</span>
      </div>
      <div class="thm-details-icon-wrapper">
        <i class="fa-solid fa-award thm-detail-icons thm-award-icon"></i>
        <span class="thm-details-text">62</span>
      </div>
      <div class="thm-details-icon-wrapper">
        <i class="fa-solid fa-door-closed thm-detail-icons thm-door-closed-icon"></i>
        <span class="thm-details-text">888</span>
      </div>
    </div>
    <a href="https://tryhackme.com" class="thm-link" target="_blank">tryhackme.com</a>
  </div>
</div>
<style>


  #thm-badge {
    width: 327px;
    height: 84px;
    background-image: url('https://tryhackme.com/img/thm_public_badge_bg.svg');
    background-size: cover;
    object-fit: fill;
    display: flex;
    align-items: center;
    gap: 12px;
    user-select: none;
    cursor: pointer;
    border-radius: 12px;
  }

  .thm-avatar-outer {
    width: 60px;
    height: 60px;
    border-radius: 50%;
    margin-right: 0;
    background: linear-gradient(to bottom left, #a3ea2a, #2e4463);
    padding: 2px;
    margin-left: 10px;
  }

  .thm-avatar {
    background-image: url(https://tryhackme-images.s3.amazonaws.com/user-avatars/60bb05295d950f005033b618-1725566628891);
    display: block;
    width: 60px;
    height: 60px;
    float: left;
    background-size: cover;
    background-repeat: no-repeat;
    background-position: center center;
    border-radius: 50%;
    box-sizing: content-box; /* Needed for border to stop changing image width*/
    background-color: #121212;
    object-fit: cover;
    box-shadow: 0 0 3px 0 #303030;
  }

  .thm-badge-user-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .thm-details-icon-wrapper {
    display: flex;
    gap: 5px;
  }

  .thm-details-wrapper {
    display: flex;
    gap: 8px;
  }

  .thm-title-wrapper {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .thm-user_name {
    font-family: 'Ubuntu', sans-serif;
    font-style: normal;
    font-weight: 500;
    font-size: 14px;
    line-height: 16px;

    color: #f9f9fb;
    transform: rotate(0.2deg);

    max-width: 135px;
    text-overflow: ellipsis;
    display: block;
    white-space: nowrap;
    overflow: hidden;
  }

  .thm-rank-icon {
    width: 8px;
    height: 10px;
    font-style: normal;
    font-weight: 900;
    font-size: 10px;
    line-height: 10px;
    text-align: center;

    color: #ffbb45;
    transform: rotate(0.2deg);
  }

  .thm-rank-title {
    font-family: Ubuntu, sans-serif;
    font-style: normal;
    font-weight: 500;
    font-size: 12px;
    line-height: 14px;

    color: #ffffff;
    transform: rotate(0.2deg);
  }

  .thm-detail-icons {
    font-weight: 900;
    text-align: center;

    transform: rotate(0.2deg);
  }

  .thm-trophy-icon {
    color: #9ca4b4;
    width: 13px;
    height: 13px;
    font-style: normal;
    font-size: 11px;
    line-height: 11px;
  }

  .thm-fire-icon {
    width: 12px;
    height: 13px;
    font-style: normal;
    font-size: 13px;
    line-height: 13px;
    color: #a3ea2a;
  }

  .thm-award-icon {
    width: 10px;
    height: 13px;
    font-style: normal;
    font-size: 13px;
    line-height: 13px;
    color: #d752ff;
  }

  .thm-door-closed-icon {
    width: 14px;
    height: 12px;
    font-style: normal;
    font-size: 12px;
    line-height: 12px;
    color: #719cf9;
  }

  .thm-details-text {
    font-family: Ubuntu, sans-serif;
    font-style: normal;
    font-weight: 400;
    font-size: 11px;
    line-height: 13px;
    color: #ffffff;
    transform: rotate(0.2deg);
  }

  .thm-link {
    text-decoration: none;
    font-family: Ubuntu, sans-serif;
    font-style: normal;
    font-weight: 400;
    font-size: 11px;
    line-height: 13px;
    margin: 0;

    color: #f9f9fb;
    transform: rotate(0.2deg);
  }

  .thm-link:hover {
    text-decoration: underline;
  }
</style>
<script>
  document.getElementById('thm-badge').addEventListener('click', function ({ target }) {
    if (target.tagName === 'A') {
      // If it's an anchor, do nothing here and let the default action proceed
      return;
    }
    window.open('https://tryhackme.com/p/0XC3L1KD', '_blank');
  });
</script>


<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Maze Game</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }

    .maze-game-container {
      text-align: center;
    }

    .maze {
      display: grid;
      grid-template-columns: repeat(4, 50px);
      grid-template-rows: repeat(3, 50px);
      gap: 5px;
      margin-bottom: 20px;
    }

    .maze-cell {
      width: 50px;
      height: 50px;
      border: 1px solid #333;
      display: flex;
      justify-content: center;
      align-items: center;
    }

    .maze-start {
      background-color: green;
    }

    .maze-end {
      background-color: red;
    }

    .maze-wall {
      background-color: #555;
    }

    .maze-empty {
      background-color: #fff;
    }

    .maze-controls {
      display: flex;
      gap: 10px;
      justify-content: center;
    }

    .maze-move-btn {
      padding: 10px;
      background-color: #28a745;
      color: white;
      border: none;
      cursor: pointer;
    }

    .maze-move-btn:hover {
      background-color: #218838;
    }
  </style>
</head>
<body>
  <div class="maze-game-container">
    <div class="maze">
      <div class="maze-cell maze-start"></div>
      <div class="maze-cell maze-wall"></div>
      <div class="maze-cell maze-wall"></div>
      <div class="maze-cell maze-wall"></div>
      <div class="maze-cell maze-empty"></div>
      <div class="maze-cell maze-wall"></div>
      <div class="maze-cell maze-wall"></div>
      <div class="maze-cell maze-wall"></div>
      <div class="maze-cell maze-empty"></div>
      <div class="maze-cell maze-wall"></div>
      <div class="maze-cell maze-end"></div>
    </div>
    <div class="maze-controls">
      <button class="maze-move-btn" id="up">Up</button>
      <button class="maze-move-btn" id="down">Down</button>
      <button class="maze-move-btn" id="left">Left</button>
      <button class="maze-move-btn" id="right">Right</button>
    </div>
  </div>

  <script>
    const maze = [
      ['start', 'wall', 'wall', 'wall'],
      ['empty', 'wall', 'empty', 'empty'],
      ['empty', 'wall', 'wall', 'end']
    ];

    let playerPosition = { x: 0, y: 0 };

    function renderMaze() {
      const mazeContainer = document.querySelector('.maze');
      mazeContainer.innerHTML = '';

      maze.forEach((row, y) => {
        row.forEach((cell, x) => {
          const mazeCell = document.createElement('div');
          mazeCell.classList.add('maze-cell');
          if (cell === 'start') mazeCell.classList.add('maze-start');
          if (cell === 'wall') mazeCell.classList.add('maze-wall');
          if (cell === 'empty') mazeCell.classList.add('maze-empty');
          if (cell === 'end') mazeCell.classList.add('maze-end');

          if (playerPosition.x === x && playerPosition.y === y) {
            mazeCell.style.backgroundColor = 'blue'; // Player's position
          }

          mazeContainer.appendChild(mazeCell);
        });
      });
    }

    function movePlayer(direction) {
      const { x, y } = playerPosition;
      
      if (direction === 'up' && y > 0 && maze[y - 1][x] !== 'wall') {
        playerPosition.y--;
      } else if (direction === 'down' && y < 2 && maze[y + 1][x] !== 'wall') {
        playerPosition.y++;
      } else if (direction === 'left' && x > 0 && maze[y][x - 1] !== 'wall') {
        playerPosition.x--;
      } else if (direction === 'right' && x < 3 && maze[y][x + 1] !== 'wall') {
        playerPosition.x++;
      }

      renderMaze();
      checkEndCondition();
    }

    function checkEndCondition() {
      if (maze[playerPosition.y][playerPosition.x] === 'end') {
        alert('You won the game!');
      }
    }

    document.getElementById('up').addEventListener('click', () => movePlayer('up'));
    document.getElementById('down').addEventListener('click', () => movePlayer('down'));
    document.getElementById('left').addEventListener('click', () => movePlayer('left'));
    document.getElementById('right').addEventListener('click', () => movePlayer('right'));

    renderMaze();
  </script>
</body>
</html>
