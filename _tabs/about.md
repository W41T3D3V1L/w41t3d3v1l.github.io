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


<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Interactive Puzzle Game</title>
  <style>
    code {
      font-family: 'Courier New', Courier, monospace;
      padding: 0.2em 0.4em;
      border-radius: 4px;
      color: #d14;
    }

    #puzzle-container {
      text-align: center;
      margin-top: 50px;
    }

    #bio-container {
      display: none;
      text-align: center;
      margin-top: 50px;
    }

    input[type="number"] {
      padding: 10px;
      font-size: 16px;
      border-radius: 4px;
      border: 1px solid #ccc;
    }

    button {
      padding: 10px 20px;
      font-size: 16px;
      margin-top: 20px;
      border: none;
      background-color: #28a745;
      color: white;
      border-radius: 4px;
    }

    button:hover {
      background-color: #218838;
    }

    .message {
      font-size: 18px;
      margin-top: 20px;
    }
  </style>
</head>
<body>
  <div id="puzzle-container">
    <h1>Welcome to the Puzzle Game!</h1>
    <p>Guess the secret number to unlock the bio.</p>
    <input type="number" id="guess" placeholder="Enter a number between 1 and 10">
    <button onclick="checkGuess()">Submit Guess</button>
    <p class="message" id="message"></p>
  </div>

  <div id="bio-container">
    <p>
      My name is celikd, and I am a <code>full-stack web developer</code> and a passionate <code>pentester</code>. 
      <code>Hacking is my true passion</code>, and through this site, you'll find all my <code>TryHackMe (THM)</code> 
      and <code>Hack The Box (HTB) write-ups</code>. I combine my skills in <code>web development</code> with 
      <code>security expertise</code> to explore and solve challenges in the world of <code>cybersecurity</code>.
    </p>
  </div>

  <script>
    // Secret number to unlock the bio
    const secretNumber = 7;

    function checkGuess() {
      const userGuess = document.getElementById("guess").value;
      const messageElement = document.getElementById("message");

      if (userGuess == secretNumber) {
        messageElement.textContent = "Congratulations! You've guessed the right number. Here is the bio!";
        document.getElementById("bio-container").style.display = "block";
        document.getElementById("puzzle-container").style.display = "none";
      } else {
        messageElement.textContent = "Wrong guess! Try again.";
      }
    }
  </script>
</body>
</html>

