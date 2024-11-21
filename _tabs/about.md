---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

### Hey, I'm c3l1kd.
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Guess the Secret Number</title>
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
  <style>
    .highlight {
      background-color: #ffeb3b;
      padding: 0 5px;
      color: red;
      border-radius: 3px;
    }

    input[type="number"] {
      padding: 12px;
      font-size: 18px;
      border-radius: 8px;
      border: 2px solid #007bff;
      width: 300px;
      max-width: 90%;
      margin-top: 20px;
    }

    button {
      padding: 12px 20px;
      font-size: 18px;
      border-radius: 8px;
      background: linear-gradient(45deg, #ff6a00, #ee0979);
      color: white;
      border: none;
      cursor: pointer;
      transition: background 0.3s ease, transform 0.3s ease;
      margin-top: 10px;
    }

    button:hover {
      background: linear-gradient(45deg, #ee0979, #ff6a00);
      transform: scale(1.05);
    }

    button:active {
      transform: scale(1);
    }

    .message {
      font-size: 18px;
      margin-top: 10px;
      font-weight: bold;
    }
  </style>
</head>
<body>
  <div id="puzzle-container">
    <p>Guess the secret number to unlock the bio.</p>
    <input type="number" id="guess" placeholder="Enter a number between 1 and 10">
    <button onclick="checkGuess()">Submit Guess</button>
    <p class="message" id="message"></p>
  </div>

  <div id="bio-container" style="display:none;">
    <p>
      A <span class="highlight">full-stack web developer</span> 
      and a passionate <span class="highlight">pentester</span>. <span class="highlight">Hacking is my true passion</span>, 
      and through this site, you'll find all my <span class="highlight">TryHackMe (THM)</span> and 
      <span class="highlight">Hack The Box (HTB) write-ups</span>. I combine my skills in <span class="highlight">web development</span> 
      with <span class="highlight">security expertise</span> to explore and solve challenges in the world of cybersecurity. 
      I hope you enjoy exploring my projects!
    </p>
    <img src="https://tryhackme-badges.s3.amazonaws.com/0XC3L1KD.png?update=1" alt="Yise" />
  </div>

  <script>
    const correctNumber = 7; // Set the correct number
    const guessInput = document.getElementById("guess");
    const messageElement = document.getElementById("message");
    const bioContainer = document.getElementById("bio-container");
    const puzzleContainer = document.getElementById("puzzle-container");

    function checkGuess() {
      const userGuess = parseInt(guessInput.value);

      // Check if the guess is a valid number
      if (isNaN(userGuess)) {
        messageElement.textContent = "Please enter a valid number!";
        return;
      }

      if (userGuess === correctNumber) {
        messageElement.textContent = "Correct! Here's my bio:";
        puzzleContainer.style.display = "none";
        bioContainer.style.display = "block";
      } else {
        messageElement.textContent = "Incorrect. Try again!";
      }
    }
  </script>
</body>
</html>