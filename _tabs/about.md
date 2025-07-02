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
  #puzzle-container, #bio-container {
    font-family: 'Ubuntu', sans-serif;
    text-align: center;
    margin-top: 40px;
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
  .message {
    font-size: 18px;
    margin-top: 10px;
    font-weight: bold;
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 10px;
    margin-top: 40px;
  }
  .badges img {
    width: 80px;
    height: auto;
  }
</style>
<body>
<div id="puzzle-container">
  <p>🔐 Guess the secret number to unlock the bio and badge wall.</p>
  <input type="number" id="guess" placeholder="Enter a number between 1 and 10">
  <button onclick="checkGuess()">Submit Guess</button>
  <p class="message" id="message"></p>
</div>

<div id="bio-container" style="display:none;">
  <p>
    A <span class="highlight">full-stack web developer</span> and a passionate 
    <span class="highlight">pentester</span>. <span class="highlight">Hacking is my true passion</span>, 
    and through this site, you'll find all my <span class="highlight">TryHackMe (THM)</span> and 
    <span class="highlight">Hack The Box (HTB) write-ups</span>. I combine my skills in 
    <span class="highlight">web development</span> with <span class="highlight">security expertise</span> 
    to explore and solve challenges in the world of cybersecurity. I hope you enjoy exploring my projects!
  </p>
  <img src="https://tryhackme-badges.s3.amazonaws.com/0XC3L1KD.png?update=1" alt="THM Badge" width="250" />
  <div class="badges">
    <img src="https://tryhackme.com/img/badges/linux.svg" />
    <img src="https://tryhackme.com/img/badges/webbed.svg" />
    <img src="https://tryhackme.com/img/badges/burpsuite.svg" />
    <img src="https://tryhackme.com/img/badges/owasptop10.svg" />
    <img src="https://tryhackme.com/img/badges/hashcracker.svg" />
    <img src="https://tryhackme.com/img/badges/metasploit.svg" />
    <img src="https://tryhackme.com/img/badges/blue.svg" />
    <img src="https://tryhackme.com/img/badges/linuxprivesc.svg" />
    <img src="https://tryhackme.com/img/badges/networkfundamentals.svg" />
    <img src="https://tryhackme.com/img/badges/howthewebworks.svg" />
    <img src="https://tryhackme.com/img/badges/streak7.svg" />
    <img src="https://tryhackme.com/img/badges/introtowebsecurity.svg" />
    <img src="https://tryhackme.com/img/badges/phishing.svg" />
    <img src="https://tryhackme.com/img/badges/introtooffensivesecurity.svg" />
    <img src="https://tryhackme.com/img/badges/mrrobot.svg" />
    <img src="https://tryhackme.com/img/badges/ohsint.svg" />
    <img src="https://tryhackme.com/img/badges/adventofcyber.svg" />
    <img src="https://tryhackme.com/img/badges/king.svg" />
    <img src="https://tryhackme.com/img/badges/securityawareness.svg" />
    <img src="https://tryhackme.com/img/badges/streak30.svg" />
    <img src="https://tryhackme.com/img/badges/ice.svg" />
    <img src="https://tryhackme.com/img/badges/docker.svg" />
    <img src="https://tryhackme.com/img/badges/hololive.svg" />
    <img src="https://tryhackme.com/img/badges/wireshark.svg" />
    <img src="https://tryhackme.com/img/badges/wreath.svg" />
    <img src="https://tryhackme.com/img/badges/pentestingtools_badge.svg" />
    <img src="https://tryhackme.com/img/badges/attackingad.svg" />
    <img src="https://tryhackme.com/img/badges/overpass_badge.svg" />
    <img src="https://tryhackme.com/img/badges/investigations_badge.svg" />
    <img src="https://tryhackme.com/img/badges/windowsprivesc.svg" />
    <img src="https://tryhackme.com/img/badges/streak90.svg" />
    <img src="https://tryhackme.com/img/badges/adventofcyber4.svg" />
    <img src="https://tryhackme.com/img/badges/introtosecurityengineering.svg" />
    <img src="https://tryhackme.com/img/badges/threatsandrisks.svg" />
    <img src="https://tryhackme.com/img/badges/networkandsystemsecurity.svg" />
    <img src="https://tryhackme.com/img/badges/managingincidents.svg" />
    <img src="https://tryhackme.com/img/badges/softwaresecurity.svg" />
    <img src="https://tryhackme.com/img/badges/3million.svg" />
    <img src="https://tryhackme.com/img/badges/aoc5sidequest1.svg" />
    <img src="https://tryhackme.com/img/badges/loganalysis.svg" />
    <img src="https://tryhackme.com/img/badges/aoc5sidequest2.svg" />
    <img src="https://tryhackme.com/img/badges/adventofcyber5.svg" />
    <img src="https://tryhackme.com/img/badges/iacsecurity.svg" />
    <img src="https://tryhackme.com/img/badges/securityofthepipeline.svg" />
    <img src="https://tryhackme.com/img/badges/boogeyman3.svg" />
    <img src="https://tryhackme.com/img/badges/cyberthreatintellegenceblue.svg" />
    <img src="https://tryhackme.com/img/badges/redteamcapstone.svg" />
    <img src="https://tryhackme.com/img/badges/endpointsecuritymonitoring.svg" />
    <img src="https://tryhackme.com/img/badges/networksecurityandtrafficanalysisv2.svg" />
    <img src="https://tryhackme.com/img/badges/advancedelk.svg" />
    <img src="https://tryhackme.com/img/badges/containersecurity.svg" />
    <img src="https://tryhackme.com/img/badges/cyberdefenceframework.svg" />
    <img src="https://tryhackme.com/img/badges/incidentresponse.svg" />
    <img src="https://tryhackme.com/img/badges/malwareanalysis.svg" />
    <img src="https://tryhackme.com/img/badges/threathunting.svg" />
    <img src="https://tryhackme.com/img/badges/advancedsplunk.svg" />
    <img src="https://tryhackme.com/img/badges/threatemulation.svg" />
    <img src="https://tryhackme.com/img/badges/windcorp_badge.svg" />
    <img src="https://tryhackme.com/img/badges/careerready.svg" />
    <img src="https://tryhackme.com/img/badges/swordapprentice.svg" />
    <img src="https://tryhackme.com/img/badges/shieldapprentice.svg" />
    <img src="https://tryhackme.com/img/badges/aocsidequest5.svg" />
    <img src="https://tryhackme.com/img/badges/aoc5.svg" />
  </div>
</div>
<script>
  const correctNumber = 7;
  const guessInput = document.getElementById("guess");
  const messageElement = document.getElementById("message");
  const bioContainer = document.getElementById("bio-container");
  const puzzleContainer = document.getElementById("puzzle-container");
  function checkGuess() {
    const userGuess = parseInt(guessInput.value);
    if (isNaN(userGuess)) {
      messageElement.textContent = "❗ Please enter a valid number!";
      return;
    }
    if (userGuess === correctNumber) {
      messageElement.textContent = "✅ Correct! Here's my bio and badges:";
      puzzleContainer.style.display = "none";
      bioContainer.style.display = "block";
    } else {
      messageElement.textContent = "❌ Incorrect. Try again!";
    }
  }
</script>
</body>
