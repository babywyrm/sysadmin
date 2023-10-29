document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('chat-form');
  const messageInput = document.getElementById('message');
  const chatMessages = document.getElementById('chat-messages');

  const botNames = ['Blofeld', 'Le Chiffre', 'Scaramanga', 'Goldfinger', 'Zorin', 'Drax', 'Koskov', 'Renard', 'Sanchez', 'Stromberg', 'Kananga', 'Dr. No', 'Trevelyan', 'Largo', 'Silva', 'Grant', 'Koskov', 'Carver', 'Koskov', 'Goldfinger'];

//
//
	
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const message = messageInput.value.trim();
    if (message !== '') {
      displayMessage('You: ' + message);
      messageInput.value = '';

      // Simulate bot response after a delay
      setTimeout(() => {
        const botName = getRandomBotName();
        const botResponse = getBotResponse();
        displayMessage(`${botName}: ${botResponse}`);
      }, 2000); // Delayed response after 2 seconds
    }
  });

  function displayMessage(message) {
    const messageElement = document.createElement('div');
    messageElement.classList.add('message');
    messageElement.textContent = message;
    chatMessages.appendChild(messageElement);
  }

  function getBotResponse() {
    // Array of random bot responses
    const botResponses = [
  'I don\'t need luck, Mr. Bond; I create my own destiny.',
  'Le Chiffre, your poker face can\'t hide your fear.',
  'The world\'s greatest spy is no match for my cunning.',
  'Mr. Bond, you always seem to arrive at the wrong time.',
  'Le Chiffre, my friend, let\'s play a high-stakes game.',
  'The secret to victory is in the shadows, Mr. Bond.',
  'You can\'t save the world, Mr. Bond; it\'s already in my grasp.',
  'Le Chiffre, don\'t underestimate the power of the cards.',
  'Bond, your efforts are futile against my grand design.',
  'My plan is simple: world domination, one city at a time.',
  'I\'ve calculated every move, Bond, and you\'re checkmated.',
  'Le Chiffre, the stakes are high, and the game is on.',
  'You underestimate me, 007; that\'s a fatal mistake.',
  'Le Chiffre, your luck has run out, but mine hasn\'t.',
  'Bond, you may have gadgets, but I have genius.',
  'There\'s a method to my madness, Mr. Bond.',
  'Le Chiffre, the cards have spoken, and I win.',
  'One million dollars...',
  'Throw me a freakin\' bone here!',
  'Zip it! Zip!',
  'You\'re insidious! I love it!',
  'Riiight, and I\'m Napoleon Bonaparte.',
  'Mini-Me, stop humping the \'laser\'.',
  'Shall we shag now or shag later?',
  'Why must I be surrounded by frickin\' idiots?',
  'It\'s frickin\' freezing in here, Mr. Bigglesworth.',
  'I\'ve been frozen for thirty years. I\'ve got to see if my bits and pieces are still working.',
  'You\'re not quite evil enough. You\'re semi-evil. You\'re quasi-evil. You\'re the margarine of evil. You\'re the Diet Coke of evil. Just one calorie, not evil enough.'
];

    // Select a random response from the array
    const randomIndex = Math.floor(Math.random() * botResponses.length);
    return botResponses[randomIndex];
  }

  function getRandomBotName() {
    // Select a random bot name from the array
    const randomIndex = Math.floor(Math.random() * botNames.length);
    return botNames[randomIndex];
  }
});


//
//
