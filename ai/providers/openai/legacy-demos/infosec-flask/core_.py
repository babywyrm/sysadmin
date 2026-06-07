
###
###

import os
import slack
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
import mysql.connector

###
###

# Instantiate the Slack client
client = slack.WebClient(token=os.environ['SLACK_API_TOKEN'])

# Define the channel ID where the bot will operate
channel_id = '<your_channel_id>'

# Define the path to the machine learning model and vectorizer
model_path = '/models/qa_model.pkl'
vectorizer_path = '/models/qa_vectorizer.pkl'

# Establish a connection to the MariaDB database
db = mysql.connector.connect(
    host='<db_host>',
    user='<db_username>',
    password='<db_password>',
    database='<db_name>'
)

# Check if the model and vectorizer files exist, otherwise train the model
if os.path.exists(model_path) and os.path.exists(vectorizer_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
else:
    # Define a list of security-related questions and their corresponding answers
    security_questions = {
        'What is encryption?': 'Encryption is the process of encoding information in such a way that only authorized parties can access it.',
        'What is a firewall?': 'A firewall is a network security device that monitors and controls incoming and outgoing network traffic based on predetermined security rules.',
        'What is two-factor authentication (2FA)?': 'Two-factor authentication is an extra layer of security that requires users to provide two different forms of identification to verify their identity.',
        # Add more security questions and answers as needed
    }

    # Extract questions and answers from the security_questions dictionary
    questions = list(security_questions.keys())
    answers = list(security_questions.values())

    # Perform text feature extraction
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(questions)

    # Train the machine learning model
    model = LinearSVC()
    model.fit(X, answers)

    # Save the model and vectorizer for future use
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)

    # Store the model in the MariaDB database
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS models (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), model BLOB)")
    cursor.execute("INSERT INTO models (name, model) VALUES (%s, %s)", ('QA_Model', pickle.dumps(model)))
    db.commit()
    cursor.close()

# Handle incoming messages
@slack.RTMClient.run_on(event='message')
def handle_message(**payload):
    data = payload['data']

    # Extract the user and text from the incoming message
    user_id = data.get('user')
    text = data.get('text')

    # Ignore messages without user or text
    if user_id is None or text is None:
        return

    # Normalize the text by removing leading/trailing spaces and converting to lowercase
    text = text.strip().lower()

    # Check if the message is a security-related question
    if text.startswith('what is'):
        # Use the trained model to predict the answer
        transformed_text = vectorizer.transform([text])
        predicted_answer = model.predict(transformed_text)[0]
        client.chat_postMessage(channel=channel_id, text=predicted_answer)

# Start the Slack bot
rtm_client = slack.RTMClient(token=os.environ['SLACK_API_TOKEN'])
rtm_client.start()

###
###
