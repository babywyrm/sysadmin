##
##

from flask import Flask, render_template, request
import mysql.connector
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC

app = Flask(__name__)

# Establish a connection to the MariaDB database
db = mysql.connector.connect(
    host='<db_host>',
    user='<db_username>',
    password='<db_password>',
    database='<db_name>'
)

# Define the path to the machine learning model and vectorizer
model_path = '/models/qa_model.pkl'
vectorizer_path = '/models/qa_vectorizer.pkl'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/questions', methods=['GET'])
def questions():
    # Retrieve the questions from the database
    cursor = db.cursor()
    cursor.execute('SELECT * FROM questions')
    questions = cursor.fetchall()
    cursor.close()

    return render_template('questions.html', questions=questions)

@app.route('/questions', methods=['POST'])
def add_question():
    question = request.form['question']
    answer = request.form['answer']

    # Insert the new question into the database
    cursor = db.cursor()
    cursor.execute('INSERT INTO questions (question, answer) VALUES (%s, %s)', (question, answer))
    db.commit()
    cursor.close()

    return 'Question added successfully!'

@app.route('/predict', methods=['POST'])
def predict():
    question = request.form['question']

    # Load the machine learning model and vectorizer
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)

    # Perform text feature extraction on the input question
    transformed_text = vectorizer.transform([question])

    # Use the trained model to predict the answer
    predicted_answer = model.predict(transformed_text)[0]

    return render_template('prediction.html', question=question, answer=predicted_answer)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

##
##
