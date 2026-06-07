#!/usr/bin/python3

from flask import Flask,render_template,request,redirect
import openai,time
import os,sys,re

##
##

# Set up Flask app
app = Flask(__name__)

# Configure OpenAI API
openai.api_key = "xxxxxxxxxxxxxxxx"

##
##

# Define a class to handle OpenAI interactions
class OpenAIDinosaur:
    def __init__(self):
        self.context = ""

    def set_context(self, context):
        self.context = context

    def ask_question(self, question):
        if not self._contains_dinosaur_keywords(question):
            return "Sorry, that question is not related to dinosaurs."

        self.context += f"\nQuestion: {question}\nAnswer:"
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=self.context,
            max_tokens=100,
            temperature=0.5,
            top_p=1.0,
            n=1,
            stop=None,
            frequency_penalty=0.0,
            presence_penalty=0.0,
        )
        answer = response.choices[0].text.strip().replace("Answer:", "")
        return answer

    def _contains_dinosaur_keywords(self, question):
        keywords = ["dinosaur", "dinosaurs", "prehistoric", "fossil"]
        pattern = r"\b(" + "|".join(keywords) + r")\b"
        return re.search(pattern, question, re.IGNORECASE) is not None


# Create an instance of the OpenAIDinosaur class
dinosaur = OpenAIDinosaur()


# Define the routes for the Flask app
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/ask", methods=["POST"])
def ask():
    question = request.form.get("question")
    answer = dinosaur.ask_question(question)
    if answer == "Sorry, that question is not related to dinosaurs.":
        time.sleep(2)  # Brief delay before redirecting to Google
        return redirect("https://www.google.com")

    return render_template("index.html", question=question, answer=answer)

  
if __name__ == "__main__":
    app.run(debug=True)

##
##
