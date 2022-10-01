This article aims to provide a clear and succinct step by step tutorial on how to build a Docker image that runs your Python code in a Docker container in easy to follow steps.

It’s becoming extremely important in the industry now for every technologist, being a Quant developer, Data Engineer, Architect or a Data Scientist, to be able to run a Python process within a docker container.

#
##
#
https://medium.com/fintechexplained/running-python-in-docker-container-58cda726d574
#
##
#

Image By Author
A Quick Overview Of The Concepts
In a nutshell, we are going to create a docker file that we will use to build a docker image which we will then run in a docker container.


Image By Author
What is Docker?
Docker is a software platform. It enables software developers to develop, ship and run applications within its containers. Containers are lightweight software applications.

We are going to build a Docker image in this tutorial.

What is a docker file, image and container?
A docker file is a text file that contains the set of instructions for the Docker platform. Therefore, it can be versioned and committed to a code repository.
An image includes everything needed to run an application — the code or binary, runtime, dependencies, and any other file system objects required.
Docker containers run the application code.
Now that the theory is done, let’s get started with a practical exercise.
In this article, we are going to build a Python program and then run it inside a Docker container.

There are essentially 5 steps:
Create your python program (skip if you already have a Python program code)
Create a docker file
Build the docker file into an image
Run the docker image in a container
Test the Python program running within a container
Step 1. Let’s Create Our Python Web-Server program
Open Your IDE e.g. PyCharm
Create a new project. Name: FinTechExplained_Python_Docker
Create a new folder: src within the FinTechExplained_Python_Docker folder
Create a new file named requirements.txt within the src folder
Open the requirements.txt file and add: flask==2.0.2
6. Create a new file: main.py within the src folder and Dockerfile (no extension) in the root folder FinTechExplained_Python_Docker

This will be the final directory structure:


Image By Author
7. Add the following contents in the main.py file:

from flask import Flask
app = Flask(’FinTechExplained WebServer’)

@app.route(’/’)
def get_data():
    return [1,2,3]
We have added a new route above which calls the get_data() function that then returns [1,2,3].

That’s the Python code done now.

8. Run the application by executing: python -m flask run --host=0.0.0.0 --port=5000

Open your browser e.g. Google Chrome. And navigate to the url e.g. http://localhost:5000

9. It will return [1,2,3].

10. Now the application is running in your local machine. Stop the Python program. We are going to run it within a docker container next.

Step 2. Write Docker File
Open the file named Dockerfile (without any extension) in the root folder: FinTechExplained_Python_Docker
2. Add the following contents:

FROM python:3.8-slim-buster

WORKDIR /src

COPY src/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0"]
Let’s understand the contents of the file.

The first line is

FROM python:3.8-slim-buster
Remember the dockerfile will create an image. The first command uses the FROM keyword. It tells docker to create an imagine that will be inherited from an image named: 3.8-slim-buster
This command is telling the docker service to use the base image as python:3.8-slim-buster. This is an official Python image. It has all of the required packages that we need to run a Python application.
The next line is:

WORKDIR /src
We are setting a working directory. It will then navigate to the src folder. It is essentially creating a working directory. From now on, we can pass in the relative paths based on the src directory.

The next line is:

COPY src/requirements.txt requirements.txt
Then it will copy the requirements.txt file. The COPY <first parameter> <second parameter> command tells Docker to take the file in the first parameter to copy into the image at the location specified in the second parameter. Therefore, we’ll copy the requirements.txt file into our working directory /src.

The next line is:

RUN pip install --no-cache-dir -r requirements.txt
Now it will run the command: pip install that will install all of the dependencies within the requirements.txt file in the image.

COPY . .
Now, we’ll copy the contents of the current working directory. Essentially, the COPY command copies the files that are located in the src directory and copies them into the image.

The final line will run the command to run the Python process:

CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0"]
This command will start the flask WebServer.

Note, this is how our Directory structure is:


Image By Author
Step 3: Now Build An Image
This command is straightforward. Open a terminal and ensure you are within the FinTechExplained_Python_Docker folder.

Run the following command:

docker build --tag fintechexplained-python-docker .

This command will build the docker image for you. It will tag it as fintechexplained-python-docker.

Once the image is ready, we are ready to run it.

Step 4: Run The Docker Image In A Container
Run the following command:

docker run --publish 5000:5000 fintechexplained-python-docker
This command will run the docker container.

Step 5: Test The Application
Open the browser. Navigate to the URL as before:

http://localhost:5000

And it will return [1,2,3]

The main difference is that the same Python Flask web server is now running within a docker container. We can launch multiple docker containers on different machines and even launch them on the same machine by overriding the port number.

That’s all it is.
If you want to understand more about Docker then I highly recommend reading this article. The article outlines the most important commands that I highly recommend everyone to be familiar with

Docker
Must know platform for architects, data scientists and developers
medium.com

It’s a must know concept.

Summary
Containers are lightweight software applications. They offer a number of benefits including a reduction in time to deliver an application, scalability, ease of application management, support and better user experience.

This article presented a step-by-step tutorial that we can follow to run a Python program within a Docker container.

