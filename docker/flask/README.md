

# Here's an advanced Flask app with decorators and functions that tracks base Ubuntu images in Docker repositories:

```
from flask import Flask, jsonify
import docker
import requests

app = Flask(__name__)
client = docker.from_env()

def get_base_images(registry_url):
    registry = DockerRegistry(registry_url)
    repositories = registry.repositories
    base_images = []
    for repository in repositories:
        tags = registry.get_repository(repository)
        for tag in tags:
            manifest = registry.get_tag(repository, tag)
            if 'config' in manifest and 'labels' in manifest['config']:
                labels = manifest['config']['labels']
                if 'org.label-schema.schema-version' in labels and 'org.label-schema.name' in labels:
                    schema_version = labels['org.label-schema.schema-version']
                    name = labels['org.label-schema.name']
                    if schema_version == '1.0' and name.startswith('ubuntu'):
                        base_images.append({'repository': repository, 'tag': tag})
    return base_images

class DockerRegistry:
    def __init__(self, registry_url):
        self.registry_url = registry_url

    def __repr__(self):
        return f'<DockerRegistry {self.registry_url}>'

    @property
    def repositories(self):
        url = f'{self.registry_url}/v2/_catalog'
        response = requests.get(url)
        data = response.json()
        return data['repositories']

    def get_repository(self, repository_name):
        url = f'{self.registry_url}/v2/{repository_name}/tags/list'
        response = requests.get(url)
        data = response.json()
        return data['tags']

    def get_tag(self, repository_name, tag_name):
        url = f'{self.registry_url}/v2/{repository_name}/manifests/{tag_name}'
        headers = {'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
        response = requests.get(url, headers=headers)
        return response.json()

class DockerImage:
    def __init__(self, image):
        self.image = image

    def __repr__(self):
        return f'<DockerImage {self.image.short_id}>'

    @property
    def tags(self):
        return self.image.tags

    @property
    def size(self):
        return self.image.attrs['Size']

@app.route('/<registry_url>/ubuntu', methods=['GET'])
def get_ubuntu_images(registry_url):
    base_images = get_base_images(registry_url)
    return jsonify(base_images)

@app.route('/images', methods=['GET'])
def get_images():
    images = client.images.list()
    return jsonify([{'id': image.id, 'tags': image.tags} for image in images])

@app.route('/images/<string:image_id>', methods=['GET'])
def get_image(image_id):
    image = client.images.get(image_id)
    return jsonify(DockerImage(image).__dict__)

if __name__ == '__main__':
    app.run(debug=True)
    
```    
    
In this application, we define a get_base_images function that takes a Docker registry URL and returns a list of base Ubuntu images in the registry. The function uses the DockerRegistry and DockerImage classes to retrieve the repositories, tags, and labels of the manifests for each tag. The function filters out only the Ubuntu base images and returns the list of images.

We use a decorator to define the route for the get_ubuntu_images function. The route takes the registry_url parameter and returns the list of base Ubuntu images.

We also define routes for the base images and a specific image using the DockerImage class, as in the previous examples.

When the Flask application is run, we initialize the Docker client and start the



///////////////////////

Dockerizing a Python 3 Flask App Line-by-Line
If you’re like me, you end up writing a lot of Flask apps for random web applications and APIs. When you’re done building these Flask apps, typically, you need to deploy them to production somehow. Unless you’re using a container service like Heroku, deployment is synonymous with SSHing to a live server, installing your dependencies, and starting your application from source.


//////////////////////

https://medium.com/bitcraft/dockerizing-a-python-3-flask-app-line-by-line-400aef1ded3a

//////////////////////


Docker logo. Because, containers, get it?
Docker makes the process of deployment easier by containerizing your app and automatically installing dependencies from a simple declarative config called the Dockerfile. In your Dockerfile, you can specify the operating system to run on, the apt-get or yum commands to run before your application starts, or any other logic you can think of. Docker will generate an image from this and handle running your application using that image inside a container.
In this guide, we’ll walk through the process of writing a Dockerfile for a modern Flask app. By the time we’re done, we’ll have a nice Ubuntu + nginx + uwsgi + Flask stack all working.
Requirements
Before we begin, ensure that you have Docker Community Edition installed. Instructions vary by operating system but it is available for Windows, OS X, and Linux.
Also, you’ll need a Python 3 Flask application to deploy. Make sure that in your app.py , any app.run() calls are wrapped in an if __name__ == '__main__' check so that uwsgi does not accidentally spawn 2 copies of your server.
The Dockerfile
First, create a file named Dockerfile (no extension) in the root of your Flask application and open it in your favorite text editor.
Docker uses a very simple, declarative language to define the build process. Let’s start off by identifying the operating system we’d like to use:
FROM ubuntu:18.10
This tells Docker to fetch the Ubuntu 18.10 Cosmic Cuttlefish disk image from the Docker official repository and use it as the base OS for this container. Next, let’s add some information about the maintainer of this package:
LABEL maintainer="Zach Bloomquist <zach@bloomqu.ist>"
Docker doesn’t use this information for anything except for setting the author field of the created image. It’s also nice to leave a breadcrumb for developers who may come after you. Next:
RUN apt-get update
RUN apt-get install -y python3 python3-dev python3-pip nginx
RUN pip3 install uwsgi
RUN commands are executed while building the Docker image. These will update apt’s package index and then fetch our dependencies. The package python3-dev may stand out to you — this package is required for uwsgi to build when we install it with pip .
COPY ./ ./app
WORKDIR ./app
The COPY command copies files from the source’s filesystem to the container’s filesystem. These commands copy over the application’s source code to a new folder and cd into it for the rest of the build. Next:
RUN pip3 install -r requirements.txt
This installs the requirements for your Python 3 app to execute, assuming you list your dependencies in requirements.txt.
COPY ./nginx.conf /etc/nginx/sites-enabled/default
This command sets up the configuration for nginx inside the container by overwriting Ubuntu’s default. It assumes you have a proper nginx configuration at ./nginx.conf containing something like this:
server {
  location @flask {
    include uwsgi_params;
    uwsgi_pass unix://tmp/uwsgi.sock;
  }
  location / {
    try_files @flask;
  }
}
This example config will pass all requests to the container’s port 80 to the uwsgi application listening on that socket.
Now, back to the Dockerfile:
CMD service nginx start && uwsgi -s /tmp/uwsgi.sock --chmod-socket=666 --manage-script-name --mount /=app:app
The CMD command tells Docker what command to execute when someone runs the image our Dockerfile creates. In this case, we want to start nginx, then start up uwsgi to back it.
Building & Running
Now that our Dockerfile is created, let’s build the image from the current directory:
docker build -t my-image-name .
You can watch Docker chew through installing Ubuntu, installing the system packages, and installing our pip requirements. Once that’s done, you’re ready to boot up a new container based off your image:
docker run -d -p 1337:80 my-image-name
The -d option tells Docker to run the container in the background and print out the container ID. -p 1337:80 maps port 1337 on the host machine to port 80 in the container.
Now that your container is running and port 1337 is mapped, you should be able to visit http://localhost:1337/ and see your Flask application running. Woohoo!
You can use the container ID printed out by docker run -d to manage the life cycle of your app. Here are some good CLI commands to know:
docker image ls — list available images
docker container ls — list all containers
docker logs <partial container ID> — tail logs from a container
docker kill <partial container ID> — kill execution of a container
docker restart <partial container ID> — restart container
docker start <partial container ID> — start stopped container
docker stop <partial container ID> — gracefully end container
docker container prune — delete all non-running containers
I hope this guide was helpful to you in Dockerizing your Flask application. If you have any comments or questions, please leave them below.
Appendix: Next Steps
If you really want to turbo-charge your Dockerization, try these tips:
Make use of named containers so you don’t have to keep track of container IDs. Pass the --name my-awesome-name to docker run to name your new containers, then you can do things like docker restart my-awesome-name.
Create shell script helpers to help your users interact with the Dockerized app. For example, you might create a shell script called install.sh that ensures Docker is installed, then builds the Docker image and ensures it runs on startup.
Use Docker Compose to further abstract your deployment. Docker Compose allows you to orchestrate multiple containers for one deployment. In this example, we might’ve used a container just running nginx to proxy requests to a separate container running our Flask app.
Read the second part of this article, “Docker-composing” a Python 3 Flask App Line-by-Line, next!
How’d you like this article? If you liked it or learned something, please leave a clap! BitCraft is a software development group and we’re always taking on new clients. Reach out to us at hello@bitcraft.io or visit our website at bitcraft.io!
