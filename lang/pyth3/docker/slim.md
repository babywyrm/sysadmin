Dockerizing a REST API in Python Less Than 9 MB and Based on scratch Image

##
#
https://medium.com/analytics-vidhya/dockerizing-a-rest-api-in-python-less-than-9-mb-and-based-on-scratch-image-ef0ee3ad3f0a
#
##

Packaging applications as container images have been quite common for years. While creating container images, for example with Docker, image size becomes significant in many cases; due to network usage, (probably) increased attack surface, disk usage, push-pull time, longer build times, … and the list goes on. The final image frequently includes a lot of unused components; like shells, OS config files, libraries, build-time dependencies. In languages like Go, it is easy to create a statically linked executable and include it in an empty image, even without and OS if possible. But when working with Python and languages that need a virtual machine at the runtime, it is not common to use a way to achieve the same result. In this post, we will introduce a way to create Docker images for Python applications which will be less than 9 MB and based on the scratch image.


There will be more optimization possibilities, undoubtedly. We are getting through a path using a toolset (opinionated by us) to reach < 9MB goal.

Creating a Docker Image for an API with Python and Flask
Firstly, let’s create a Docker image, based on the Python image from Docker Hub. We will install Falcon framework on it, as well as Gunicorn as an application server. Afterward, we will inspect the image size. We will use a repo with a basic random integer generator as an example. The source code is available from here

gurayyildirim/rastgeleSayi
Demo application for trying Docker. Contribute to gurayyildirim/rastgeleSayi development by creating an account on…
github.com

For that example, the Dockerfile we will build is(a little bit different from the version in the repo):

FROM python:3
CMD gunicorn -b 0.0.0.0:80 rastgele:api
WORKDIR /code
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt
ADD . /code
Let’s build and see the size of the image:

$ git clone https://github.com/gurayyildirim/rastgelesayi && cd rastgelesayi
# edit Dockerfile as above
$ docker build -t guray/random:0.1 .
... build output is truncated ...
$ docker image ls guray/random:0.1

Output of a Python container image size in Docker
It is almost 1GB, meaning that for a small API, we have an image that costs 1GB and includes many files that we don’t even open once.

This image makes sense for a huge number of purposes. But for a small API or a lot of other applications; we want to shrink the image without losing the functionality.

Using Alpine Linux Image
One of the first steps to optimize the image size is changing the base image with an Alpine Linux based image. In that way, we should get lower numbers as image size. The Dockerfile for that has an only difference in the FROM line:

FROM python:3-alpine
CMD gunicorn -b 0.0.0.0:80 rastgele:api
WORKDIR /code
ADD requirements.txt requirements.txt
RUN pip install -r requirements.txt
ADD . /code
And let’s build and check the final image size again:

$ docker build -t guray/random:0.2 .
... build output is truncated ...
$ docker image ls guray/random:0.2

Example Docker image with Python-based on Alpine Linux
The number decreased as expected. It is useful now. But there is one point to keep in mind: Alpine Linux comes with musl instead of glibc which is common in many numbers of distributions. It sometimes causes problems with pre-built binaries, and other cases as well.

Still, it is ready to be run now, and the size is lowered. Our application is also able to run without any problems, due to Falcon’s itself and being based on pure Python dependencies.

Further Optimization
For us, it is clear that being obsessive about this kind of optimizations may result in black holes and it is easy to find ourselves trying to gain a couple of more bits. However, for our application, it is understandable that 115MB is still a huge number.

Docker Slim is a great project to automatically finds shrinks a Docker image as well as tries to make it more secure. Let’s try it on the last image:

$ docker-slim build --http-probe --expose 80 guray/random:0.2
$ docker image ls guray/random.slim

Slimmed Docker image with a Python API written in Falcon
The size has reduced to ~36MB with some magic done by Docker Slim. It is a great tool and it makes a lot of heavy lifting for you. If you are curious, here are the details.

Even Further Optimization
You may face with times that you need to distribute your application to your users when they may not have Python or any dependencies installed on their computers. In these times, it is not rare that we cannot expect everybody to install Python and dependencies manually. In these cases, we are trying to create a package for our application, a package that includes Python and other dependencies.

There are some tools in Python to help you create distributable packages for your application. Essentially, they package Python binary and dependencies along with your application. Pyinstaller and Cx_freeze are 2 of these tools that will make our life easier.

In this post, we will stick with Pyinstaller. There is no vital reason for this, other than we found it more easy and intuitive than others we experienced(we are open to suggestions). Basically, you are just providing your app to it and it generates a directory that includes all the necessary files ready to be distributed.

Behind the scenes, it scans your app and finds imported libraries (from import statements) and adds them into the package, converts py files to pyc, and much more. It also comes with some recipes(called hooks) that describe implicit imports for specific modules so as not to throw an ImportError error in runtime. It is also possible to create new hooks explicitly defining dependencies of an application.

In that case, Pyinstaller should provide us a more slimmed packaged version of our application thanks to not including all the files/modules, and only filtered/explicitly used ones instead. For more details about the process, the documentation of the project is written brilliantly.

Creating the First Package
Let’s install Pyinstaller and create a package for our example API. Since Pyinstaller collects modules from our system, the requirements should be installed as well(this is only for poking up, you should run these in a container at the end):

$ pip3 install pyinstaller
... install output is truncated ...
$ pip3 install -r requirements.txt
... install output is truncated ...
$ pyinstaller rastgele.py
... a lot of output describing the process here ...
After the process is completed, the dist directory will include our files as a directory. We can include this directory on an image and we will be ready to go. Let’s see the size of this directory:

$ du -sh dist/rastgele/
15M dist/rastgele/
So it costs 15MB for our files. We can compress this directory if needed, resulting 6.6M with archiving with tar and employing gzip for compression:

$ tar czf rastgele.tar.gz dist/rastgele/
$ ls -lh rastgele.tar.gz
-rw-r--r-- 1 x x 6.6M May 15 11:07 rastgele.tar.gz
However, this method requires tar as well as gzip installed on the target computer/container image as well as we should define a clear way to extract it at the starting.

Running the App — Oops! 😬 And Fix!
Let’s try running our app to see what is happening. There is a executable binary file with the name of our Python file and we will run it directly:

$ cd dist/rastgele/
$ ./rastgele
$
Nothing happened. There are more than one problems here. Firstly, Pyinstaller just runs the Python file and our file does not include a structure to run itself when directly executed. In other words, we are starting our API server with gunicorn when we use it. But now, Pyinstaller does not know it and just tries ‘python rastgele.py’.

Solution for this is explained in Gunicorn docs, which is adding a standard ‘if __name__ == “__main__”’ conditional block and starting Gunicorn directly inside the app. We are implementing it like in the Gunicorn’s example. Let’s see how it happens:

We should import Gunicorn BaseApplication class. So insert this at the import section of the program(final whole code is added below):

from gunicorn.app.base import BaseApplication
And afterward, we can just define the same class and initialize it if the program is run directly:

class StandaloneRandomNumberAPI(BaseApplication):
def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()
def load_config(self):
        config = {key: value for key, value in self.options.items()
                  if key in self.cfg.settings and value is not None}
        for key, value in config.items():
            self.cfg.set(key.lower(), value)
def load(self):
        return self.application
if __name__ == "__main__":
  
    options = {
        'bind': '%s:%s' % ('0.0.0.0', '80'),
        'workers': 4,
    }
    StandaloneRandomNumberAPI(api, options).run()
And the program should look like this:

https://gist.github.com/gurayyildirim/ff2d8e12a3d0faaa29ba802393e23806

Now try to run the final code:

$ python3 rastgele.py 
[2020-05-15 11:54:47 +0000] [1239] [INFO] Starting gunicorn 19.7.1
[2020-05-15 11:54:47 +0000] [1239] [INFO] Listening at: http://0.0.0.0:80 (1239)
[2020-05-15 11:54:47 +0000] [1239] [INFO] Using worker: sync
[2020-05-15 11:54:47 +0000] [1243] [INFO] Booting worker with pid: 1243
[2020-05-15 11:54:47 +0000] [1244] [INFO] Booting worker with pid: 1244
[2020-05-15 11:54:47 +0000] [1245] [INFO] Booting worker with pid: 1245
[2020-05-15 11:54:47 +0000] [1246] [INFO] Booting worker with pid: 1246
Our application is now running. Meaning that we can start packaging it again:

$ pyinstaller rastgele.py
... output removed ...
$ du -sh dist/rastgele/
15M dist/rastgele/
Now let’s try running our app:

$ ./dist/rastgele/rastgele
Error: class uri 'gunicorn.glogging.Logger' invalid or not found:
[Traceback (most recent call last):
  File "gunicorn/util.py", line 134, in load_class
  File "importlib/__init__.py", line 126, in import_module
  File "<frozen importlib._bootstrap>", line 994, in _gcd_import
  File "<frozen importlib._bootstrap>", line 971, in _find_and_load
  File "<frozen importlib._bootstrap>", line 953, in _find_and_load_unlocked
ModuleNotFoundError: No module named 'gunicorn.glogging'
]
Error again! The reason why we are going over this errors is that it may be frequent or rare based on your stack. But they help us to understand how the whole mechanism is working.

The solution is to express implicit dependencies(called hidden imports). There are a couple of ways to it. We will stick with passing them to Pyinstaller via CLI. From here we can see gunicorn.glogging is a missing dependency. And before trying, I want to also share the other one: gunicorn.workers.sync. In order to make Pyinstaller aware of them, just pass their names (it is only one of the approaches):

$ pyinstaller rastgele.py --hidden-import "gunicorn.glogging" --hidden-import "gunicorn.workers.sync"
...
8811 INFO: Analyzing hidden import 'gunicorn.glogging'
9187 INFO: Analyzing hidden import 'gunicorn.workers.sync'
...
Now try to run our application. It should work without any errors:

$ ./dist/rastgele/rastgele 
[2020-05-15 12:26:59 +0000] [1897] [INFO] Starting gunicorn 19.7.1
[2020-05-15 12:26:59 +0000] [1897] [INFO] Listening at: http://0.0.0.0:80 (1897)
[2020-05-15 12:26:59 +0000] [1897] [INFO] Using worker: sync
[2020-05-15 12:26:59 +0000] [1901] [INFO] Booting worker with pid: 1901
[2020-05-15 12:26:59 +0000] [1902] [INFO] Booting worker with pid: 1902
[2020-05-15 12:26:59 +0000] [1903] [INFO] Booting worker with pid: 1903
[2020-05-15 12:26:59 +0000] [1904] [INFO] Booting worker with pid: 1904
The size will grow slightly but not much(even not noticeable with -h parameter in our case):

$ du -sh dist/rastgele/
15M dist/rastgele/
Making It One File
The last part is packaging our app as one, binary, and executable file. Pyinstaller has a -F parameter to do that. It includes a bootloader that will extract your files from that file and run them afterward. This packaging is also responsible for compression, so binary size will be like the file we compressed before:

$ ls -lh ./dist/rastgele
-rwxr-xr-x 1 root root 7.0M May 15 12:32 ./dist/rastgele
Now we have a binary sized 7.0MB and we can run it directly:

$ ./dist/rastgele 
[2020-05-15 12:33:57 +0000] [2229] [INFO] Starting gunicorn 19.7.1
[2020-05-15 12:33:57 +0000] [2229] [INFO] Listening at: http://0.0.0.0:80 (2229)
[2020-05-15 12:33:57 +0000] [2229] [INFO] Using worker: sync
[2020-05-15 12:33:57 +0000] [2233] [INFO] Booting worker with pid: 2233
[2020-05-15 12:33:57 +0000] [2234] [INFO] Booting worker with pid: 2234
[2020-05-15 12:33:57 +0000] [2235] [INFO] Booting worker with pid: 2235
[2020-05-15 12:33:57 +0000] [2236] [INFO] Booting worker with pid: 2236
Success. Now we can copy that file, for example from after generating in a stage in a Docker multi-stage build, to an image with CentOS, Debian, Ubuntu, … etc. But not Alpine ☹️ If you suffered before in a case, it is not using glibc, instead musl. It causes linker errors on runtime which is not even giving an easy to understand error for many people. Still it is one of the reasons why Alpine image size is small, so not a bad thing. If you are curious, just try to run this binary in an Alpine Linux container.

Packaging with Glibc and Other Libraries — Static Linking
The final step is packaging our app so that it includes all dependent libraries as well. It is kind of like static linking you may heard or used before. In order to create packages which includes all the libraries, we will use StaticX. It requires ldd (which is probably already installed), binutils, gcc, and patchelf(you should build it from the repository) packages on the system as dependencies.

For a CentOS based build system, the commands are listed below. You may prefer installing one by one instead of using “group install” to reach the same functionality:

$ yum install binutils wget -y
$ yum group install "Development Tools" -y
Download, build and install patchelf(outputs are removed for brevity):

$ cd / && wget https://github.com/NixOS/patchelf/archive/0.10.tar.gz
$ tar xzf 0.10.tar.gz
$ cd patchelf-0.10/
$ ./bootstrap.sh
$ ./configure
$ make
$ make install
Afterward we are ready to install StaticX:

$ pip3 install staticx
Now we are ready to create binaries that include all the dependent libraries. Go to the project directory and get into dist directory in it:

$ cd dist/
Run StaticX against it:

$ staticx rastgele rastgele_app
It will take a short while and afterward our final file will be ready:

$ ls -lh
total 16M
-rwxr-xr-x 1 root root 7.0M May 15 12:32 rastgele
-rwxr-xr-x 1 root root 8.2M May 15 16:36 rastgele_app
Now we have a 8.2M file that includes all the necessary objects for our API application. We can use that binary even in a scratch image.

If you try to run it, staticX extracts packed files into a temporary directory in /tmp, inside a directory whose name is starting with staticx-. Moreover; pyinstaller will create a temporary directory in /tmp as well, to extract your app files like in the directory packaging mode which we started with at the beginning of this post. The name of the directory that pyinstaller creates is starting with _MEI and following a few of random characters. When your app is closing gracefully, these temporary directories should automatically be removed as well.

Example Dockerfile with a Minimal Image
After creating the static file for the app, now we are ready to package it as a Docker image. We will use scratch image as the base image, so it will not include any files other than our app. You should also create a directory named tmp in the same directory as your binary because scratch image does not have /tmp, nor mkdir command.

$ mkdir tmp
Here is an example Dockerfile for it:

FROM scratch
ENTRYPOINT ["/rastgele_app"]
COPY tmp /tmp
COPY rastgele_app /
Save the Dockerfile and start the build:

$ docker build -t guray/pystatic-tut:1.0 .
...
Successfully tagged guray/pystatic-tut:1.0
Now we are ready to try it:

$ docker run -it --rm guray/pystatic-tut:1.0
[2020-05-15 16:48:29 +0000] [7] [INFO] Starting gunicorn 19.7.1
[2020-05-15 16:48:29 +0000] [7] [INFO] Listening at: http://0.0.0.0:80 (7)
[2020-05-15 16:48:29 +0000] [7] [INFO] Using worker: sync
[2020-05-15 16:48:29 +0000] [13] [INFO] Booting worker with pid: 13
[2020-05-15 16:48:29 +0000] [14] [INFO] Booting worker with pid: 14
[2020-05-15 16:48:29 +0000] [15] [INFO] Booting worker with pid: 15
[2020-05-15 16:48:29 +0000] [16] [INFO] Booting worker with pid: 16
Increasing Security — Changing User to Nobody
As a final step, we will change our user to nobody. Since there are a lot of environments that are not allowing running containers with root or id 0 user, it is frequently necessary in the environments we are helping. In order to do it, just change the port to a number that is greater than 1024 (ports ≤1024 require root access even if its inside a container, due to the nature of the unix systems). So edit the options line in the code like this:

options = {
        'bind': '%s:%s' % ('0.0.0.0', '8000'),
        'workers': 4,
    }
And package it again:

$ pyinstaller -F rastgele.py --hidden-import "gunicorn.glogging" --hidden-import "gunicorn.workers.sync"
$ cd dist/
$ staticx rastgele rastgele_app
Now it is ready to be packaged again, but with an updated Dockerfile as well:

FROM scratch
ENTRYPOINT ["/rastgele_app"]
USER 65535
COPY --chown=65535:65535 tmp /tmp
COPY --chown=65535:65535 rastgele_app /
Afterward we can build the image and run a container created from it:

$ docker run -it --rm guray/pystatic-tut:1.1
[2020-05-15 16:58:29 +0000] [8] [INFO] Starting gunicorn 19.7.1
[2020-05-15 16:58:29 +0000] [8] [INFO] Listening at: http://0.0.0.0:8000 (8)
[2020-05-15 16:58:29 +0000] [8] [INFO] Using worker: sync
[2020-05-15 16:58:29 +0000] [14] [INFO] Booting worker with pid: 14
[2020-05-15 16:58:29 +0000] [15] [INFO] Booting worker with pid: 15
[2020-05-15 16:58:29 +0000] [16] [INFO] Booting worker with pid: 16
[2020-05-15 16:58:29 +0000] [17] [INFO] Booting worker with pid: 17
Now check the image size:

$ docker image ls guray/pystatic-tut:1.1
REPOSITORY           TAG                 IMAGE ID            CREATED             SIZE
guray/pystatic-tut   1.1                 4fc7ab2d0d23        41 seconds ago      8.5MB
Even Further Optimization
If you are curious, passing -OO to Python when running pyinstaller will help you to earn several bytes as well. Just run like this:

$ python3 -OO -m PyInstaller -F rastgele.py --hidden-import "gunicorn.glogging" --hidden-import "gunicorn.workers.sync"
This will remove docstrings and a couple of other things. More details can be found in Python manual and also PyInstaller’s manual.

We can also strip the binaries when using StaticX. The parameter for it is:

$ cd dist/
$ staticx --strip rastgele rastgele_app
If you copy the previous version as /r1 and the current as /r2, you can see the size difference:

$ ls -l /r1 /r2
-rwxr-xr-x 1 root root 8499512 May 15 17:03 /r1
-rwxr-xr-x 1 root root 8005856 May 15 17:04 /r2
It is like 0.5MB is on our side now, (hopefully) without losing any functionality. Let’s build and run it:

$ docker build -t guray/pystatic-tut:1.2 .
$ docker run -it --rm guray/pystatic-tut:1.2
[2020-05-15 17:06:36 +0000] [7] [INFO] Starting gunicorn 19.7.1
[2020-05-15 17:06:36 +0000] [7] [INFO] Listening at: http://0.0.0.0:8000 (7)
[2020-05-15 17:06:36 +0000] [7] [INFO] Using worker: sync
[2020-05-15 17:06:36 +0000] [13] [INFO] Booting worker with pid: 13
[2020-05-15 17:06:36 +0000] [14] [INFO] Booting worker with pid: 14
[2020-05-15 17:06:36 +0000] [15] [INFO] Booting worker with pid: 15
[2020-05-15 17:06:37 +0000] [16] [INFO] Booting worker with pid: 16
And the image is now 8.01MB:

docker image ls guray/pystatic-tut
REPOSITORY           TAG                 IMAGE ID            CREATED             SIZE
guray/pystatic-tut   1.2                 58a915bf1a36        40 seconds ago      8.01MB
guray/pystatic-tut   1.1                 4fc7ab2d0d23        8 minutes ago       8.5MB
If you need further optimization, you can install upx; then ,if it is in the path or its path is provided, pyinstaller will use it to compress your package further. For our case, there is no gain to use it, since our package consists of compiled binaries. But still it is worth trying.

Conclusion
Again, it is like a blackhole. It is clear that there are a lot of other possibilities that will reduce the image size. If you have ideas about them, please share them in the comments. We will be happy to try them and update the story with the results.

