changing python version in docker
Asked 3 months ago
Modified 3 months ago
Viewed 628 times
0

I am trying to have this repo on docker: https://github.com/facebookresearch/detectron2/tree/main/docker

but when I want to docker compose it, I receive this error:

ERROR: Package 'detectron2' requires a different Python: 3.6.9 not in '>=3.7'

The default version of the python I am using is 3.10 but I don't know why through docker it's trying to run it on python 3.6.9.

Is there a way for me to change it to a higher version of python while running the following dockerfile?

FROM nvidia/cuda:11.1.1-cudnn8-devel-ubuntu18.04
# use an older system (18.04) to avoid opencv incompatibility (issue#3524)

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y \
    python3-opencv ca-certificates python3-dev git wget sudo ninja-build
RUN ln -sv /usr/bin/python3 /usr/bin/python

# create a non-root user
ARG USER_ID=1000
RUN useradd -m --no-log-init --system  --uid ${USER_ID} appuser -g sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER appuser
WORKDIR /home/appuser

ENV PATH="/home/appuser/.local/bin:${PATH}"
RUN wget https://bootstrap.pypa.io/pip/3.6/get-pip.py && \
    python3 get-pip.py --user && \
    rm get-pip.py

# install dependencies
# See https://pytorch.org/ for other options if you use a different version of CUDA
RUN pip install --user tensorboard cmake   # cmake from apt-get is too old
RUN pip install --user torch==1.10 torchvision==0.11.1 -f https://download.pytorch.org/whl/cu111/torch_stable.html

RUN pip install --user 'git+https://github.com/facebookresearch/fvcore'
# install detectron2
RUN git clone https://github.com/facebookresearch/detectron2 detectron2_repo
# set FORCE_CUDA because during `docker build` cuda is not accessible
ENV FORCE_CUDA="1"
# This will by default build detectron2 for all common cuda architectures and take a lot more time,
# because inside `docker build`, there is no way to tell which architecture will be used.
ARG TORCH_CUDA_ARCH_LIST="Kepler;Kepler+Tesla;Maxwell;Maxwell+Tegra;Pascal;Volta;Turing"
ENV TORCH_CUDA_ARCH_LIST="${TORCH_CUDA_ARCH_LIST}"

RUN pip install --user -e detectron2_repo

# Set a fixed model cache directory.
ENV FVCORE_CACHE="/tmp"
WORKDIR /home/appuser/detectron2_repo

# run detectron2 under user "appuser":
# wget http://images.cocodataset.org/val2017/000000439715.jpg -O input.jpg
# python3 demo/demo.py  \
    #--config-file configs/COCO-InstanceSegmentation/mask_rcnn_R_50_FPN_3x.yaml \
    #--input input.jpg --output outputs/ \
    #--opts MODEL.WEIGHTS detectron2://COCO-InstanceSegmentation/mask_rcnn_R_50_FPN_3x/137849600/model_final_f10217.pkl

    pythondocker

Share
Improve this question
Follow
asked Jun 21 at 14:57
amd's user avatar
amd
344 bronze badges
Add a comment
2 Answers
Sorted by:
0

This is an open issue with facebookresearch/detectron2. The developers updated the base Python requirement from 3.6+ to 3.7+ with commit 5934a14 last week but didn't modify the Dockerfile.

I've created a Dockerfile based on Nvidia CUDA's CentOS8 image (rather than Ubuntu) that should work.

FROM nvidia/cuda:11.1.1-cudnn8-devel-centos8

RUN cd /etc/yum.repos.d/ && \
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-* && \
    dnf check-update; dnf install -y ca-certificates python38 python38-devel git sudo which gcc-c++ mesa-libGL && \
    dnf clean all

RUN alternatives --set python /usr/bin/python3 && alternatives --install /usr/bin/pip pip /usr/bin/pip3 1

# create a non-root user
ARG USER_ID=1000
RUN useradd -m --no-log-init --system  --uid ${USER_ID} appuser -g wheel
RUN echo '%wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER appuser
WORKDIR /home/appuser

ENV PATH="/home/appuser/.local/bin:${PATH}"

# install dependencies
# See https://pytorch.org/ for other options if you use a different version of CUDA
ARG CXX="g++"
RUN pip install --user tensorboard ninja cmake opencv-python opencv-contrib-python  # cmake from apt-get is too old
RUN pip install --user torch==1.10 torchvision==0.11.1 -f https://download.pytorch.org/whl/cu111/torch_stable.html

RUN pip install --user 'git+https://github.com/facebookresearch/fvcore'
# install detectron2
RUN git clone https://github.com/facebookresearch/detectron2 detectron2_repo
# set FORCE_CUDA because during `docker build` cuda is not accessible
ENV FORCE_CUDA="1"
# This will by default build detectron2 for all common cuda architectures and take a lot more time,
# because inside `docker build`, there is no way to tell which architecture will be used.
ARG TORCH_CUDA_ARCH_LIST="Kepler;Kepler+Tesla;Maxwell;Maxwell+Tegra;Pascal;Volta;Turing"
ENV TORCH_CUDA_ARCH_LIST="${TORCH_CUDA_ARCH_LIST}"

RUN pip install --user -e detectron2_repo

# Set a fixed model cache directory.
ENV FVCORE_CACHE="/tmp"
WORKDIR /home/appuser/detectron2_repo

# run detectron2 under user "appuser":
# curl -o input.jpg http://images.cocodataset.org/val2017/000000439715.jpg
# python3 demo/demo.py  \
    #--config-file configs/COCO-InstanceSegmentation/mask_rcnn_R_50_FPN_3x.yaml \
    #--input input.jpg --output outputs/ \
    #--opts MODEL.WEIGHTS detectron2://COCO-InstanceSegmentation/mask_rcnn_R_50_FPN_3x/137849600/model_final_f10217.pkl

Alternatively, this is untested as the following images don't work on my machine (because I run arm64) so I can't debug...

In the original Dockerfile, changing your FROM line to this might resolve it, but I haven't verified this (and the image mentioned in the issue (pytorch/pytorch:1.10.0-cuda11.3-cudnn8-devel) might work as well.

FROM nvidia/cuda:11.1.1-cudnn8-devel-ubuntu20.04

Share
Improve this answer
Follow
edited Jun 22 at 17:55
answered Jun 21 at 15:08
wkl's user avatar
wkl
74.6k1616 gold badges160160 silver badges175175 bronze badges

    Thanks but it didn't work! Different error message: ERROR: Exception: Traceback (most recent call last): File "/home/appuser/.local/lib/python3.8/site-packages/pip/_internal/cli/base_command.py", line 164, in exc_logging_wrapper status = run_func(*args) File "/home/appuser/.local/lib/python3.8/site-packages/pip/_internal/cli/req_command.py", line 205, in wrapper return func(self, options, args) File "/home/appuser/.local/lib/python3.8/site-packages/pip/_internal/commands/install.py", line 338, in run requirement_set = resolver.resolve( – 
    amd
    Jun 21 at 16:35
    @amd Sorry for delay - I had to spend time writing a new Dockerfile (which I will put up for PR on Github) which is based on the CUDA CentOS8 image (rather than Ubuntu). I tested it and it should work, and if you have problems I'll be in a better position to debug. I couldn't test your problem with the ubuntu20.04 image because it's only built for amd64, but I use an arm64 computer. – 
    wkl
    Jun 22 at 17:38
    Thanks! I copied your code on detectron repo to see if it works for me or not. It seems like it's not compatible with my system. I receive this error: – 
    amd
    Jun 22 at 18:51
    failed to copy: httpReadSeeker: failed open: failed to authorize: no active session for po60e9ugfjo33sgo7nkxauoo0: context deadline exceeded Service 'detectron2' failed to build : Build failed – 
    amd
    Jun 22 at 18:51
    @amd Interesting - this doesn't seem to be a compatibility issue (the CentOS image I use is available for both x86 and arm machines), but it looks like your docker build seems to be taking too long and it's being killed. Can you docker pull nvidia/cuda:11.1.1-cudnn8-devel-centos8 without any issue? It is a rather large image. – 
    wkl
    Jun 22 at 19:07

Show 1 more comment
-1

You can use pyenv: https://github.com/pyenv/pyenv

Just google docker pyenv container, will give you some entries like: https://gist.github.com/jprjr/7667947

If you follow the gist you can see how it has been updated, very easy to update to latest python that pyenv support. anything since 2.2 to 3.11

Only drawback is that container becomes quite large because it holds all glibc development tools and libraries to compile cpython, but often it helps in case you need modules without wheels and need to compile because it is already there.

Below is a minimal Pyenv Dockerfile Just change the PYTHONVER or set a --build-arg to anything pythonversion pyenv support have (pyenv install -l):

FROM ubuntu:22.04
ARG MYHOME=/root
ENV MYHOME ${MYHOME}
ARG PYTHONVER=3.10.5
ENV PYTHONVER ${PYTHONVER}
ARG PYTHONNAME=base
ENV PYTHONNAME ${PYTHONNAME}
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y locales wget git curl zip vim apt-transport-https tzdata language-pack-nb language-pack-nb-base manpages \
    build-essential libjpeg-dev libssl-dev xvfb zlib1g-dev libbz2-dev libreadline-dev libreadline6-dev libsqlite3-dev tk-dev libffi-dev libpng-dev libfreetype6-dev \
    libx11-dev libxtst-dev libfontconfig1 lzma lzma-dev

RUN git clone https://github.com/pyenv/pyenv.git ${MYHOME}/.pyenv && \
    git clone https://github.com/yyuu/pyenv-virtualenv.git ${MYHOME}/.pyenv/plugins/pyenv-virtualenv && \
    git clone https://github.com/pyenv/pyenv-update.git ${MYHOME}/.pyenv/plugins/pyenv-update

SHELL ["/bin/bash", "-c", "-l"]

COPY ./.bash_profile  /tmp/
RUN cat /tmp/.bash_profile >> ${MYHOME}/.bashrc && \
    cat /tmp/.bash_profile >> ${MYHOME}/.bash_profile && \
    rm -f /tmp/.bash_profile && \
    source ${MYHOME}/.bash_profile && \
    pyenv install ${PYTHONVER} && \
    pyenv virtualenv ${PYTHONVER} ${PYTHONNAME} && \
    pyenv global ${PYTHONNAME}

and the pyenv config to be saved as .bash_profile in Dockerfile directory:

# profile for pyenv
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv init --path)"
eval "$(pyenv virtualenv-init -)"

build with: docker build -t pyenv:3.10.5 .

Will build the image, but as said it is quite big:

docker images
REPOSITORY  TAG     IMAGE ID       CREATED         SIZE
pyenv       3.10.5  64a4b91364d4   2 minutes ago   1.04GB

very easy to test any python version only changing PYTHONVER

docker run -ti pyenv:3.10.5 /bin/bash
(base) root@968fd2178c8a:/# python --version
Python 3.10.5
(base) root@968fd2178c8a:/# which python
/root/.pyenv/shims/python

if I build with docker build -t pyenv:3.12-dev --build-arg PYTHONVER=3.12.dev . or change the PYTHONVER in the Dockerfile:

docker run -ti pyenv:3.12-dev /bin/bash
(base) root@c7245ea9f52e:/# python --version
Python 3.12.0a0

Share
Improve this answer
Follow
edited Jun 22 at 10:57
answered Jun 21 at 15:08
MortenB's user avatar
MortenB
2,1262323 silver badges3232 bronze badges

    Can you give more details on how this would be used? Answers that are just links are routinely deleted. (In general, version-manager tools like pyenv are a little tricky to use in Docker. Since most paths to running containers don't involve shell dotfiles, you wind up repeating the "bring in the version-manager environment" step over and over.) – 
    David Maze
    Jun 21 at 15:50

