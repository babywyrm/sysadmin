
$ docker run -it --rm --name=pydev -h pydev -v ${PWD}:/data registry.gitlab.com/python-devs/ci-images:latest

runner@pydev:~$ ls /usr/local/bin/python*
/usr/local/bin/python-argcomplete-check-easy-install-script  /usr/local/bin/python3.12         /usr/local/bin/python3.7
/usr/local/bin/python-argcomplete-tcsh                       /usr/local/bin/python3.12-config  /usr/local/bin/python3.7m
/usr/local/bin/python2.7                                     /usr/local/bin/python3.5          /usr/local/bin/python3.7m-config
/usr/local/bin/python2.7-config                              /usr/local/bin/python3.5m         /usr/local/bin/python3.8
/usr/local/bin/python3.10                                    /usr/local/bin/python3.5m-config  /usr/local/bin/python3.8-config
/usr/local/bin/python3.10-config                             /usr/local/bin/python3.6          /usr/local/bin/python3.9
/usr/local/bin/python3.11                                    /usr/local/bin/python3.6m         /usr/local/bin/python3.9-config
/usr/local/bin/python3.11-config                             /usr/local/bin/python3.6m-config

#############
#############

# [Choice] Python version: 3, 3.8, 3.7, 3.6
ARG VARIANT=3.9
FROM mcr.microsoft.com/vscode/devcontainers/python:0-${VARIANT}

ENV PYTHONUNBUFFERED 1

# Update args in docker-compose.yaml to set the UID/GID of the "vscode" user.
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN if [ "$USER_GID" != "1000" ] || [ "$USER_UID" != "1000" ]; then groupmod --gid $USER_GID vscode && usermod --uid $USER_UID --gid $USER_GID vscode; fi

# [Option] Install Node.js
ARG INSTALL_NODE="true"
ARG NODE_VERSION="lts/*"
RUN if [ "${INSTALL_NODE}" = "true" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

# [Optional] If your requirements rarely change, uncomment this section to add them to the image.
# COPY requirements.txt /tmp/pip-tmp/
# RUN pip3 --disable-pip-version-check --no-cache-dir install -r /tmp/pip-tmp/requirements.txt \
#    && rm -rf /tmp/pip-tmp

# [Optional] Uncomment this section to install additional OS packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>

# Poetry is the Python package / venv manager of choice. One of its dependencies is
# partially implemented in Rust, so we need to install Rust in order to install Poetry.
ARG POETRY_VERSION="1.1.0"
RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y rustc && \
    pip install "poetry==${POETRY_VERSION}" && \
    python -m venv /usr/local/py-utils/venvs/coquus && \
    chown -R vscode /usr/local/py-utils/venvs/coquus
COPY .devcontainer/pypoetry_config.toml /home/vscode/.config/pypoetry/config.toml

#############
#############
