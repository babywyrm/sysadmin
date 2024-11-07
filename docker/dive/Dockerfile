FROM alpine:3.18

ARG DOCKER_CLI_VERSION=${DOCKER_CLI_VERSION}
RUN wget -O- https://download.docker.com/linux/static/stable/$(uname -m)/docker-${DOCKER_CLI_VERSION}.tgz | \
    tar -xzf - docker/docker --strip-component=1 && \
    mv docker /usr/local/bin

COPY dive /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/dive"]


FROM ubuntu
ARG build_license \
 postgres_db_string
ENV build_license=$build_license \
 postgres_db_string=$postgres_db_string
COPY . .
CMD echo "secret_sauce: $secret_sauce" \
 && echo "build_license: $build_license" \
 && echo "postgres_db_string: $postgres_db_string"
 

 ##
 ## https://medium.com/@kacey.gam/dive-into-docker-part-4-inspecting-docker-image-layers-9a6c9ab859fc
 ##
