

# 🐳 Docker + 🏗️ Crane Cheat Sheet ( mostly to win an argument ) 

**Date:** 2025-07-07
**Docs:**

* [Docker Overview](https://docs.docker.com/engine/docker-overview/#docker-objects)
* [Dockerfile Reference](https://docs.docker.com/engine/reference/builder/)
* [Crane Docs (go-containerregistry)](https://github.com/google/go-containerregistry/tree/main/cmd/crane)

---

## 🔍 Listing

| Task                    | Docker Command      | Crane Equivalent     |
| ----------------------- | ------------------- | -------------------- |
| List images             | `docker images`     | ❌ *(Not applicable)* |
| List containers         | `docker ps -a`      | ❌                    |
| List volumes            | `docker volume ls`  | ❌                    |
| List networks           | `docker network ls` | ❌                    |
| List Compose containers | `docker-compose ps` | ❌                    |

---

## 🗑️ Removing

| Task                                        | Docker Command                    | Crane Equivalent                      |
| ------------------------------------------- | --------------------------------- | ------------------------------------- |
| Remove container                            | `docker rm my_container`          | ❌                                     |
| Prune stopped containers                    | `docker container prune`          | ❌                                     |
| Remove image                                | `docker rmi my-image`             | `crane delete my-image` *(if remote)* |
| Prune dangling images                       | `docker image prune`              | ❌                                     |
| Remove all images                           | `docker image prune -a`           | ❌                                     |
| Remove volume                               | `docker volume rm my_volume`      | ❌                                     |
| Prune all volumes                           | `docker volume prune`             | ❌                                     |
| Remove all build cache                      | `docker builder prune -a`         | ❌                                     |
| Prune system (containers, networks, images) | `docker system prune`             | ❌                                     |
| Reset Docker                                | Docker GUI → Troubleshoot → Reset | ❌                                     |
| Stop & remove Compose                       | `docker-compose down`             | ❌                                     |

---

## 📥 Pulling Images

| Task       | Docker Command         | Crane Equivalent                   |
| ---------- | ---------------------- | ---------------------------------- |
| Pull image | `docker pull my-image` | `crane pull my-image my-image.tar` |

---

## 📤 Publishing Images

| Task              | Docker Command                | Crane Equivalent                          |
| ----------------- | ----------------------------- | ----------------------------------------- |
| Login to registry | `docker login`                | ❌ *(use `gcloud auth` or pre-auth Crane)* |
| Tag image         | `docker tag img usr/repo:tag` | `crane tag usr/repo oldtag newtag`        |
| Push image        | `docker push usr/repo:tag`    | `crane push my-image.tar usr/repo:tag`    |

---

## 🛠️ Building Images

| Task                         | Docker Command                                 | Crane Equivalent                       |
| ---------------------------- | ---------------------------------------------- | -------------------------------------- |
| Build image                  | `docker build -t my-image .`                   | ❌ *(use `ko`, `buildah`, or `docker`)* |
| Build with custom Dockerfile | `docker build -f Dockerfile-alt -t my-image .` | ❌                                      |
| Compose build all            | `docker-compose build`                         | ❌                                      |
| Compose build service        | `docker-compose build my_service`              | ❌                                      |

---

## 📦 Creating Containers

| Task                     | Docker Command                 | Crane Equivalent |
| ------------------------ | ------------------------------ | ---------------- |
| Create container         | `docker create my-image`       | ❌                |
| Compose up without start | `docker-compose up --no-start` | ❌                |

---

## ▶️ Starting & Stopping

| Task            | Docker Command              | Crane Equivalent |
| --------------- | --------------------------- | ---------------- |
| Start container | `docker start my_container` | ❌                |
| Stop container  | `docker stop my_container`  | ❌                |
| Compose start   | `docker-compose start`      | ❌                |
| Compose stop    | `docker-compose stop`       | ❌                |

---

## 🏃 Running Containers

| Task                      | Docker Command                               | Crane Equivalent |
| ------------------------- | -------------------------------------------- | ---------------- |
| Run image                 | `docker run my-image`                        | ❌                |
| Run with command          | `docker run my-image echo "hello"`           | ❌                |
| Run in background         | `docker run -d my-image`                     | ❌                |
| Auto-remove               | `docker run --rm my-image`                   | ❌                |
| Named container           | `docker run --name my_container my-image`    | ❌                |
| With env var              | `docker run --env MY_VAR=val my-image`       | ❌                |
| Compose up                | `docker-compose up`                          | ❌                |
| Compose up in background  | `docker-compose up -d`                       | ❌                |
| Compose up with rebuild   | `docker-compose up --build`                  | ❌                |
| Compose run with override | `docker-compose run my_service echo "hello"` | ❌                |

---

## 💾 Volumes

| Task                      | Docker Command                             | Crane Equivalent |
| ------------------------- | ------------------------------------------ | ---------------- |
| Mount volume              | `docker run -v vol:/path img`              | ❌                |
| Copy data between volumes | `docker run -v vol1:/from -v vol2:/to ...` | ❌                |

---

## 🌐 Ports & Networking

| Task                      | Docker Command                             | Crane Equivalent |
| ------------------------- | ------------------------------------------ | ---------------- |
| Map ports                 | `docker run -p 9090:80 img`                | ❌                |
| Ping host.docker.internal | `docker run img ping host.docker.internal` | ❌                |
| Create network            | `docker network create my_net`             | ❌                |
| Use network               | `docker run --network=my_net img`          | ❌                |

---

## 🧑‍💻 Interacting with Containers

| Task                     | Docker Command                        | Crane Equivalent |
| ------------------------ | ------------------------------------- | ---------------- |
| Bash into container      | `docker exec -it my_container bash`   | ❌                |
| View logs                | `docker logs -f my_container`         | ❌                |
| Copy file into container | `docker cp file.txt container:/tmp/`  | ❌                |
| Bash via Compose         | `docker-compose exec my_service bash` | ❌                |
| Logs via Compose         | `docker-compose logs -f`              | ❌                |

---

## 📊 Getting Information

| Task                   | Docker Command              | Crane Equivalent                       |
| ---------------------- | --------------------------- | -------------------------------------- |
| Docker version         | `docker version`            | ❌                                      |
| Image history          | `docker history my-image`   | ❌                                      |
| Container stats        | `docker stats my_container` | ❌                                      |
| File changes           | `docker diff my_container`  | ❌                                      |
| Processes in container | `docker top my_container`   | ❌                                      |
| Inspect object         | `docker inspect my-image`   | `crane manifest my-image` (image only) |
| Compose processes      | `docker-compose top`        | ❌                                      |

---

## 🧠 Bonus Crane Tips

| Task                         | Crane Command                                           |
| ---------------------------- | ------------------------------------------------------- |
| Get image digest             | `crane digest my-image`                                 |
| Get raw manifest             | `crane manifest my-image`                               |
| Get image config             | `crane config my-image`                                 |
| Copy image across registries | `crane cp us-docker.pkg.dev/foo/image gcr.io/bar/image` |
| Append layer to image        | `crane append --base my-image --layer my-layer.tar`     |

