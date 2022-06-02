## Connect services with docker-compose at multirepo project

Sometimes you have a project with different services (or microservices) and each one of them has its own repository. At those cases, tests the whole project (and its interactions) can be challenging.

With [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) you can run easily each service from its repo, but for making them to see each other you (usually) need to manually create a network with Docker, assume so facts (as directories names) or do some crazy network configurations.

## TL;DR

You have the final configuration [here](#summary).

## The context

I found myself with a project like this and I guessed that it should exist a simpler way to do it. So this is what I came up with.

Suppose you have a project with this structure:
```
big-project/
├── backend
│   └── docker-compose.yml
└── frontend
    └── docker-compose.yml
```

Actually, you have some code for each repo/component, but I leave just the compose files for clarity.

The project **big-project** is composed by two components:
*  **backend**
*  **frontend**

And these are its docker compose files:

**Backend**
```
version: "3"
services:
  backend:
    image: alpine
    command: /bin/sh -c "while true; do sleep 1000; done"
```

**Frontend**
```
version: "3"
services:
  frontend:
    image: alpine
    command: /bin/sh -c "while true; do sleep 1000; done"
```

**NOTE**: The loop at the command is to have the container running and be able to simulate a running service. Also, to be able to connect with them to test the connectivity, we'll see that later. 

You have to keep in mind that the name of those directories might change (misspelling, moving directories, etc), so you can't rely on them for naming your services on Docker or from your app.

This is important because `docker-compose` uses the directory name as **project name** by default, but if it changes, it can be messy.

For example, if I start the services from both repos Docker will create the services with these names:

At the **backend**:
```
big-project/backend$ docker-compose up -d
Creating network "backend_default" with the default driver
Creating backend_backend_1 ... 
Creating backend_backend_1 ... done
```

At the **frontend**:
```
big-project/frontend$ docker-compose up -d
Creating network "frontend_default" with the default driver
Creating frontend_frontend_1 ... 
Creating frontend_frontend_1 ... done
```

I can see them from Docker:
```
$ docker ps 
CONTAINER ID       IMAGE       COMMAND                  CREATED           STATUS           PORTS        NAMES
ff5379d9e6fd       alpine      "/bin/sh -c 'while t…"   8 minutes ago     Up 8 minutes                  backend_backend_1
5a7fe942bb96       alpine      "/bin/sh -c 'while t…"   8 minutes ago     Up 8 minutes                  frontend_frontend_1
```

As you can see, Docker create **prefix** (`backend_` and `frontend_`) and **suffix** (`_1`) to your services, so they are unique at your system, to avoid collisions. This is because Docker has it own `hostname` system to be able to use the name of the containers instead of rely on fixed IPs.

So, **it's preferable to use the name of the services than complicated network rules and fixed IPs**.

## The problem

Docker is very smart on managing the containers, network and namespaces, but in this case it is a problem for us. The networks are named different, but also they are isolated, so you can't connect from one to another or use the services names:

```
big-project/frontend$ docker-compose exec frontend sh
/ # ping frontend
PING frontend (172.21.0.2): 56 data bytes
64 bytes from 172.21.0.2: seq=0 ttl=64 time=0.091 ms
64 bytes from 172.21.0.2: seq=1 ttl=64 time=0.102 ms
^C
--- frontend ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max = 0.091/0.096/0.102 ms
/ # ping backend
ping: bad address 'backend'
/ # ping backend_backend_1
ping: bad address 'backend_backend_1'

```


## The solution

To solve this problem I'm going to use some features from `docker-compose`:
* The [network configuration](https://docs.docker.com/compose/compose-file/#network-configuration-reference).
* The `container_name` configuration ([reference](https://docs.docker.com/compose/compose-file/#container_name)).
* The environment variable `COMPOSE_PROJECT_NAME` ([reference](https://docs.docker.com/compose/reference/envvars/#compose_project_name)).
* The `.env` file ([reference](https://docs.docker.com/compose/environment-variables/#the-env-file)).

**NOTE:** Before the next steps, let's stop and destroy all the services and networks created before:

**Backend**
```
big-project/backend$ docker-compose down
Stopping backend_backend_1 ... done
Removing backend_backend_1 ... done
Removing network backend_default
```

**Frontend**
```
big-project/frontend$ docker-compose down
Stopping frontend_frontend_1 ... done
Removing frontend_frontend_1 ... done
Removing network frontend_default
```


### The network configuration

Let's add some basic network configuration to the `docker-compose` file:

**Backend**:
```
version: "3"
services:
  backend:
    image: alpine
    command: /bin/sh -c "while true; do sleep 1000; done"
    networks:
      dev:
   
networks:
  dev:
```

**Frontend**:
```
version: "3"
services:
  frontend:
    image: alpine
    command: /bin/sh -c "while true; do sleep 1000; done"
    networks:
      dev:
   
networks:
  dev:
```

Now, let's get all the services up and see what we have:

**Backend**
```
big-project/backend$ docker-compose up -d
Creating network "backend_dev" with the default driver
Creating backend_backend_1 ... 
Creating backend_backend_1 ... done
```

### Container names

Docker has created named network for our projects, but if you closely, you'll see that we're going to have still two issues:
* The network names are still different.
* The container names have autogenerated prefix and suffix that make them unpredictable.

To avoid the container random names we just need to set the `container_name` tag at the configuration file:
```
some_service:
  image: some_image
  container_name: service_name
```

Let's see the files updated:

**Backend**
```
version: "3"
services:
  backend:
    image: alpine
    container_name: backend
    command: /bin/sh -c "while true; do sleep 1000; done"
    networks:
      dev:

networks:
  dev:
```

**Frontend**
```
version: "3"
services:
  frontend:
    image: alpine
    container_name: frontend
    command: /bin/sh -c "while true; do sleep 1000; done"
    networks:
      dev:

networks:
  dev:
```

Now let's get the services up:

**Backend**
```
big-project/backend$ docker-compose up -d
Creating network "backend_dev" with the default driver
Creating backend ... 
Creating backend ... done
```

**Frontend**
``` 
big-project/frontend$ docker-compose up -d
Creating network "frontend_dev" with the default driver
Creating frontend ... 
Creating frontend ... done
```

Now we have predictable service names across all the repos. Let's fix now the network

### Project name and network name

To fix the issue with the network prefix and to get all the services inside the same network, so they can see each other, let's use the environment variable `COMPOSE_PROJECT_NAME`.

As I said before, the prefix comes from the project name. If the variable `COMPOSE_PROJECT_NAME` is empty, `docker-compose` will use the name of the directory where the `docker-compose.yml` lives.
If we want to change that name we can do it by doing:

```
big-project/frontend$ COMPOSE_PROJECT_NAME=super-project-x docker-compose up -d
Creating network "superprojectx_dev" with the default driver
Creating frontend ... 
Creating frontend ... done
```

**NOTE:** To stop the services and network you need to pass the same variable or it will fail.
```
$ COMPOSE_PROJECT_NAME=super-project-x docker-compose down
```

Or
```
big-project/frontend$ docker-compose --project-name supes-project-z up -d
Creating network "supesprojectz_dev" with the default driver
Creating frontend ... 
Creating frontend ... done
```

**NOTE:** As with the previous case, we need to pass the project name also to stop the services and network:
```
$ docker-compose --project-name supes-project-z down
```

Either way you have now the container at the same network, and they see each other:


### ENV file to avoid manual steps

The previous methods are fine, but every manual step can be misspelled or forgotten, so let's find a way to automate this and make it easier.
The best solution that I found is to use a `.env` file at the same directory that the `docker-compose-yml`. There we can define the variable `COMPOSE_PROJECT_NAME` and it will be usad for all the commands (`up`, `down`, `exec`, `run` etc).

The file will be at the root of our two repositories (`frontend` and `backend`) so both components share the same project name:
```
big-project$ cat frontend/.env 
COMPOSE_PROJECT_NAME=multirepo
big-project$ cat backend/.env 
COMPOSE_PROJECT_NAME=multirepo
```

Now we can launch all the services and check the setup:
**Backend**
```
big-project/backend$ docker-compose up -d
Creating network "multirepo_dev" with the default driver
Creating backend ... 
Creating backend ... done
```

**Frontend**
```
big-project/frontend$ docker-compose up -d
WARNING: Found orphan containers (backend) for this project. If you removed or renamed this service in your compose file, you can run this command with the --remove-orphans flag to clean it up.
Creating frontend ... 
Creating frontend ... done
```

**NOTE:** The warning is ok. That is because we have one container at that network (`multirepo_dev`) that is not defined at that specific `docker-compose.yml`. That's because it was launched by the other docker compose, from the other repo.

Now let's check if the services can see each other:
```
big-project/frontend$ docker-compose exec frontend sh

/ # ping frontend
PING frontend (192.168.0.3): 56 data bytes
64 bytes from 192.168.0.3: seq=0 ttl=64 time=0.033 ms
64 bytes from 192.168.0.3: seq=1 ttl=64 time=0.075 ms
^C
--- frontend ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max = 0.033/0.054/0.075 ms

/ # ping backend
PING backend (192.168.0.2): 56 data bytes
64 bytes from 192.168.0.2: seq=0 ttl=64 time=0.285 ms
64 bytes from 192.168.0.2: seq=1 ttl=64 time=0.134 ms
^C
--- backend ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max = 0.134/0.209/0.285 ms
```

Yes, from the container `frontend` I can ping the container `backend` by name.

We can make it more complex adding more services, more repos, specific ports etc. But the basic network communication between components (from different repos/directories) is already in place.


## Summary

This is the requirement we have:
* Two services (`frontend` and `backend`) that live at different repositories and have their own `docker-compose.yml` to test or develop locally.
* We need those services to talk to each other.
* We want to avoid manual steps and the simplest configuration.

Final project structure:
```
big-project/
├── backend
│   ├── docker-compose.yml
│   └── .env
└── frontend
    ├── docker-compose.yml
    └── .env
```

Both repos have the same variable defined at `.env`:
```
COMPOSE_PROJECT_NAME=multirepo
```

And those are the docker files:

**Backend** `docker-compose.yml`
```
version: "3"
services:
  backend:
    image: alpine
    container_name: backend
    command: /bin/sh -c "while true; do sleep 1000; done"
    networks:
      dev:

networks:
  dev:
```

**Frontend** `docker-compose.yml`
```
version: "3"
services:
  frontend:
    image: alpine
    container_name: frontend
    command: /bin/sh -c "while true; do sleep 1000; done"
    networks:
      dev:

networks:
  dev:
```

Now we can launch both configurations (`docker-compose up -d`) and all the services will see each other.
