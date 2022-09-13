The Fargate/Terraform tutorial I wish I had

#
##
##
https://section411.com/2019/07/hello-world/
##
##
#

By Jimmy Sawczuk
By Jimmy Sawczuk
Published 3 years ago · Updated 9 months ago · 31 min. read

Henrique Dias, Unsplash

In my last way-too-long, way-too-technical, seriously-nobody-cares technical post, I wrote about serverless functions. The main benefit of serverless functions, I wrote, is that you can deploy code to production without having to worry about keeping a server online, secure, and up-to-date. But a secondary benefit of serverless function is also its main trade-off: they’re just functions. Computer scientists might call them pure functions, because the outputs of serverless functions are usually entirely dependent on their inputs and nothing else. You could also call them stateless, because they don’t retain any artifacts or side effects from any one invocation. (The runtimes from AWS and Google fudge this somewhat, but let’s pretend.) This trade-off makes the code simpler to understand and to debug.

For many cases, as it was for Louvre, the trade of simplicity for state is well worth it. But other times, it’s worth it to have a more stateful system. An API might want to store database connections for reusability, or maintain in-memory caches for speed, or simply maintain a counter for the purpose of rate-limiting. And that’s where AWS Fargate comes in.

Fargate is sort of the best of both worlds. Like its predecessor, it’s a way of launching containers on AWS while maintaining visibility on the container after it launches. But unlike its predecessor, the EC2 launch type, Fargate doesn’t require you to pre-allocate and maintain an instance on which to run your container. With Fargate, you simply get to define your container and launch it.

Or at least that’s the promise. AWS, however, is complicated, and launching a Fargate service using the console is no mean feat. You have to use at least five different AWS services, in a specific order, and that’s not including any databases or other integrations you might want to use. The console never really tells you where to start. It never tells you where to go next. Sometimes the information the console gives to you is just plain wrong. If you mess up, you might be able to fix it. But if not, you might have to start from scratch.

That’s why infrastructure configuration languages like Terraform are so appealing. You simply define your infrastructure once, in code. Then you run a program which uses that configuration to build your infrastructure. If you mess up, or want to try something new, you can simply blow it all up and rest assured that it’s just as easy to recreate it. Best of all, all infrastructure changes can now be peer-reviewed and committed to version control, a requirement in highly-regulated environments and a plus everywhere else.

But the promise of Terraform is a little too good to be true, and that’s because Terraform has to play by the rules of your cloud provider. Terraform will build whatever infrastructure you tell it to, but you still have to know what you want. With AWS, and newer services like Fargate in particular, this isn’t always clear. So while you’ll see a lot of Terraform in this tutorial, this is really a tutorial on how to set up a Fargate service.

Here’s the goal: we’re going to try to spin up a Fargate service, using Terraform and as minimal a configuration as we can get away with. I’ll show the code step by step below, but at the end of this article I’ll provide a link to a Github repository with all of the Terraform necessary to start a Fargate service, with a few minimal changes.

(If you’ve read this far and find yourself wanting to run from the room screaming, thanks for sticking with me for this long! I’ll write about something more interesting next time, I promise.)
The setup

Let’s start with the app. The core building blocks of Fargate services are Docker containers and the whole point of Docker, or containerization in general, is that the host operating system no longer has to care about what sort of app is in the container (and vice versa!). So as a demo, I wrote a quick Go app (natch), but it could easily be a Node app, a Rails app or even just a webserver serving static files (don’t actually do this last one – there are better ways to solve that particular problem).

Here’s our application:



	

// main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi"
)

func main() {
	var err error
	time.Local, err = time.LoadLocation("America/New_York")
	if err != nil {
		panic("timezone not loaded!")
	}

	mux := chi.NewRouter()
	mux.Get("/health", health)
	mux.Get("/", handler)

	log.Println("listening on :3000")
	http.ListenAndServe(":3000", mux)
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok " + time.Now().Format(time.RFC3339)))
}

func handler(w http.ResponseWriter, r *http.Request) {
	lat := r.URL.Query().Get("lat")
	if lat == "" {
		lat = "41.495833"
	}

	lng := r.URL.Query().Get("lng")
	if lng == "" {
		lng = "-81.685278"
	}

	date, _ := time.Parse(time.RFC3339, r.URL.Query().Get("date"))
	if date.IsZero() {
		date = time.Now()
	}

	u := fmt.Sprintf(
		"https://api.sunrise-sunset.org/json?lat=%s&lng=%s&date=%s&formatted=0",
		lat,
		lng,
		date.Format("2006-01-02"),
	)

	log.Println("sending request to", u)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("couldn't make http request"))
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Errorf("http: do: %w", err).Error()))
		return
	}

	var target struct {
		Status  string `json:"status"`
		Results struct {
			Sunrise   time.Time `json:"sunrise"`
			Sunset    time.Time `json:"sunset"`
			SolarNoon time.Time `json:"solar_noon"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&target); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("couldn't decode json"))
		return
	}

	resp.Body.Close()

	out := struct {
		OK        bool   `json:"ok"`
		Date      string `json:"date"`
		Sunrise   string `json:"sunrise"`
		Sunset    string `json:"sunset"`
		SolarNoon string `json:"solar_noon"`
	}{
		OK:        true,
		Date:      date.Format("2006-01-02"),
		Sunrise:   target.Results.Sunrise.In(time.Local).Format("3:04 PM"),
		Sunset:    target.Results.Sunset.In(time.Local).Format("3:04 PM"),
		SolarNoon: target.Results.SolarNoon.In(time.Local).Format("3:04 PM"),
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(out)
}

Hopefully, it’s pretty straightforward. We’re creating an HTTP server and exposing two endpoints on it. One of them is just a health check; the other queries an API for the sunrise and sunset times for a particular location on a particular day. The whole app is less than 100 lines of code, but it’s doing two things that we’d want a typical API to do: listen for requests and act as a gateway to make requests to an upstream service.

Next, in order to deploy it on Fargate, we need to define the Docker container – or Dockerize – our app. Here’s the Dockerfile which makes that happen:

	

# Dockerfile
FROM golang:1.17 AS builder
WORKDIR /app
COPY main.go go.mod go.sum ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o app .

FROM alpine:latest

RUN apk update \
	&& apk add ca-certificates tzdata \
	&& update-ca-certificates \
	&& apk add shadow \
	&& groupadd -r app \
	&& useradd -r -g app -s /sbin/nologin -c "Docker image user" app

USER app
WORKDIR /app

COPY --from=builder /app/app ./app
EXPOSE 3000
CMD ["./app"]

We’re using two stages in this Dockerfile. The first stage, which starts on line 1, builds the application. The second stage, starting on line 7, copies the built application into a slimmer and less permissive environment.

To make things a little easier, I took the liberty of building the Docker image and pushing it to a public Docker repository on Github. This saves us the couple of steps required to create a private repository and push an image to it. The service we’re about to create can just use the image from the public repository.

I promise this isn’t some half-witted attempt to get you to install malicious code in a Docker container in your AWS account. But if you’d prefer to be cautious, you can create the image yourself and upload it to any Docker repository you control. (For simplicity, make sure it’s public for now.) Here’s an example of how to do it on Docker Hub:

    Create a public repository called sun-api on Docker Hub.
    Make sure you’re logged into your Docker account on the CLI by running docker login.
    Grab the two files above and put them in a directory together (not your $GOPATH). Run go mod init; this should create a go.mod file and a go.sum file.
    Run docker build -t <your_docker_username>/sun-api:latest ..
    Run docker push <your_docker_username>/sun-api:latest.

Keep an eye out for when we use this image name later on in the tutorial and replace my image’s URL in the image path with <your_docker_username>/sun-api:latest.

(By the way, creating a private ECR repo to push Docker images to and making your service pull from that repo isn’t hard. The part that’s a bit of a pain is actually pushing your image from your machine to the ECR repo. So I’m opting to skip it. But I’ll give you the Terraform for creating the ECR repo as well, if you want to do that in the future.)

Now that our app is ready to deploy, let’s start writing some Terraform. Add these lines to a file named config.tf in your directory:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23

	

# config.tf
provider "aws" {
  region  = "us-east-1"
  profile = "tfuser"
}

terraform {
  required_version = ">= 1.0"

  backend "s3" {
    bucket  = "terraform"
    key     = "terraform.tfstate"
    region  = "us-east-1"
    profile = "tfuser"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.69.0"
    }
  }
}

Both of the blocks in this file contain a line that says profile = "tfuser". This tells Terraform how to authenticate with your AWS account. You’ll need to set this up manually: under IAM in the AWS Console, select Users in the left hand nav, then find the Add User button (or just click here). The username should be tfuser, and make sure the checkbox labeled “programmatic access” is checked. On the next screen, make sure to add the AdministratorAccess policy.

After creating your user, you should see a screen with an Access Key ID and Secret Access Key. Copy those values into a file named ~/.aws/credentials, with the following format:

1
2
3

	

[tfuser]
aws_access_key_id = <YOUR_ACCESS_KEY_ID>
aws_secret_access_key = <YOUR_SECRET_ACCESS_KEY>

Terraform reads every file ending in .tf in the same directory as part of the same workspace, so we can split up our code into meaningful files. We combined most of our config into one file, but if things ever get more complicated, we can split out this config into a provider.tf, backend.tf and versions.tf, for example.

Our backend block under terraform is telling AWS we’re going to put the state file in an S3 bucket called terraform with a filenamed called terraform.tfstate. You’ll probably need to change the bucket name to something more unique; since S3 bucket names are unique per region, there’s a really good chance someone is using the name terraform. Create a bucket with the name you picked in the S3 console (the default, totally private settings are what you want), then set that as your bucket name in backend.tf.

Next, from the command line and in the same directory as your config.tf file, run terraform init. You should see a success message that looks something like this:



	

$ terraform init

Initializing the backend...

Successfully configured the backend "s3"! Terraform will automatically
use this backend unless the backend configuration changes.

Initializing provider plugins...
- Reusing previous version of hashicorp/aws from the dependency lock file
- Installing hashicorp/aws v3.69.0...
- Installed hashicorp/aws v3.69.0 (signed by HashiCorp)

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.

If that’s what you see, great! If not, make sure your tfuser user has the appropriate AWS permissions and verify that Terraform is installed correctly on your machine (if you run terraform version, you should see something along the lines of Terraform v1.0.5).

You may have also noticed that Terraform created a file called .terraform.lock.hcl in your directory. If you’re using version control, this file is like a package-lock.json or go.sum and is safe to commit.
The service

Our end goal is to create a Fargate ECS service. So let’s start by creating that and see where we get. From the Terraform documentation, it seems like we want to create an aws_ecs_service. Let’s add an aws_ecs_service resource block, with the required fields filled out as well as we can. (Paste this into a new file called ecs.tf.)

1
2
3
4
5

	

# ecs.tf
resource "aws_ecs_service" "sun_api" {
  name            = "sun-api"
  task_definition = ""
}

It turns out there are only two absolutely required fields, so our first iteration is pretty simple. We’re supplying the name of the service, which is arbitrary. We don’t know what the task_definition is yet, so we’ll just use an empty string for now. This is obviously not going to be our final solution, but let’s run a plan and see where we are.

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25

	

$ terraform plan

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_ecs_service.sun_api will be created
  + resource "aws_ecs_service" "sun_api" {
      + cluster                            = (known after apply)
      + deployment_maximum_percent         = 200
      + deployment_minimum_healthy_percent = 100
      + enable_ecs_managed_tags            = false
      + enable_execute_command             = false
      + iam_role                           = (known after apply)
      + id                                 = (known after apply)
      + launch_type                        = (known after apply)
      + name                               = "sun-api"
      + platform_version                   = (known after apply)
      + scheduling_strategy                = "REPLICA"
      + tags_all                           = (known after apply)
      + wait_for_steady_state              = false
    }

Plan: 1 to add, 0 to change, 0 to destroy.

This is just a plan, meaning we haven’t actually made any changes to our AWS environment yet. But it’s always a good idea to inspect the plan output to make sure Terraform is doing what we expect it to do. In this case, the only thing that seems off is the launch_type. Terraform is saying it will be “known after apply,” which means it’ll use whatever AWS defaults to. We want to ensure it’s FARGATE, so let’s add that line:

1
2
3
4
5

	

resource "aws_ecs_service" "sun_api" {
  name            = "sun-api"
  task_definition = ""
+ launch_type     = "FARGATE"
}

And here’s the resulting output:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25

	

$ terraform plan

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_ecs_service.sun_api will be created
  + resource "aws_ecs_service" "sun_api" {
      + cluster                            = (known after apply)
      + deployment_maximum_percent         = 200
      + deployment_minimum_healthy_percent = 100
      + enable_ecs_managed_tags            = false
      + enable_execute_command             = false
      + iam_role                           = (known after apply)
      + id                                 = (known after apply)
      + launch_type                        = "FARGATE"
      + name                               = "sun-api"
      + platform_version                   = (known after apply)
      + scheduling_strategy                = "REPLICA"
      + tags_all                           = (known after apply)
      + wait_for_steady_state              = false
    }

Plan: 1 to add, 0 to change, 0 to destroy.

This seems too easy, but let’s run an apply anyway, just to see what happens:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17

	

$ terraform apply
...
Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_ecs_service.sun_api: Creating...
╷
│ Error: error creating sun-api service: error waiting for ECS service (sun-api) creation: InvalidParameterException: TaskDefinition can not be blank.
│
│   with aws_ecs_service.sun_api,
│   on ecs.tf line 1, in resource "aws_ecs_service" "sun_api":
│    1: resource "aws_ecs_service" "sun_api" {
│
╵

As we suspected, that config wasn’t all we needed. (We haven’t even specified the image yet!) But it’s a good example of the difference between running terraform plan and terraform apply. terraform plan validates your config to make sure the syntax is valid, that any variables being referenced are defined, and that the required fields are populated. Even though a plan might be valid, however, Terraform doesn’t have much of an idea what AWS will say when it tries to execute the plan.

In this case, aws_ecs_service documentation specifies that TaskDefinition should be: “The family and revision (family:revision) or full ARN of the task definition that you want to run in your service.” It’s a good reminder that while Terraform helps us define our infrastructure, it doesn’t guarantee that the infrastructure we define will even run, much less meet best practices.

The good news is this: we know what to fix! Now that we’ve gone through one iteration of the code/plan/apply troubleshooting cycle, I’ll move a little faster. Let’s add these blocks to the ecs.tf file:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44

	

# We'll eventually want a place to put our logs.
resource "aws_cloudwatch_log_group" "sun_api" {
  name = "/ecs/sun-api"
}

# Here's our task definition, which defines the task that will be running to provide
# our service. The idea here is that if the service decides it needs more capacity,
# this task definition provides a perfect blueprint for building an identical container.
#
# If you're using your own image, use the path to your image instead of mine,
# i.e. `<your_dockerhub_username>/sun-api:latest`.
resource "aws_ecs_task_definition" "sun_api" {
  family = "sun-api"

  container_definitions = <<EOF
  [
    {
      "name": "sun-api",
      "image": "ghcr.io/jimmysawczuk/sun-api:latest",
      "portMappings": [
        {
          "containerPort": 3000
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-region": "us-east-1",
          "awslogs-group": "/ecs/sun-api",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
  EOF

  # These are the minimum values for Fargate containers.
  cpu = 256
  memory = 512
  requires_compatibilities = ["FARGATE"]

  # This is required for Fargate containers (more on this later).
  network_mode = "awsvpc"
}

Next, update the task_definition field in our aws_ecs_service block:

1
2
3
4
5
6

	

resource "aws_ecs_service" "sun_api" {
  name            = "sun-api"
- task_definition = ""
+ task_definition = aws_ecs_task_definition.sun_api.arn
  launch_type     = "FARGATE"
}

This is our first example of using a variable to populate another field, and it’s one of Terraform’s most powerful and appealing features. Instead of having to hardcode that ARN into our config, we can simply say: “that task definition I just created, whatever its ARN is, use it here.” If we ever destroy and recreate that task definition, and it gets a new ARN, this config will still work perfectly.

Running terraform apply should give us our first partial success:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21

	

$ terraform apply
...
Plan: 3 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

aws_cloudwatch_log_group.sun_api: Creating...
aws_ecs_task_definition.sun_api: Creating...
aws_cloudwatch_log_group.sun_api: Creation complete after 0s [id=/ecs/sun-api]
╷
│ Error: ClientException: Fargate requires task definition to have execution role ARN to support log driver awslogs.
│
│   with aws_ecs_task_definition.sun_api,
│   on ecs.tf line 17, in resource "aws_ecs_task_definition" "sun_api":
│   17: resource "aws_ecs_task_definition" "sun_api" {
│
╵

A couple things actually got created! Now that we’re in this for real, if you need to tear down everything, you can run terraform destroy. Like apply, it’ll give you a plan output that specifies what it intends to destroy, so make sure you inspect that closely. But Terraform will only touch resources it knows about, so it should only affect resources you’ve created here.

We’re still stuck on that task definition and it’s about to get weird, because it’s time to add some permissions. We need to create a role for the task to use while it’s running, but we have to also explicitly allow our ECS task to assume that role. AWS provides a policy we can use for execution, but we’ll have to attach it to a role we create. Add these lines to ecs.tf:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32

	

# This is the role under which ECS will execute our task. This role becomes more important
# as we add integrations with other AWS services later on.

# The assume_role_policy field works with the following aws_iam_policy_document to allow
# ECS tasks to assume this role we're creating.
resource "aws_iam_role" "sun_api_task_execution_role" {
  name               = "sun-api-task-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json
}

data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# Normally we'd prefer not to hardcode an ARN in our Terraform, but since this is
# an AWS-managed policy, it's okay.
data "aws_iam_policy" "ecs_task_execution_role" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Attach the above policy to the execution role.
resource "aws_iam_role_policy_attachment" "ecs_task_execution_role" {
  role       = aws_iam_role.sun_api_task_execution_role.name
  policy_arn = data.aws_iam_policy.ecs_task_execution_role.arn
}

Here, we’re creating a role that AWS will use to run our app. First, we attach a policy that allows the role to be assumed by ECS tasks (blocks 1 and 2). Then we grab the AWS-defined default policy for ECS task execution and attach it (blocks 3 and 4).

Now we can add this line to our aws_ecs_task_definition resource:



	

# ecs.tf
resource "aws_ecs_task_definition" "sun_api" {
  ...
+ execution_role_arn = aws_iam_role.sun_api_task_execution_role.arn

  cpu = 256
  memory = 512
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
}

If we run terraform apply now, it seems to try for a long time to create the service before finally failing.



	

$ terraform apply
...
aws_iam_role.sun_api_task_execution_role: Creating...
aws_iam_role.sun_api_task_execution_role: Creation complete after 1s [id=sun-api-task-execution-role]
aws_iam_role_policy_attachment.ecs_task_execution_role: Creating...
aws_ecs_task_definition.sun_api: Creating...
aws_ecs_task_definition.sun_api: Creation complete after 0s [id=sun-api]
aws_ecs_service.sun_api: Creating...
aws_iam_role_policy_attachment.ecs_task_execution_role: Creation complete after 1s [id=sun-api-task-execution-role-20210902182501012700000002]
aws_ecs_service.sun_api: Still creating... [10s elapsed]
...
aws_ecs_service.sun_api: Still creating... [3m50s elapsed]
╷
│ Error: error creating sun-api service: ClusterNotFoundException:
│
│   with aws_ecs_service.sun_api,
│   on ecs.tf line 1, in resource "aws_ecs_service" "sun_api":
│    1: resource "aws_ecs_service" "sun_api" {
│
╵

That output suggests that we need a cluster in which to put our service, so let’s create it:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11

	

# ecs.tf
+ resource "aws_ecs_cluster" "app" {
+   name = "app"
+ }

  resource "aws_ecs_service" "sun_api" {
    name            = "sun-api"
    task_definition = aws_ecs_task_definition.sun_api.arn
+   cluster         = aws_ecs_cluster.app.id
    launch_type     = "FARGATE"
 }

After adding those lines, our next terraform plan run should tell us that we’re closing in. We just need to create the cluster and the service. But when we try to apply that, we get the following:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14

	

$ terraform apply
...
aws_ecs_cluster.app: Creating...
aws_ecs_cluster.app: Still creating... [10s elapsed]
aws_ecs_cluster.app: Creation complete after 11s [id=arn:aws:ecs:us-east-1:123456123456:cluster/app]
aws_ecs_service.sun_api: Creating...
╷
│ Error: error creating sun-api service: error waiting for ECS service (sun-api) creation: InvalidParameterException: Network Configuration must be provided when networkMode 'awsvpc' is specified.
│
│   with aws_ecs_service.sun_api,
│   on ecs.tf line 5, in resource "aws_ecs_service" "sun_api":
│    5: resource "aws_ecs_service" "sun_api" {
│
╵

The good news is we’re still making progress. The bad news is we’re about to talk about networking.
Networking

We set our task definition’s network_mode to be awsvpc because that’s what AWS requires for Fargate tasks. Unfortunately, that comes with some other hidden dependencies. Namely, Fargate tasks need to be in a VPC.

Creating the VPC by itself is fairly simple, but it also requires you to define subnets, route tables, NAT gateways and more. So I’ll save you the pain I went through trying to get this stuff working properly, and just give you the config. Open a new file called network.tf and copy these lines into it.


	

# network.tf
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "public_d" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.1.0/25"
  availability_zone = "us-east-1d"

  tags = {
    "Name" = "public | us-east-1d"
  }
}

resource "aws_subnet" "private_d" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.0/25"
  availability_zone = "us-east-1d"

  tags = {
    "Name" = "private | us-east-1d"
  }
}

resource "aws_subnet" "public_e" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.1.128/25"
  availability_zone = "us-east-1e"

  tags = {
    "Name" = "public | us-east-1e"
  }
}

resource "aws_subnet" "private_e" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.128/25"
  availability_zone = "us-east-1e"

  tags = {
    "Name" = "private | us-east-1e"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.app_vpc.id
  tags = {
    "Name" = "public"
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.app_vpc.id
  tags = {
    "Name" = "private"
  }
}

resource "aws_route_table_association" "public_d_subnet" {
  subnet_id      = aws_subnet.public_d.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_d_subnet" {
  subnet_id      = aws_subnet.private_d.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "public_e_subnet" {
  subnet_id      = aws_subnet.public_e.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_e_subnet" {
  subnet_id      = aws_subnet.private_e.id
  route_table_id = aws_route_table.private.id
}

resource "aws_eip" "nat" {
  vpc = true
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.app_vpc.id
}

resource "aws_nat_gateway" "ngw" {
  subnet_id     = aws_subnet.public_d.id
  allocation_id = aws_eip.nat.id

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_route" "public_igw" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route" "private_ngw" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.ngw.id
}

resource "aws_security_group" "http" {
  name        = "http"
  description = "HTTP traffic"
  vpc_id      = aws_vpc.app_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "https" {
  name        = "https"
  description = "HTTPS traffic"
  vpc_id      = aws_vpc.app_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "egress_all" {
  name        = "egress-all"
  description = "Allow all outbound traffic"
  vpc_id      = aws_vpc.app_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ingress_api" {
  name        = "ingress-api"
  description = "Allow ingress to API"
  vpc_id      = aws_vpc.app_vpc.id

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

From a high level, here’s what’s going on. First, we create a VPC. The VPC lets us ensure our services are isolated from the rest of AWS and the world, which is definitely a good thing. But VPCs don’t come with any built-in configuration, so we have to do that ourselves. To our VPC, we add two sets of public and private subnets in two availability zones. This is a best practice that happens to be an AWS requirement: even if one of the availability zones go down, we should still be okay. Next, we define a route table for the public and private subnets and associate them accordingly: our public subnets will be exposed to the Internet via the Internet gateway directly, but we’ll put our private subnets behind a NAT gateway so that it can talk to the Internet but the Internet can’t get in. Finally, we’ll create some security groups so the Internet can reach our ALB, our ALB can reach our service and our service can reach the Internet.

Note that if we were using the console to do these operations, we’d get a couple security groups by default. Terraform removes these, however, so we have to recreate them explicitly. Also, check out those output blocks, which will tell us the VPC and subnet IDs on the command line when they’re created.

After adding that file, we can run terraform apply to create our VPC and various networking pieces. Everything should create successfully, but we’ll still see this error:

1
2
3
4
5
6
7
8

	

╷
│ Error: error creating sun-api service: error waiting for ECS service (sun-api) creation: InvalidParameterException: Network Configuration must be provided when networkMode 'awsvpc' is specified.
│
│   with aws_ecs_service.sun_api,
│   on ecs.tf line 5, in resource "aws_ecs_service" "sun_api":
│    5: resource "aws_ecs_service" "sun_api" {
│
╵

Back in ecs.tf, add this block to your aws_ecs_service block:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17

	

# ecs.tf
resource "aws_ecs_service" "sun_api" {
...
+ network_configuration {
+   assign_public_ip = false

+   security_groups = [
+     aws_security_group.egress_all.id,
+     aws_security_group.ingress_api.id,
+   ]

+   subnets = [
+     aws_subnet.private_d.id,
+     aws_subnet.private_e.id,
+   ]
+ }
}

With any luck, the service should now create successfully when we run terraform apply! We’re not done yet, but this calls for a celebration.
Load balancer

We’re getting really close now. Our service is created and our task is configured; all we need now is a way to let incoming traffic in. We need a load balancer (or ALB, for Application Load Balancer). Let’s add these lines to our ecs.tf file:

	

# ecs.tf
resource "aws_lb_target_group" "sun_api" {
  name        = "sun-api"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.app_vpc.id

  health_check {
    enabled = true
    path    = "/health"
  }

  depends_on = [aws_alb.sun_api]
}

resource "aws_alb" "sun_api" {
  name               = "sun-api-lb"
  internal           = false
  load_balancer_type = "application"

  subnets = [
    aws_subnet.public_d.id,
    aws_subnet.public_e.id,
  ]

  security_groups = [
    aws_security_group.http.id,
    aws_security_group.https.id,
    aws_security_group.egress_all.id,
  ]

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_alb_listener" "sun_api_http" {
  load_balancer_arn = aws_alb.sun_api.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.sun_api.arn
  }
}

output "alb_url" {
  value = "http://${aws_alb.sun_api.dns_name}"
}

This last output block is important because it will tell us what URL we’ll use to reach the service without us having to go into the AWS console to figure it out.

Next, add this block to your aws_ecs_service block:

1
2
3
4
5
6
7
8

	

resource "aws_ecs_service" "sun_api" {
...
+ load_balancer {
+   target_group_arn = aws_lb_target_group.sun_api.arn
+   container_name   = "sun-api"
+   container_port   = "3000"
+ }
}

One more change. By default, the ECS service we created won’t start any containers. We need to tell it how many containers we want.

1
2
3
4
5

	

resource "aws_ecs_service" "sun_api" {
...
+
+ desired_count = 1
}

Finally, run terraform apply one more time. (The ALB may take a bit to spin up.)

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20

	

$ terraform apply
...
Plan: 4 to add, 0 to change, 1 to destroy.

Changes to Outputs:
  + alb_url = (known after apply)

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

...

Apply complete! Resources: 4 added, 0 changed, 1 destroyed.

Outputs:

alb_url = "http://sun-api-lb-1234512345.us-east-1.elb.amazonaws.com"

Finally, finally, finally, copy and paste that URL into your browser. If all has gone well, you should see the service respond!

If you’re tired of reading, feel free to skip to the end; the hard part is over. But if you’re in the mood to tackle just a couple more changes, we can really put a bow on this API.
Cleanup

You may have noticed that the load balancer is listening on HTTP, not HTTPS. In most cases, we’ll want APIs to be served over HTTPS, so let’s try and correct that using a certificate issued by AWS. You’ll need a domain (or a subdomain) with DNS that you control.

Add these lines to your ecs.tf file, substituting in your domain name in the first block (fully qualified, but without https):

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18
19
20
21
22
23

	

# ecs.tf
resource "aws_acm_certificate" "sun_api" {
  domain_name       = "sun-api.jimmysawczuk.net"
  validation_method = "DNS"
}

output "domain_validations" {
  value = aws_acm_certificate.sun_api.domain_validation_options
}

# These comments are here so Terraform doesn't try to create the listener
# before we have a valid certificate.
# resource "aws_alb_listener" "sun_api_https" {
#   load_balancer_arn = aws_alb.sun_api.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   certificate_arn   = aws_acm_certificate.sun_api.arn
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.sun_api.arn
#   }
# }

Next, find your sun_api_http listener and change the default action to this:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14
15
16
17
18

	

# ecs.tf
resource "aws_alb_listener" "sun_api_http" {
...
-  default_action {
-    type             = "forward"
-    target_group_arn = aws_lb_target_group.sun-api.arn
-  }

+  default_action {
+    type = "redirect"

+    redirect {
+      port        = "443"
+      protocol    = "HTTPS"
+      status_code = "HTTP_301"
+    }
+  }
}

Running terraform apply here should update your existing HTTP listener in place, then create a new HTTP listener which redirects to HTTPS. It’ll also create your certificate. But before you can turn on the HTTPS listener, you’ll need to validate the domain you chose with your DNS provider. The output of the apply should give you all the information you need:

1
2
3
4
5
6
7
8

	

domain_validations = toset([
  {
    "domain_name" = "sun-api.jimmysawczuk.net"
    "resource_record_name" = "_b60a3030189fef2d4239f2c64587866c.sun-api.jimmysawczuk.net."
    "resource_record_type" = "CNAME"
    "resource_record_value" = "_ee46084a09797925cf49c173dd9fadef.duyqrilejt.acm-validations.aws."
  },
])

That block tells me I should create a CNAME record that looks like this:

_b60a3030189fef2d4239f2c64587866c.sun-api 60 IN CNAME _ee46084a09797925cf49c173dd9fadef.duyqrilejt.acm-validations.aws.

While you’re there, go ahead and create a second CNAME record that points your domain at your load balancer URL. For me, that’d be:

sun-api 60 IN CNAME sun-api-lb-1234512345.us-east-1.elb.amazonaws.com.

Your DNS provider should have instructions on how to create CNAME records, like this page from Cloudflare.

Once the validation CNAME record is created, you can uncomment the HTTPS listener block and run terraform apply once more. If this seems to try for a while before timing out, the DNS for the validation record may not have propagated yet, which means AWS hasn’t been able to validate your domain. Give it a few minutes and then try again. (You can also monitor the status of your certificate in ACM in the console.)

Whenever the listener gets created successfully, you should be able to hit the API using https://<your-domain> rather than the load balancer URL.

One last thing. Say we’re ready to start writing our own proprietary code and we want to switch our service to pull from a private ECR repository. This is actually pretty straightforward. Go ahead and add these lines to ecs.tf:

1
2
3

	

resource "aws_ecr_repository" "sun_api" {
  name = "sun-api"
}

Next, change the image field in your task definition JSON to reference the ECR repo:

 1
 2
 3
 4
 5
 6
 7
 8
 9
10
11
12
13
14

	

resource "aws_ecs_task_definition" "sun_api" {
  family = "sun-api"

  container_definitions = <<EOF
  [
    {
      "name": "sun-api",
-     "image": "ghcr.io/jimmysawczuk/sun-api:latest",
+     "image": "${aws_ecr_repository.sun_api.repository_url}:latest",
      ...
    }
  ]
  ...
}

You can run terraform apply to make these changes, but remember that your service won’t work properly until you actually push an image to your new ECR repo. Follow these instructions provided by AWS to authenticate your Docker CLI with your new ECR repo.
Conclusion

That wasn’t so bad, was it?

…

Okay, maybe it was a little rough. But we accomplished quite a bit. Not only did we spin up a Fargate service on HTTPS from scratch, but we did it using Terraform. That means rather than wasting time haphazardly clicking random buttons in the AWS console, we have an exact blueprint for how we spun this service up. And even better, we can instantly clone this Fargate service and create a second one that functions in the same – or similar – way. We might even decide that this is the way we want to create all Fargate services in the future and turn this into a module. That way, all we’ll have to do to spin up a new service is invoke the module with the parameters we define, abstracting away all of the boilerplate AWS stuff we now know we need. But that can wait until next time.

Thanks very much for reading! As promised, here’s a link to the repository with everything we’ve done today. If you are or are aspiring to be a technical person, I hope this was useful. Please let me know how I can improve this post in the comments or by emailing me at feedback@section411.com.

And if you’re not technical and you made it this far, I really appreciate you reading. I’ll be back with some baseball, a movie review or a personal story next time.

Thanks to Sara Sawczuk for reading a draft of this post. When she hits it big as an editor for real writers, I hope she gives me a family discount. Thanks also to Jordan Castillo Chavez for reviewing the more technical parts of this post.

This post and its accompanying repository was updated in September 2021 to use Terraform 1.0.5 and clean up some weird resource names, and then again in December 2021 to improve the networking setup.
