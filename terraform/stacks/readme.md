
# Cross Referencing resources

To reference the resources created by this stack in other stacks you need to define a `data` resource pointing to the S3 bucket and `key` defined in `remote-state.tf.

Your `data` definition should look something like this:

```hcl
data "terraform_remote_state" "vpc" {
    backend = "s3"
    config {
        bucket = "terraform-state.example.com"
        key = "eu-west-1/vpc-1"
        region = "eu-west-1"
    }
}
```

In your code, if you wanted (for example) to reference the `vpc_id` created by this stack you would do something like this:

```hcl
vpc_id = "${data.terraform_remote_state.vpc.vpc_id}"
```

* The `.vpc.` section in the variable name **must** match the name of the `data` resource you define.
* The `.vpc_id` is the name of the variable from this (the source stack). Must be one of those listed in `outputs.tf`.


```
// Directory layout
//
//


stacks/
|__ us-east-1
    |__ test
        |__ vpc
        |__ services
        |__ apps
            |__ foo
            |__ bar

We have REMOTE files in every directory that's a stack, and a Makefile that finds directories
with a REMOTE file to initialize their remote state appropriately.

// If a module needs a VPC output
resource "terraform_remote_state" "vpc" {
  backend = "s3"
  config {
    bucket = "terraform"
    
    // these vars propagate from the stack to every module
    key = "${var.region}/${var.environment}/vpc"
  }
}

// If a module needs to know about the NAT or jump hosts
resource "terraform_remote_state" "services" {
  backend = "s3"
  config {
    bucket = "terraform"
    
    // these vars propagate from the stack to every module
    key = "${var.region}/${var.environment}/services"
  }
}


###############################
##
##

#!/usr/bin/env bash

# List terraform resources in the current directory and ask their arn to import them into terraform state

RESOURCES_LIST=$(awk -F\" '/^resource "/ {print $2"."$4}' *.tf)

for resource in ${RESOURCES_LIST}
do
    read -p "Enter ARN for resource ${resource} (type none to not import it): " arn
    if [[ ${arn} != "none" ]]
    then
        terraform import ${resource} ${arn}
    fi
done


##
##
```

# Overview

Below is a list of the topics I cover:
- [How many OUs should I have?](#how-many-ous-should-i-have)
- [How do I promote code across environments?](#how-do-i-promote-code-across-environments)
- [How should I provision the infrastructure?](#how-should-i-provision-the-infrastructure) _(i.e. automate your infrastructure as code)_
- [How will the infrastructure be deployed? How to bootstrap initially?](#how-will-the-infrastructure-be-deployed-how-to-bootstrap-initially)
- [How do I set up Configuration Management?](#how-do-i-set-up-configuration-management)
- [How should the application be built or compiled?](#how-should-the-application-be-built-or-compiled)
- [How do I reuse scripts across multiple pipelines?](#how-do-i-reuse-scripts-across-multiple-pipelines)
- [How can I use the same configs locally and in the cloud?](#how-can-i-use-the-same-configs-locally-and-in-the-cloud)
- [Do I need EC2s or containers?](#do-i-need-ec2s-or-containers)
- [How do I share _resources_ across application infrastructure?](#how-do-i-share-resources-across-application-infrastructure)
- [How do I share code across application infrastructure?](#how-do-i-share-code-across-application-infrastructure)
- [How can multiple developers work on infrastructure concurrently?](#how-can-multiple-developers-work-on-infrastructure-concurrently)
- [How do I test infrastructure changes?](#how-do-i-test-infrastructure-changes)
- [How do I secure my infrastructure?](#how-do-i-secure-my-infrastructure)
- [How do I monitor my infrastructure?](#how-do-i-monitor-my-infrastructure)
- [How do I avoid downtime?](#how-do-i-avoid-downtime)
- [What kinds of disaster recovery do I plan for?](#what-kinds-of-disaster-recovery-do-i-plan-for)
- [How do I keep my images and applications up to date?](#how-do-i-keep-my-images-and-applications-up-to-date)

Below are my brief analyses on some tooling alternatives:
- [Why not use Waypoint?](#why-not-use-waypoint)
- [Why not use Kubernetes?](#why-not-use-kubernetes)
- [Why not use CloudFormation?](#why-not-use-cloudformation)
- [Why not use the CDK or SAM?](#why-not-use-the-cdk-or-sam)
- [What about Terraform CDK?](#what-about-terraform-cdk)


# How many OUs should I have?

At the moment, I recommend **1 per environment**. You get the advantages of isolating environments without the overhead of wiring too many things up. I also recommend having **1 shared infrastructure repo** if you need to share any resources across applications in an environment. Here's an example breakdown:
```
/app1         (dev, prod)
  lambda
/app2         (dev, prod)
  ecs
/shared-infra (dev, prod)
  vpc
  elasticache
```

These articles are useful reads for understanding elaborate multi-account set ups:
- [Blog on OUs with AWS](https://aws.amazon.com/blogs/mt/best-practices-for-organizational-units-with-aws-organizations/)
- [OU Best Practices](https://aws.amazon.com/organizations/getting-started/best-practices/)

## What about project-wide resources?

Sometimes you may have a tool or application that applies to all of your applications (across all environments) but in itself it has only a single environment (due to licensing or other reasons).

An example of this might be something like:
- An on-prem SonarQube set up
- A single large Jenkins server to save costs
- A single Gitlab setup isolated in its own acount

Reiterating my example above, you might have something like this:
```
app name            (account name)

/app1               (dev, prod)
/app2               (dev, prod)
/shared-infra       (dev, prod) <-- shared infrastructure per-environment
/cross-acount-infra (dev, prod, master) <-- This could span multiple accounts in different ways
/jenkins            (jenkins)   <-- one jenkins shared across all apps and all environments
/sonarqube          (sonarqube)
```

To clarify the intent of `cross-account-infra`, there are a number of "unusual" scenarios you might wish to control with this repo:
- Security Hub or other configurations that require the "master" account to link with child accounts
- Route 53 where a master or particular child account owns the domains
- Depending on your needs, you might also want security and/or logging as their own accounts (and repos):
```
/security-infra  (security) <-- GuardDuty, Security Hub, etc..
/logging-infra   (logging)  <-- CloudTrail, CloudWatch, etc.
```

However, if you don't want 1 account per shared product, you might wish to simplify it to something like this:
```
/jenkins   (tools)
/sonarqube (tools)  <-- both jenkins and sonarqube exist in a "tools" account
```

In this context, I'm using the term `tools` to avoid ambiguity with "shared infrastructure" since you'd probably want a unique term to avoid people getting confused between shared infrastructure (per environment) vs. shared infrastructure (across an entire project). Some other naming thoughts:
- `standalone` _(though I feel this could be ambiguous since there are contexts in which you create a standalone environment for an application to test it)_
- `ops` - It might make sense to call it an "ops" account since they are operational tools

## Why not several OUs?

I also prototyped having an additional "infrastructure" account in https://github.com/JAMSUPREME/tf-multi-account but it was ultimately less value than anticipated. Here is some of my reasoning:
- When talking about `infrastructure` it wouldn't be clear if we are discussing shared infrastructure, or the actual "infrastructure" account
- If we need shared infrastructure, we end up with multiple repos and their purposes (and accounts) aren't clearly defined, e.g.
```
/app1         (dev, prod)
/app2         (dev, prod)
/shared-infra (dev, prod)
/infra        (infra)      <- this becomes ambiguous
```
- It may or may not be practical to have a shared CodeBuild/CodePipeline in the infrastructure repo. If apps need unexpected customizations, we'll be cluttering both repos and introducing confusion.
- The promotion model can be made fairly simple by using SNS, so we won't be tightly coupling environments (see "Benefits" below for my earlier thoughts)
- The problem of a central ECR repo (or any other resource) can be solved by a distinct `shared-infra` repo, and there is no need for a distinct AWS account

# How do I promote code across environments?

This varies slightly depending on whether or not you are using multiple OUs:
- Single OU: Since your DEV, QA, and PROD all share an environment, you can control promotion via your `buildspec.yml` or `Jenkinsfile` (see one such example https://github.com/ICF-ITModernization/base-api-java/blob/master/Jenkinsfile#L128). This makes promotion obvious, and easy for interjecting special behavior for different environments.
- Multiple OUs: Since DEV, QA, and PROD are all in distinct accounts, we need to have them communicate in some manner. As demonstrated in [tf-multi-account](https://github.com/JAMSUPREME/tf-multi-account/blob/main/terraform/application/cloudwatch_send_promotion.tf) we can send promotion events to other OUs in our organization, and then listen for those events in the higher environment. For this example, I used only **Cloudwatch/EventBridge** in an attempt to avoid complexity, but you could also use any pub/sub architecture you want.

# How should I provision the infrastructure?

Broadly, I recommend using **Terraform** to bootstrap an initial pipeline (CodeBuild/Jenkins). Thereafter, your pipeline can adjust its own infrastructure by running `terraform apply`. If all of your resources are public, Github Actions may be a simpler alternative.

# How will the infrastructure be deployed? How to bootstrap initially?

Generally,
- Write the infrastructure code for your pipeline (CodeBuild, Jenkins, etc.)
- Initially create that from your local machine
- Once it exists, create an application pipeline (`buildspec.yml`, `Jenkinsfile`) that can build the application and then apply infrastructure changes. e.g.
```
# in a buildspec
phases:
  install:
    runtime-versions:
      java: corretto11
  build:
    commands:
      - docker build .
      - terraform apply -auto-approve
      
# or Jenkinsfile (may be prettier if you use fancy plugins)
pipeline {
  stages {
    stage('Build and deploy') {
      sh "docker build ."
      sh "terraform apply -auto-approve"
    }
  }
}
```

Since logs will exist, and you could add a manual step to prevent promoting to production if a bug existed, I think it's perfectly fine to have the pipeline potentially adjusting its own infrastructure.

# How do I set up Configuration Management?

There are different ways in which you might use configuration management:
- You might use something like https://www.chef.io/ to create your initial docker or EC2 image
- You might use an AWS userdata https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html to provision your image a particular way on startup
- You might use a fully-featured Chef or Puppet setup, potentially via https://aws.amazon.com/opsworks/ to provision resources

These tools can often be used in conjunction with your infrastructure provisioning (Terraform/CloudFormation). However, caution should be used when bouncing between many tools, as it can be difficult to follow the steps involved if it constantly jumps around from Terraform to UserData to Chef to Dockerfile to Task Definition, etc. 

# How should the application be built or compiled?

Jenkins, CodeBuild, Github Actions, etc. all work equally fine. The drawbacks of having a long-lived Jenkins server is that it requires more upkeep, though you may get better visualization. With Actions or a CodeBuild using an up-to-date base image, you don't need to worry about the server.

One of the related questions to this is whether or not you can reuse similar infrastructure code so you aren't copy/pasting the same shell scripts all over. This can be done whether you use a long-lived option like Jenkins or a bootstrapped custom image with helper scripts. Which leads to the next question...

# How do I reuse scripts across multiple pipelines?

If you're using Jenkins, the easiest way is to use a shared library. See https://github.com/ICF-ITModernization/base-jenkins-shared-library for some examples, along with an example on how to let the shared library run its own methods in its own pipeline to verify that they work before it publishes itself. It also has a self-documenting function reference, so this repo should serve as a handy starting point for any new library.

If you aren't using something long-lived like jenkins, then an alternative may be to write a set of helpful bash scripts that you can source on startup. This way your `buildspec.yml` could use any helper scripts already defined.

# How can I use the same configs locally and in the cloud?

If you use **Kubernetes**, it is _possible_ to reuse your configuration locally and remotely, but the caveat is that you would need to run your databases, caches, etc. within your k8s cluster. If you are OK with this, then k8s is definitely a good fit. If you wish to use a cloud managed tool, then drift is inevitable.

# Do I need EC2s or containers?

Short answer: **No**. _(though if you use build server like Jenkins, that may be a special exception)_

It's important to keep in mind that in many cases, going "serverless" is cheaper and less complicated than wiring together containers.

Here's a quick set of questions to ask yourself:
- Do I perform basic input/output or CRUD operations? **Serverless** _(A database and API gateway could be made with Terraform, and you simply deploy your desired endpoints/functions to lambda for CRUD operations)_
- Do I have a static website? **Serverless** (or maybe even basic s3/cloudfront hosting)
- Do I have long-lived jobs or operations? **Containers/EC2** - If you have something that takes a **LONG** time (5 minutes or more) it is probably advisable to use containers or EC2. If it's asynchronous, you can even get away with cheaper spot pricing.
- Do I have an unsupported language (R, Elixir, Rust)? **Containers/EC2** - If you are using a less-popular language, you won't be able to use Lambda, so you'll need to spin up your own containers. Something like https://www.openfaas.com/ may be relevant in this scenario if you desire a FaaS stack but want an unsupported stack. _(**Sidenote:** For small binaries, you can also make a custom lambda runtime. See https://github.com/awslabs/aws-lambda-rust-runtime)_
- Do I need to maintain persistent state in memory/on-disk? **EC2** - If, for some reason, you need to maintain some sort of state on disk or in memory (and you aren't using a managed service like RDS, RedShift, EFS, EMR, etc...) then you might have a use case where you need to have a long-lived EC2 instance attached to a recoverable EBS volume. **This is not a common use case**.

## Using containers anyway

I'll add a footnote here that it may still be prudent to use containers for development just to isolate your tooling. For example, managing JDK aliases/locals can be a headache on a single machine, but if you spin up an image you are guaranteed to get the version you want.

The same goes for tools like Jenkins (and its many plugins). Installing all of these things and potentially making a mess of your machine can be unpleasant, so there may still be value in using a container to isolate your work environment. That being said, baking a basic image just for local development is a lot simpler than building something stable for production and maintaining it.

# How do I share _resources_ across application infrastructure?

My current recommendation is to have distinct repository `shared-infrastructure` in which you place all shared resources. This same practice applies regardless of whether you're using CloudFormation, Terraform, or something else.

As a brief example, the folder structure might look a bit like this:
```
/Github
  /app-one
    /terraform
      main.tf    (has app 1 resources)
  /app-two
    /terraform
      main.tf    (has app 2 resources)
  /shared-infr
    /terraform
      main.tf    (has VPC setup)
```

# How do I share _code_ across application infrastructure?

- With Terraform, this is primarily done via **modules**.
- With CloudFormation, you would generally use **Nested Stack** (via Template URL)

Regardless of tool, you should be very confident that there is a consistent set of resources to be created across applications, or you'll end up making very brittle templates that don't serve their purpose. Ideally they should be very focused templates that help you reduce boilerplate. 

Some examples:
- ECS app: If you have a lot of simple apps that need to go into a very similar ECS cluster with a load balancer and serve HTTP, it might reduce clutter to roll all the IAM, ECS, ELB, etc. into a single template.
- Lambda function: If you have a lot of lambdas running with similar configurations, it may be easiest to abstract default params, VPC configs, etc. into a single template.

The important thing to remember is that you want to create a **useful abstraction**. If it doesn't represent a unique concept in the infrastructure, you are probably better of just copy/pasting, since many of the resources in TF/CF are already representative of a single unit. You won't get much value from abstracting unless you can fill in a lot of default values or simplify something with a lot of complex parts.

# How can multiple developers work on infrastructure concurrently?

Regardless of tool, there are some important conventions that will help enable this:
- Ensure everything can be named uniquely (`environment` is an easy way to achieve this)
- Increase any account limits if you are hitting them (VPC caps are easy to hit if you use them a lot)
- If you have resources that are shared across applications, be careful not to break or corrupt them with your standalone environment

For **Terraform**, see the [Best Practices For Multiple Developers](#best-practices-for-multiple-developers) section below

For **Cloudformation**, 
- Create a unique stack based on the same template as your current application stack
- If you are using nested stacks, you may wish to duplicate them into a bucket of your own so you can edit them safely
- Note that the above steps could also be automated by having your CI/CD pipeline generate a unique bucket per-branch

# How do I test infrastructure changes?

In respect to Terraform/CloudFormation, there are a couple things you can do:
- Create the infrastructure in a standalone environment and manually verify behavior
- Create the infrastructure in dev or QA and let e2e tests verify behavior

In many cases, you'll want to do both. Usually the creation of the infrastructure will involve some manual adjustments and verification, and then once it seems stable, you would run your e2e tests against it to ensure that nothing was unintentionally broken.

## Configuration Management Tests

Configuration Management is also an important aspect of infrastructure, and there are a few ways it can be tested:
- If using Chef, then InSpec and ChefSpec are useful for verifying the end-state of configuration
- If not, using [goss](https://github.com/aelsabbahy/goss) or [serverspec](https://serverspec.org/) works just as well

While your e2e tests may indirectly confirm that your CM is functioning as expected, adding some specs can help document expected behavior and cover more nuanced aspects of the configuration (crons, SELinux settings, file permissions, etc.)

# How do I secure my infrastructure?

Here are a few tools that can help with securing containers and infrastructure:
- Prisma Cloud (formerly Twistlock) or [openSCAP](https://www.open-scap.org/resources/documentation/security-compliance-of-rhel7-docker-containers/)
- AWS Tools: Inspector, WAF & Shield, GuardDuty
- Web scanner, e.g. [OWASP ZAP](https://owasp.org/www-project-zap/)

This isn't comprehensive by any means, but the above are commonly integrated into the CI/CD pipeline.

# How do I monitor my infrastructure?

There are a few ways in which you can monitor your application:
- **Application Performance Monitoring (APM)** - APM is generally most useful for keeping an eye on unhandled exceptions in your application. It's also good to get a birds' eye view of your application health at a glance.
  - https://newrelic.com/
  - https://www.datadoghq.com/pricing/
- **Distributed tracing** - Adding an additional point onto APM, if you have microservices, you will likely need **distributed tracing** either via your APM, logging, or an additional tool like X-Ray.
- **Logging** - Whether it is HTTP traffic, warnings, or errors, you will likely have a lot of logs that need monitoring.
- **Infrastructure** - Load balancers, container clusters, DNS, EC2 instances, etc. All of these exist outside the scope of your application but could impact it, so you would likely need a separate dashboard like Cloudwatch to observe infrastructure at a glance.
- **Custom metrics** - In addition to the above (or in lieu of), you may want some sort of custom instrumentation like  https://prometheus.io/

I _**STRONGLY**_ recommend having one or more of these tools set up correctly **prior** to launching your app in production.

Newrelic and Datadog both have fairly robust tool suites that let you opt into which kinds of monitoring you need.

# How do I avoid downtime?

This isn't a comprehensive list, but here are some resources that help avoid downtime:

- **Container cluster or EC2 health check** - At the lowest level, you generally want some sort of check at your EC2 or container cluster level to ensure that your image is running as expected.
- **Autoscaling Groups (ASGs)** - First and foremost, if you **don't have an ASG**, then any time your EC2 instance goes down for any reason, your app is down. If you do have an ASG, it's also possible that it was misconfigured and is failing to bring the instances up in a timely manner.
- **Elastic Load Balancer (ELBs)** - You should have a load balancer that is distributing traffic across multiple Availability Zones (AZs) in case a single zone fails.
- **DNS routing** - With DNS failovers (or other configs) you can distribute traffic across regions. This will prevent any outages isolated to a single region.

# What kinds of disaster recovery do I plan for?

In addition to "downtime", you may also end up with some sort of disaster that results in data loss or corruption. For example, if someone accidentally dropped a database or deleted a production file system.

Here are some examples of backups you can take:

- **EBS backups** - If you store anything important on your EC2 instances, then you will want to take EBS backups and potentially re-mount them whenever starting up new instances.
- **AWS Backup (EFS)** - AWS also provides a "generic" backup for things like the Elastic File System. If you have a CMS web site of some sort, then you'd likely want to take backups periodically so you could recover from a bad deletion or admin blunder.
- **S3 replication** - In case a single region became unavailable, or you accidentally lost the data, it's useful to replicate data.
- **Database replicas** - For RDS databases, there are a lot of features for supporting read replicas and promoting replica-to-master. Aurora also has minute-level restores from its backups.

# How do I keep my images and applications up to date?

Generally, you should have a pipeline that will run something like `yum update -y` weekly or monthly and then re-tag that as your latest image. This process is effectively the same whether you're using EC2 instance or containers.

Once the latest image has been created, you would then trigger an ASG refresh (for EC2s) or deploy a new task definition (container cluster). This will safely roll out the new image without downtime.

# Why not use Waypoint?

I think Waypoint is primarily targeted at people who have some code and just want to drop it "anywhere". It might be practical for very small apps or apps that are fairly isolated.
For apps that have a lot of wiring and already a have a fairly robust Terraform setup, I don't see a big win in value, especially if you are customizing a lot of things (load balancers, images, etc.)

## Concerns

I have a few reservations about Waypoint:
- Limited documentation/features. Most behavior is intentionally opaque.
- Limited guidance on big setups (e.g. multiple dependent applications, or even an app with a DB)
- The HTTPS support is via public DNS, and doesn't support non-HTTPS protocols (like db connections)
- I have not yet figured out how one would set up a long-lived Waypoint server for an internal pipeline (only played with local server)

## Benefits

- Easy to spin up
- Gives HTTPS and DNS, so you don't have to worry about port collision
- Has a helpful UI, similar to k8s UI
- It can run against ECS/Fargate or Kubernetes

Good features:
- Can set base image or provide dockerfile: https://www.waypointproject.io/plugins/docker#docker-builder
- ENV variables can be passed: https://www.waypointproject.io/docs/app-config
- Minimal setup (downside is that there aren't many touchpoints for customization)

## Concluding thoughts on Waypoint

- Might be viable for local development, but has drawbacks for dependencies (e.g. database)
- Wouldn't recommend trying it out for a production app since we might hit issues with customizations that we cannot do
- It requires a long-lived waypoint server, which is also a drawback

## Reference

- Docker Build configuration: https://www.waypointproject.io/plugins/docker#docker-builder
- ENV variables can be passed: https://www.waypointproject.io/docs/app-config

# Why not use Kubernetes?

I wouldn't dissuade anyone from using k8s if it fits their needs and they have at least a few people familiar with it or comfortable ramping up quickly. 
It is particularly useful when you have a VERY LARGE fleet or you want to enforce consistent standards across a company or program.
For small projects, I think it is likely to be overkill (but OK if your whole team likes it).

## Local options

There are a handful of options for running k8s locally: https://kubernetes.io/docs/tasks/tools/

There are also other tools like skaffold for making the development cycle easier.

## Do we need it?

In this particular scenario, I would compare the following combinations:

- docker-compose (local setup), terraform, ECS Fargate
- k8s + minikube (local setup), terraform, EKS

### Benefits
- Kubernetes offers a lot of features
- More elaborate support for various types of clustering and deployment
- Good handling for resource management and caps

### Drawbacks
- Kubernetes is fairly complicated
- Kubernetes (in my opinion) isn't particularly valuable for small-scale setups with no intention of federation or additional oversight
- Additional local tooling (k8s, minikube) to be set up on top of docker
- Additional learning for everyone to understand k8s basics
- Some effort would need to be put into figuring out desired base templates and conventions
- Doesn't solve our problem of sharing configuration from local-to-prod since databases won't generally go into the cluster, and we also introduce some blurring of tooling for how we provision infrastructure (i.e. k8s dictating load balancer)

# Why not use CloudFormation?

If you're already largely dependent on it (or the CDK) then it may be practical to continue using it. However, if you have a greenfield, I would recommend Terraform. For a more detailed comparison, see the [Terraform vs. Cloudformation](https://gist.github.com/JAMSUPREME/67635016711e548d07f5e374aa5613bb#vs-cloudformation) section below.

# Why not use the CDK or SAM?

My experience with the CDK was limited, but from what I've experienced:
- Sometimes the CDK has bugs and while you get some simplicity up-front, when something is buggy or broken, or you need further customization, sometimes it gets in the way
- When using the CDK, it can sometimes obscure what is getting created or result in spaghetti code that is more complicated than a Terraform alternative.

That being said, I haven't used it enough successfully to accurately articulate its strong points.

# What about Terraform CDK?

In addition to the vanilla AWS CDK, there is also a CDK target for terraform: https://github.com/hashicorp/terraform-cdk (a.k.a. `tfcdk` or `cdktf`)

I did a bit of prototyping with it. See https://github.com/JAMSUPREME/tf-multi-account/tree/main/tf-cdk and [README](https://github.com/JAMSUPREME/tf-multi-account#using-cdk-tf) for more info.

## Recommendation

My current recommendation is to use Terraform CDK to **augment** a normal Terraform setup. It excels in a few scenarios in which HashiCorp Configuration Language (HCL) can get clunky, but otherwise the two are nearly interchangeable, since the majority of the TF CDK is generating Terraform-compatible JSON configuration.

### When to use CDK?

I would generally recommend augmenting vanilla TF with the CDK if you need to do any of these things:
- You want a simpler alternative to `count` usage. See [tf-multi](https://github.com/JAMSUPREME/tf-multi-account/blob/main/terraform/application/cloudwatch_receive_promotion.tf#L3-L32) repo for an example, and [Terraform different resource per environment](#different-resources-per-environment) for an explanation of how this happens in vanilla TF.
```
# with terraform
resource "aws_sns_topic" "build_emailer" {
  count = var.add_sns_topic ? 1 : 0
  name = "build_email"
  tags = local.global_tags
}
# dependent resources must also have `count` and reference the resource via `aws_sns_topic.build_emailer[0]

# with CDK
if(!add_sns_topic){
  const topic = new SnsTopic(this, 'myFirstTopic', {
    name: 'first-topic',
    displayName: 'first-topic-display'
  });
  // make other dependent resources here that reference `topic`
}
```
- Elaborate looping (`for_each`) or a lot of `dynamic` blocks. HCL gets clunky when using one or both of these.
- You want to inheritance:
```
class DefaultCloudwatchLogGroup extends CloudwatchLogGroup {
  // put default retention, KMS key, etc.
}
```
- You want flexible/functional/chained/fluent composition
```
// polymorphic tagging
function addTags(resource){
  resource.tags = local.global_tags
}
// builder-style resource composition
class S3BucketBuilder {
  function buildLifecyclePolicy(){}
  function buildVersioning(){}
}
```

## Benefits

- It can be used in a "hybrid" setup in conjunction with a "vanilla Terraform" setup.
- Conditional resource creation is **much easier** (no need for `count` and `resource[0]` usage)
- You could use composition or inheritance in a much simpler way (as opposed to TF modules)
- Looping is much simpler (compared to HCL)
- It **should** be possible to follow similar conventions for both styles

## Concerns

- The CDK doesn't automatically keep all resources in scope (must explicitly pass variables around)
- The diff report `cdktf diff` is not as detailed as the normal `terraform plan`
- The documentation isn't nearly as robust as normal TF https://registry.terraform.io/providers/hashicorp/aws/latest/docs (though you can inspect the TypeScript types)
- The `cdktf deploy` hasn't run as cleanly as a normal `terraform apply` (not sure why)
- It is technically still in `alpha` and they mention it is not ready for production use, though it seems pretty safe to do so. Similarly, there might be significant new [feature flags](https://github.com/hashicorp/terraform-cdk/blob/master/docs/working-with-cdk-for-terraform/feature-flags.md) or backwards-incompatible changes, though we don't know for sure.

## Similarities

- Both can be linted and formatted consistently
- Both can support targeting distinct backends per environment
- Both can do templating
