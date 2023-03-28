## Jenkins + Docker

The exact list of plugins for enabling Docker commands within Jenkins jobs is somewhat unclear. 

Looks like *at least the `Docker Build Step` plugin* is required to make this happen.

This does two things:

1. Helps us to run `docker` commands within Execute Shell steps
1. Adds the "Execute Docker Command" build step .

**Important Configuration**

1. Make sure the Jenkins user is added to the `docker` group. eg. `usermod -aG docker jenkins`. If you don't do this, you might see errors like `Got permission denied while trying to connect to the Docker daemon socket`.

1. **Make sure to restart the machine as well as Jenkins Service** for the above user change to take effect.

## Polling SCM in Pipeline Jobs

* [ref](http://stackoverflow.com/a/31148178/682912)

**Question: ** The Jenkins Pipeline Job Type has the "Poll SCM" field. But if I use multiple SCMs, does this work, and if so how?

**Answer: ** 

It _does_ work across multiple SCMs. Suppose you have the following setup:
* App code stored in one repo
* Deployment Ansible Playbooks stored in another repo
* Jenkins Pipeline code which builds the app and deploys it is stored in a third repo.

In this case, "Poll SCM" will work *across all 3 repos above.* It will poll all the repos as per the schedule you specify. And changes to *any* repo will trigger the pipeline.

(This conforms to the Continuous Delivery idea that *any change should trigger the pipeline*.)

## Troubleshooting: Mysterious Error: `java.io.NotSerializableException`

*This error took me a day and a half to figure out.*

* A Pipeline Job is configured to pick the code from SCM.
* There is a `Jenkinsfile`, which loads methods (`def methodName`) from a `job-config.groovy` file.  

Everything was working well until I decided to add a stub method to invoke an ansible playbook.

```
def invokePlaybook() {

}
```

Using the **Snippet Generator** functionality, I generated some sample pipeline code as follows:

![image](https://cloud.githubusercontent.com/assets/13379978/26188242/ca781126-3bbb-11e7-9849-e576a4ad8bbd.png)

The generated code looked like this:

![image](https://cloud.githubusercontent.com/assets/13379978/26188253/e0c75234-3bbb-11e7-958d-2033ae8de94c.png)

But when I copied the code, I chose to insert some newline characters. 

```
def invokePlaybook() {

  ansiblePlaybook
    credentialsId: 'jenkins-gitlab-ssh-key',
    extras: '--extra-vars @extra_vars.json',
    installation: 'Ansible-2.3.0',
    inventory: 'inventories/sit/',
    playbook: 'playbook.yml',
    sudo: true, sudoUser: "root"

}
```
**So what was the cause?**

Either the multiple-line entry was the cause, or perhaps it was the use of the `@extra_vars.json`? Who knows?

*What I did find, however,* was that if I paste the code in the inline-groovy editor (Job Type: Pipeline Script) it throws a compilation error. So remember to do this when writing your pipeline code!

```
org.codehaus.groovy.control.MultipleCompilationErrorsException: startup failed:
WorkflowScript: 112: unexpected token: jenkins-gitlab-ssh-key @ line 112, column 20.
       credentialsId: 'jenkins-gitlab-ssh-key',
```

## Interesting Plugin: Pipeline Utility Steps

* [Pipeline Utility Steps](https://jenkins.io/doc/pipeline/steps/pipeline-utility-steps/)
* [Original SO Post](https://stackoverflow.com/questions/37603619/extract-pom-version-in-a-jenkins-pipeline)


This plugin installs several useful functionalities exposed via Pipeline Steps.

E.g:

```
readJSON: Read JSON from files in the workspace.
readMavenPom: Read a maven project pom.xml file.
```
