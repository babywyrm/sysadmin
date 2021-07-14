
###################################
https://dev.to/narasimha1997/create-kubernetes-jobs-in-golang-using-k8s-client-go-api-59ej
###################################




Few months back, I was building a system that involved launching and monitoring jobs on Kubernetes programmatically, basically I was writing a controller kind of a service that would take requests from an API and schedule jobs on the Kubernetes cluster. I was using Go and there is only one fully fledged client API in go called client-go. In this post I am just documenting the process of creating k8s jobs using client-go, so that anyone working on the same problem would find this helpful.

Prerequisites:
A working Kubernetes setup, if you don't have a multi-node cluster, you can setup a local kubernetes environment using minikube or microk8s.
Basic knowledge of Go is necessary.
Must have setup a working Go modules directory.
Installing client-go package:
The client-go library is an official kubernetes client SDK by K8s community, you can use this library to programmatically manipulate your kubernetes cluster. Basically all Kubernetes controllers and components are built using this library. The kubernetes client tool kubectl is also built using client-go. client-go has following packages, which you must be aware of, before installing it:

kubernetes : This package offers you APIs using which you can connect to your Kubernetes service. It provides different kinds of connection APIs. It also provides you the access to clientset interface, which can be used to specify and manipulate K8s objects.
discovery : This package offers you APIs to discover K8s APIs.
dynamic : client-go provides you built-in types and constructs to specify any object, this strongly typed nature helps developers to identify type-errors at compile-type, but at the same time, the type system is rigid and offers less flexibility, on the other hand, dynamic API can be used to gain more flexibility because it allows developers to specify the objects as a nested map (can be de-serialized from JSON, YAML easily), this nested map can be changed easily as the need changes without having to re-compile the codebase, since the map is created dynamically and type-checking happens at runtime.
plugin/pkg/client/auth : This module offers you authentication plugins.
transport : This package is used to set up auth and start a connection.
tools/cache : This package is useful for writing controllers.
To install client-go as a module, you need to have the latest Go version which supports module system. See this tutorial if you want to know more about Go module system. Let's create a simple go module called "github.com/k8sjobs"
mkdir k8sjobs
cd k8sjobs && go mod init github.com/k8sjobs
If everything is ok, you must see go.mod file created. Let's check.
cat k8sjobs/go.mod
Output:
module github.com/k8sjobs

go 1.15
So, we have the module ready, now let's install client-go. Client-go has many versions, we will install one of the latest stable versions of client-go. From the module root, i.e from k8sjobs directory, run :
go get k8s.io/client-go@v0.20.2 
You many have to wait for installation to get complete. We can verify the installation by checking go.mod file.
module github.com/k8sjobs

go 1.15

require k8s.io/client-go v0.20.2 // indirect
The go.mod has client-go as one of it's indirect dependencies which is fine as of now because we don't have any source file which imports k8s.io/client-go yet.

What we will build?
We will build a simple command line tool that takes job name, container name and entrypoint as arguments and creates a job on the kubernetes cluster. We will be using golang's built-in package - flag to do this. We will create a file called main.go inside our module's root, which does everything that's required. So, let's start coding.
import (
    "flag"
    "fmt"
)
func main() {
    jobName := flag.String("jobname", "test-job", "The name of the job")
    containerImage := flag.String("image", "ubuntu:latest", "Name of the container image")
    entryCommand := flag.String("command", "ls", "The command to run inside the container")

    flag.Parse()

    fmt.Printf("Args : %s %s %s\n", *jobName, *containerImage, *entryCommand)
}
So now we have a basic main function setup, this will simply accept arguments jobName, containerName and imageName and prints them. Now let's begin using client-go library.

1. Connect to the cluster:
The first step is to connect to the cluster. Connection to the cluster requires K8s cluster config file, since we are connecting to an external remote cluster. Since it is assumed that you have a cluster set-up, you must be having the config file ready. It is assumed that the cluster config file is located at $HOME/.kube/config. We will write a function called connectToK8s.

Our imports till now:
import (
    "flag"
    "log"
    "os"
    "path/filepath"

    clientcmd "k8s.io/client-go/1.5/tools/clientcmd"
    "k8s.io/client-go/kubernetes"
)
The function connectToK8s connects to the cluster and then creates a clientset and returns it.
func connectToK8s() *kubernetes.Clientset {
    home, exists := os.LookupEnv("HOME")
    if !exists {
        home = "/root"
    }

    configPath := filepath.Join(home, ".kube", "config")

    config, err := clientcmd.BuildConfigFromFlags("", configPath)
    if err != nil {
        log.Panicln("failed to create K8s config")
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        log.Panicln("Failed to create K8s clientset")
    }

    return clientset
}
Now we call the function inside main:
clientset := connectToK8s()
Now we have the clientset, we can create a job on the cluster. To do this, we will write a function called launchK8sJob which will be of the form:
func launchK8sJob(clientset *kubernetes.Clientset, jobName *string, image *string, cmd *string)
But before we begin, let's recall how the K8s job specification looks like:
apiVersion: batch/v1
kind: Job
metadata:
  name: ls-job
spec:
  template:
    spec:
      containers:
      - name: ls-job
        image: ubuntu:latest
        command: ["ls", "-aRil"]
      restartPolicy: Never
  backoffLimit: 4
This is the sample specification taken from here. The K8s specification uses batch/v1 API to create Jobs, since everything in Kubernetes has a pre-defined template, we have a template for Jobs creation as well, which is shown above. The kubernetes clientset type provides Batchv1 construct which we can use to manipulate jobs. Let's create a job using Batchv1 construct.

Here are the imports till now:
import (
    "context"
    "flag"
    "log"
    "os"
    "path/filepath"
    "strings"

    batchv1 "k8s.io/api/batch/v1"
    v1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    kubernetes "k8s.io/client-go/kubernetes"
    clientcmd "k8s.io/client-go/tools/clientcmd"
)
Now the function launchK8sJob:
func launchK8sJob(clientset *kubernetes.Clientset, jobName *string, image *string, cmd *string) {
    jobs := clientset.BatchV1().Jobs("default")
    var backOffLimit int32 = 0

    jobSpec := &batchv1.Job{
        ObjectMeta: metav1.ObjectMeta{
            Name:      *jobName,
            Namespace: "default",
        },
        Spec: batchv1.JobSpec{
            Template: v1.PodTemplateSpec{
                Spec: v1.PodSpec{
                    Containers: []v1.Container{
                        {
                            Name:    *jobName,
                            Image:   *image,
                            Command: strings.Split(*cmd, " "),
                        },
                    },
                    RestartPolicy: v1.RestartPolicyNever,
                },
            },
            BackoffLimit: &backOffLimit,
        },
    }

    _, err := jobs.Create(context.TODO(), jobSpec, metav1.CreateOptions{})
    if err != nil {
        log.Fatalln("Failed to create K8s job.")
    }

    //print job details
    log.Println("Created K8s job successfully")
}
That's it! We just need to call this function from main. Here is the entire source file:
package main

import (
    "context"
    "flag"
    "log"
    "os"
    "path/filepath"
    "strings"

    batchv1 "k8s.io/api/batch/v1"
    v1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    kubernetes "k8s.io/client-go/kubernetes"
    clientcmd "k8s.io/client-go/tools/clientcmd"
)

func connectToK8s() *kubernetes.Clientset {
    home, exists := os.LookupEnv("HOME")
    if !exists {
        home = "/root"
    }

    configPath := filepath.Join(home, ".kube", "config")

    config, err := clientcmd.BuildConfigFromFlags("", configPath)
    if err != nil {
        log.Fatalln("failed to create K8s config")
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        log.Fatalln("Failed to create K8s clientset")
    }

    return clientset
}

func launchK8sJob(clientset *kubernetes.Clientset, jobName *string, image *string, cmd *string) {
    jobs := clientset.BatchV1().Jobs("default")
    var backOffLimit int32 = 0

    jobSpec := &batchv1.Job{
        ObjectMeta: metav1.ObjectMeta{
            Name:      *jobName,
            Namespace: "default",
        },
        Spec: batchv1.JobSpec{
            Template: v1.PodTemplateSpec{
                Spec: v1.PodSpec{
                    Containers: []v1.Container{
                        {
                            Name:    *jobName,
                            Image:   *image,
                            Command: strings.Split(*cmd, " "),
                        },
                    },
                    RestartPolicy: v1.RestartPolicyNever,
                },
            },
            BackoffLimit: &backOffLimit,
        },
    }

    _, err := jobs.Create(context.TODO(), jobSpec, metav1.CreateOptions{})
    if err != nil {
        log.Fatalln("Failed to create K8s job.")
    }

    //print job details
    log.Println("Created K8s job successfully")
}

func main() {
    jobName := flag.String("jobname", "test-job", "The name of the job")
    containerImage := flag.String("image", "ubuntu:latest", "Name of the container image")
    entryCommand := flag.String("command", "ls", "The command to run inside the container")

    flag.Parse()

    clientset := connectToK8s()
    launchK8sJob(clientset, jobName, containerImage, entryCommand)
}
Note that, we are setting RestartPolicy as Never and BackOffLimit to zero, it means, if the job fails, it will never be restarted by the job controller because of BackOffLimit and the Pod created by the job will die gracefully because of RestartPolicy being set to Never.

Let's build the module and run it. Before building, we set GOBIN to current working directory so that we will get the binary k8sjobs in the current working directory.
export GOBIN=$PWD
go install
If compilation is successful, you should see k8sjobs binary generated in the current working directory. Let's run the binary by providing the arguments.
./k8sjobs --jobname=test --image=alpine:latest --command="ls -aRil"
If the cluster is configured properly, the command must exit successfully and we should see the output something like this.
2021/02/13 13:39:49 Created K8s job successfully
Now let's check the job using kubectl. (I am using microk8s, so I use kubectl binary that comes with microk8s toolchain. You can just use kubectl if you have installed it separately, or just alias microk8s kubectl to kubectl).
microk8s kubectl get jobs
Output:
NAME   COMPLETIONS   DURATION   AGE
test   1/1           73s        13m
The output shows that the job has been created and is completed successfully. Now let's describe the job to check if it's the same job we created.
microk8s kubectl describe job test
Output:
Name:           test
Namespace:      default
Selector:       controller-uid=48b7b61d-4ead-4033-91cd-035f539c27bf
Labels:         controller-uid=48b7b61d-4ead-4033-91cd-035f539c27bf
                job-name=test
Annotations:    <none>
Parallelism:    1
Completions:    1
Start Time:     Sat, 13 Feb 2021 13:39:49 +0530
Completed At:   Sat, 13 Feb 2021 13:41:02 +0530
Duration:       73s
Pods Statuses:  0 Running / 1 Succeeded / 0 Failed
Pod Template:
  Labels:  controller-uid=48b7b61d-4ead-4033-91cd-035f539c27bf
           job-name=test
  Containers:
   test:
    Image:      alpine:latest
    Port:       <none>
    Host Port:  <none>
    Command:
      ls
      -aRil
    Environment:  <none>
    Mounts:       <none>
  Volumes:        <none>
Events:
  Type    Reason            Age   From            Message
  ----    ------            ----  ----            -------
  Normal  SuccessfulCreate  15m   job-controller  Created pod: test-l9zwk
  Normal  Completed         14m   job-controller  Job completed
This is the description of the job we created. You can verify that the container image name and the command is same as what we passed as arguments.

So that's it. This is just a basic example of how you can use client-go library to create K8s jobs. If you have free time, explore the library because there are whole lot of functionalities the library offers.
    
<br>
<br>    
    
