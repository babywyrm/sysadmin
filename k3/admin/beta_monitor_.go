//
// go get k8s.io/client-go@v0.27.1
// go get k8s.io/apimachinery@v0.27.1
//
// go mod init k3s_monitor
// go build -o k3s_monitor k3s_monitor.go
//

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	maxLoad              = 9.0  // System load threshold
	maxMemoryUsage       = 80   // System memory usage threshold (%)
	maxPodCPUUsage       = 80   // Pod CPU usage threshold (%)
	maxPodMemoryUsage    = 80   // Pod memory usage threshold (%)
	namespace            = "default" // Namespace to monitor
	excludeNamespaces    = "kube-system,kube-public,metallb-system" // Excluded namespaces
	logFile              = "/var/log/k3s_advanced_monitor.log" // Log file location
	checkIntervalSeconds = 300  // Monitoring interval (seconds)
)

func logAction(message string) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	logger := log.New(f, "", log.LstdFlags)
	logger.Println(message)
}

func getLoadAverage() (float64, error) {
	output, err := exec.Command("awk", "{print $1}", "/proc/loadavg").Output()
	if err != nil {
		return 0, err
	}
	load, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
	if err != nil {
		return 0, err
	}
	return load, nil
}

func getMemoryUsage() (int, error) {
	output, err := exec.Command("free", "-m").Output()
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected free output")
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 3 {
		return 0, fmt.Errorf("unexpected free output")
	}
	totalMem, _ := strconv.Atoi(fields[1])
	usedMem, _ := strconv.Atoi(fields[2])
	memoryUsage := (usedMem * 100) / totalMem
	return memoryUsage, nil
}

func getK8sClient() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func getPods(clientset *kubernetes.Clientset) (*v1.PodList, error) {
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return pods, nil
}

func checkPodResources(clientset *kubernetes.Clientset) error {
	// Placeholder: this is where you'd fetch metrics for pod CPU and memory usage
	// Using metrics-server or kubectl top via client-go isn't implemented in the basic example
	// Implement using metrics API or external library
	pods, err := getPods(clientset)
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		logAction(fmt.Sprintf("Checking pod %s in namespace %s", pod.Name, pod.Namespace))
		// Simulate checks and pod resource threshold violations
		// Here you would fetch actual metrics and compare to thresholds
	}
	return nil
}

func restartAllPods(clientset *kubernetes.Clientset) error {
	deploymentsClient := clientset.AppsV1().Deployments(namespace)
	deployments, err := deploymentsClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, deployment := range deployments.Items {
		logAction(fmt.Sprintf("Rolling restart of deployment: %s", deployment.Name))
		err := restartDeployment(clientset, deployment.Name)
		if err != nil {
			logAction(fmt.Sprintf("Failed to restart deployment %s: %v", deployment.Name, err))
		}
	}
	return nil
}

func restartDeployment(clientset *kubernetes.Clientset, deploymentName string) error {
	deploymentsClient := clientset.AppsV1().Deployments(namespace)
	_, err := deploymentsClient.Get(context.TODO(), deploymentName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	err = deploymentsClient.Delete(context.TODO(), deploymentName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}
	logAction(fmt.Sprintf("Deployment %s successfully restarted", deploymentName))
	return nil
}

func main() {
	clientset, err := getK8sClient()
	if err != nil {
		log.Fatalf("Error creating k8s client: %v", err)
	}

	for {
		load, err := getLoadAverage()
		if err != nil {
			log.Fatalf("Error retrieving load average: %v", err)
		}
		memoryUsage, err := getMemoryUsage()
		if err != nil {
			log.Fatalf("Error retrieving memory usage: %v", err)
		}

		logAction(fmt.Sprintf("Current Load: %.2f, Memory Usage: %d%%", load, memoryUsage))

		if load > maxLoad || memoryUsage > maxMemoryUsage {
			logAction(fmt.Sprintf("System under pressure (Load: %.2f, Memory: %d%%). Restarting pods...", load, memoryUsage))
			err := restartAllPods(clientset)
			if err != nil {
				log.Fatalf("Error restarting pods: %v", err)
			}
		} else {
			// Check individual pod resource usage
			err := checkPodResources(clientset)
			if err != nil {
				log.Fatalf("Error checking pod resources: %v", err)
			}
		}

		// Sleep for the check interval
		time.Sleep(checkIntervalSeconds * time.Second)
	}
}

//
//
