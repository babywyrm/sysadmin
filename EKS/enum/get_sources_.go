package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
//	"os"
	"flag"
)

//
//

type NamespaceList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

type PodList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Containers []struct {
				Image string `json:"image"`
			} `json:"containers"`
		} `json:"spec"`
	} `json:"items"`
}

func runKubectlCommand(args []string) ([]byte, error) {
	cmd := exec.Command("kubectl", args...)
	return cmd.Output()
}

func getNamespaces() (*NamespaceList, error) {
	output, err := runKubectlCommand([]string{"get", "namespaces", "-o", "json"})
	if err != nil {
		return nil, err
	}

	var namespaces NamespaceList
	if err := json.Unmarshal(output, &namespaces); err != nil {
		return nil, err
	}
	return &namespaces, nil
}

func getPods(namespace string) (*PodList, error) {
	output, err := runKubectlCommand([]string{"get", "pods", "-n", namespace, "-o", "json"})
	if err != nil {
		return nil, err
	}

	var pods PodList
	if err := json.Unmarshal(output, &pods); err != nil {
		return nil, err
	}
	return &pods, nil
}

func extractContainerImages(pods *PodList) []string {
	images := []string{}
	for _, pod := range pods.Items {
		fmt.Printf("Pod: %s\n", pod.Metadata.Name)
		for _, container := range pod.Spec.Containers {
			images = append(images, container.Image)
			fmt.Printf("  - Image: %s\n", container.Image)
		}
	}
	return images
}

func processNamespace(namespace string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()
	fmt.Printf("Fetching pods from namespace: %s\n", namespace)
	pods, err := getPods(namespace)
	if err != nil {
		fmt.Printf("Error fetching pods from namespace %s: %v\n", namespace, err)
		return
	}

	images := extractContainerImages(pods)
	for _, image := range images {
		results <- fmt.Sprintf("Namespace: %s, Image: %s", namespace, image)
	}
}

func main() {
	// Command-line argument for namespace selection
	allNamespaces := flag.Bool("all", false, "Fetch all namespaces")
	selectedNamespace := flag.String("namespace", "", "Specify a namespace to check")
	flag.Parse()

	// Get all namespaces
	namespaces, err := getNamespaces()
	if err != nil {
		fmt.Printf("Error fetching namespaces: %v\n", err)
		return
	}

	if *allNamespaces {
		fmt.Println("Fetching pods from all namespaces:")
	} else if *selectedNamespace != "" {
		fmt.Printf("Fetching pods from namespace: %s\n", *selectedNamespace)
	} else {
		fmt.Println("Available namespaces:")
		for _, ns := range namespaces.Items {
			fmt.Printf(" - %s\n", ns.Metadata.Name)
		}
		fmt.Print("Enter the namespace you want to check: ")
		fmt.Scanln(selectedNamespace)
	}

	results := make(chan string)
	var wg sync.WaitGroup

	if *allNamespaces {
		for _, ns := range namespaces.Items {
			namespace := ns.Metadata.Name
			wg.Add(1)
			go processNamespace(namespace, &wg, results)
		}
	} else {
		wg.Add(1)
		go processNamespace(*selectedNamespace, &wg, results)
	}

	// Close the results channel when all goroutines are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and print results
	for result := range results {
		fmt.Println(result)
	}
}

//
//
