# Kubernetes Enumeration Worksheet  
This worksheet provides a comprehensive list of `kubectl` commands to help you explore and enumerate various components in your Kubernetes cluster. 

It covers listing namespaces, pods, container images, metadata, and more.

**Listing Namespaces:**  
`kubectl get namespaces`  
Lists every namespace defined in your Kubernetes cluster.

**Listing Pods (All Namespaces):**  
`kubectl get pods --all-namespaces`  
Lists all pods across every namespace. For a specific namespace, use:  
`kubectl get pods -n <namespace>`

**Viewing Pod Details in JSON Format:**  
`kubectl get pods -o json`  
Outputs detailed pod information in JSON format for advanced querying or scripting.

**Extracting Container Images:**  
`kubectl get pods --all-namespaces -o jsonpath="{range .items[*]}{range .spec.containers[*]}{.image}{'\n'}{end}{end}"`  
Extracts and prints the container images used by the pods, one image per line.

**Listing Unique Container Images:**  
`kubectl get pods --all-namespaces -o jsonpath="{range .items[*]}{range .spec.containers[*]}{.image}{'\n'}{end}{end}" | sort -u`  
Sorts the images and removes duplicates so each container image is listed only once.

**Retrieving Pod Metadata (Labels & Annotations):**  
`kubectl get pods --all-namespaces -o jsonpath="{range .items[*]}{.metadata.name}{'\t'}{.metadata.labels}{'\t'}{.metadata.annotations}{'\n'}{end}"`  
Prints each pod’s name along with its labels and annotations, separated by tabs.

**Additional Enumeration Commands:**  
- **Deployments:** `kubectl get deployments --all-namespaces`  
- **Services:** `kubectl get services --all-namespaces`  
- **Nodes:** `kubectl get nodes`  

**Viewing Pod Logs:**  
`kubectl logs <pod-name> -n <namespace>`  
Replace `<pod-name>` and `<namespace>` with the appropriate values to view logs for a specific pod.

For further information, refer to the [Kubernetes Official Documentation](https://kubernetes.io/docs/) and the [JSONPath Reference for kubectl](https://kubernetes.io/docs/reference/kubectl/jsonpath/).
