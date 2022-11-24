
# Monitoring

Two different methods to install and configure Prometheus and Grafana are described in this doc.
* Prometheus and Grafana installation using Pod Annotations. This installs Prometheus and Grafana in the same namespace as NGINX Ingress
* Prometheus and Grafana installation using Service Monitors. This installs Prometheus and Grafana in two different namespaces. This is the preferred method, and helm charts supports this by default.

## Prometheus and Grafana installation using Pod Annotations

This tutorial will show you how to install [Prometheus](https://prometheus.io/) and [Grafana](https://grafana.com/) for scraping the metrics of the NGINX Ingress controller.

!!! important
    This example uses `emptyDir` volumes for Prometheus and Grafana. This means once the pod gets terminated you will lose all the data.

### Before You Begin

- The NGINX Ingress controller should already be deployed according to the deployment instructions [here](../deploy/index.md).

- The controller should be configured for exporting metrics. This requires 3 configurations to the controller. These configurations are :
  1. controller.metrics.enabled=true
  2. controller.podAnnotations."prometheus.io/scrape"="true"
  3. controller.podAnnotations."prometheus.io/port"="10254"

  - The easiest way to configure the controller for metrics is via helm upgrade. Assuming you have installed the ingress-nginx controller as a helm release named ingress-nginx, then you can simply type the command shown below :
  ```
  helm upgrade ingress-nginx ingress-nginx \
  --repo https://kubernetes.github.io/ingress-nginx \
  --namespace ingress-nginx \
  --set controller.metrics.enabled=true \
  --set-string controller.podAnnotations."prometheus\.io/scrape"="true" \
  --set-string controller.podAnnotations."prometheus\.io/port"="10254"
  ```
  - You can validate that the controller is configured for metrics by looking at the values of the installed release, like this:
  ```
  helm get values ingress-nginx --namespace ingress-nginx
  ```
  - You should be able to see the values shown below:
  ```
  ..
  controller:
    metrics:
      enabled: true
      service:
        annotations:
          prometheus.io/port: "10254"
          prometheus.io/scrape: "true"
  ..
  ```
   - If you are **not using helm**, you will have to edit your manifests like this:
     - Service manifest:
       ```
       apiVersion: v1
       kind: Service
       metadata:
        annotations:
          prometheus.io/scrape: "true"
          prometheus.io/port: "10254"
       ..
       spec:
         ports:
           - name: prometheus
             port: 10254
             targetPort: prometheus
             ..

       ```
      - Deployment manifest:
         ```
         apiVersion: v1
         kind: Deployment
         metadata:
          annotations:
            prometheus.io/scrape: "true"
            prometheus.io/port: "10254"
         ..
         spec:
           ports:
             - name: prometheus
               containerPort: 10254
               ..
         ```


### Deploy and configure Prometheus Server

Note that the kustomize bases used in this tutorial are stored in the [deploy](https://github.com/kubernetes/ingress-nginx/tree/main/deploy) folder of the GitHub repository [kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx).

- The Prometheus server must be configured so that it can discover endpoints of services. If a Prometheus server is already running in the cluster and if it is configured in a way that it can find the ingress controller pods, no extra configuration is needed.

- If there is no existing Prometheus server running, the rest of this tutorial will guide you through the steps needed to deploy a properly configured Prometheus server.

- Running the following command deploys prometheus in Kubernetes:

  ```
  kubectl apply --kustomize github.com/kubernetes/ingress-nginx/deploy/prometheus/
  ```

#### Prometheus Dashboard

- Open Prometheus dashboard in a web browser:

  ```console
  kubectl get svc -n ingress-nginx
  NAME                   TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                                      AGE
  default-http-backend   ClusterIP   10.103.59.201   <none>        80/TCP                                       3d
  ingress-nginx          NodePort    10.97.44.72     <none>        80:30100/TCP,443:30154/TCP,10254:32049/TCP   5h
  prometheus-server      NodePort    10.98.233.86    <none>        9090:32630/TCP                               1m
  ```

  - Obtain the IP address of the nodes in the running cluster:

  ```console
  kubectl get nodes -o wide
  ```

  - In some cases where the node only have internal IP addresses we need to execute:

  ```
  kubectl get nodes --selector=kubernetes.io/role!=master -o jsonpath={.items[*].status.addresses[?\(@.type==\"InternalIP\"\)].address}
  10.192.0.2 10.192.0.3 10.192.0.4
  ```

  - Open your browser and visit the following URL: _http://{node IP address}:{prometheus-svc-nodeport}_ to load the Prometheus Dashboard.

  - According to the above example, this URL will be http://10.192.0.3:32630

  ![Prometheus Dashboard](../images/prometheus-dashboard.png)

#### Grafana
  - Install grafana using the below command
  ```
  kubectl apply --kustomize github.com/kubernetes/ingress-nginx/deploy/grafana/
  ```
  - Look at the services
  ```
  kubectl get svc -n ingress-nginx
  NAME                   TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                                      AGE
  default-http-backend   ClusterIP   10.103.59.201   <none>        80/TCP                                       3d
  ingress-nginx          NodePort    10.97.44.72     <none>        80:30100/TCP,443:30154/TCP,10254:32049/TCP   5h
  prometheus-server      NodePort    10.98.233.86    <none>        9090:32630/TCP                               10m
  grafana                NodePort    10.98.233.87    <none>        3000:31086/TCP                               10m
  ```

  - Open your browser and visit the following URL: _http://{node IP address}:{grafana-svc-nodeport}_ to load the Grafana Dashboard.
According to the above example, this URL will be http://10.192.0.3:31086

  The username and password is `admin`

  - After the login you can import the Grafana dashboard from [official dashboards](https://github.com/kubernetes/ingress-nginx/tree/main/deploy/grafana/dashboards), by following steps given below :

    - Navigate to lefthand panel of grafana
    - Hover on the gearwheel icon for Configuration and click "Data Sources"
    - Click "Add data source"
    - Select "Prometheus"
    - Enter the details (note: I used http://CLUSTER_IP_PROMETHEUS_SVC:9090)
    - Left menu (hover over +) -> Dashboard
    - Click "Import"
    - Enter the copy pasted json from https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/grafana/dashboards/nginx.json
    - Click Import JSON
    - Select the Prometheus data source
    - Click "Import"



  ![Grafana Dashboard](../images/grafana.png)

### Caveats

#### Wildcard ingresses

  - By default request metrics are labeled with the hostname. When you have a wildcard domain ingress, then there will be no metrics for that ingress (to prevent the metrics from exploding in cardinality). To get metrics in this case you need to run the ingress controller with `--metrics-per-host=false` (you will lose labeling by hostname, but still have labeling by ingress).

### Grafana dashboard using ingress resource
  - If you want to expose the dashboard for grafana using a ingress resource, then you can :
    - change the service type of the prometheus-server service and the grafana service to "ClusterIP" like this :
    ```
    kubectl -n ingress-nginx edit svc grafana
    ```
    - This will open the currently deployed service grafana in the default editor configured in your shell (vi/nvim/nano/other)
    - scroll down to line 34 that looks like "type: NodePort"
    - change it to look like "type: ClusterIP". Save and exit.
    - create a ingress resource with backend as "grafana" and port as "3000"
  - Similarly, you can edit the service "prometheus-server" and add a ingress resource.

## Prometheus and Grafana installation using Service Monitors
This document assumes you're using helm and using the kube-prometheus-stack package to install Prometheus and Grafana.

### Verify NGINX Ingress controller is installed

- The NGINX Ingress controller should already be deployed according to the deployment instructions [here](../deploy/index.md).

- To check if Ingress controller is deployed,
  ```
  kubectl get pods -n ingress-nginx
  ```
- The result should look something like:
  ```
  NAME                                        READY   STATUS    RESTARTS   AGE
  ingress-nginx-controller-7c489dc7b7-ccrf6   1/1     Running   0          19h
    ```

### Verify Prometheus is installed

- To check if Prometheus is already deployed, run the following command:

  ```
  helm ls -A
  ```
  ```
  NAME         	NAMESPACE    	REVISION	UPDATED                             	STATUS  	CHART                       	APP VERSION
  ingress-nginx	ingress-nginx	10      	2022-01-20 18:08:55.267373 -0800 PST	deployed	ingress-nginx-4.0.16        	1.1.1
  prometheus   	prometheus   	1       	2022-01-20 16:07:25.086828 -0800 PST	deployed	kube-prometheus-stack-30.1.0	0.53.1
  ```
- Notice that prometheus is installed in a differenet namespace than ingress-nginx

- If prometheus is not installed, then you can install from [here](https://artifacthub.io/packages/helm/prometheus-community/kube-prometheus-stack)

### Re-configure NGINX Ingress controller

- The Ingress NGINX controller needs to be reconfigured for exporting metrics. This requires 3 additional configurations to the controller. These configurations are :
  ```
  controller.metrics.enabled=true
  controller.metrics.serviceMonitor.enabled=true
  controller.metrics.serviceMonitor.additionalLabels.release="prometheus"
  ```
- The easiest way of doing this is to helm upgrade
  ```
  helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --set controller.metrics.enabled=true \
  --set controller.metrics.serviceMonitor.enabled=true \
  --set controller.metrics.serviceMonitor.additionalLabels.release="prometheus"
  ```
- Here `controller.metrics.serviceMonitor.additionalLabels.release="prometheus"` should match the name of the helm release of the `kube-prometheus-stack`

- You can validate that the controller has been successfully reconfigured to export metrics by looking at the values of the installed release, like this:
  ```
  helm get values ingress-nginx --namespace ingress-nginx
  ```
  ```
  controller:
    metrics:
      enabled: true
      serviceMonitor:
        additionalLabels:
          release: prometheus
        enabled: true
  ```
### Configure Prometheus

- Since Prometheus is running in a different namespace and not in the ingress-nginx namespace, it would not be able to discover ServiceMonitors in other namespaces when installed. Reconfigure your kube-prometheus-stack Helm installation to set `serviceMonitorSelectorNilUsesHelmValues` flag to false. By default, Prometheus only discovers PodMonitors within its own namespace. This should be disabled by setting `podMonitorSelectorNilUsesHelmValues` to false
- The configurations required are:
  ```
  prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false
  prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
  ```
- The easiest way of doing this is to use `helm upgrade ...`
  ```
  helm upgrade prometheus prometheus-community/kube-prometheus-stack \
  --namespace prometheus  \
  --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
  ```
- You can validate that Prometheus has been reconfigured by looking at the values of the installed release, like this:
  ```
  helm get values prometheus --namespace prometheus
  ```
- You should be able to see the values shown below:
  ```
  prometheus:
    prometheusSpec:
      podMonitorSelectorNilUsesHelmValues: false
      serviceMonitorSelectorNilUsesHelmValues: false
  ```

### Connect and view Prometheus dashboard
- Port forward to Prometheus service. Find out the name of the prometheus service by using the following command:
  ```
  kubectl get svc -n prometheus
  ```

  The result of this command would look like:
  ```
  NAME                                      TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)                      AGE
  alertmanager-operated                     ClusterIP   None             <none>        9093/TCP,9094/TCP,9094/UDP   7h46m
  prometheus-grafana                        ClusterIP   10.106.28.162    <none>        80/TCP                       7h46m
  prometheus-kube-prometheus-alertmanager   ClusterIP   10.108.125.245   <none>        9093/TCP                     7h46m
  prometheus-kube-prometheus-operator       ClusterIP   10.110.220.1     <none>        443/TCP                      7h46m
  prometheus-kube-prometheus-prometheus     ClusterIP   10.102.72.134    <none>        9090/TCP                     7h46m
  prometheus-kube-state-metrics             ClusterIP   10.104.231.181   <none>        8080/TCP                     7h46m
  prometheus-operated                       ClusterIP   None             <none>        9090/TCP                     7h46m
  prometheus-prometheus-node-exporter       ClusterIP   10.96.247.128    <none>        9100/TCP                     7h46m
  ```
  prometheus-kube-prometheus-prometheus is the service we want to port forward to. We can do so using the following command:
  ```
  kubectl port-forward svc/prometheus-kube-prometheus-prometheus -n prometheus 9090:9090
  ```
  When you run the above command, you should see something like:
  ```
  Forwarding from 127.0.0.1:9090 -> 9090
  Forwarding from [::1]:9090 -> 9090
  ```
- Open your browser and visit the following URL http://localhost:{port-forwarded-port} according to the above example it would be, http://localhost:9090

  ![Prometheus Dashboard](../images/prometheus-dashboard1.png)

### Connect and view Grafana dashboard
- Port forward to Grafana service. Find out the name of the Grafana service by using the following command:
  ```
  kubectl get svc -n prometheus
  ```

  The result of this command would look like:
  ```
  NAME                                      TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)                      AGE
  alertmanager-operated                     ClusterIP   None             <none>        9093/TCP,9094/TCP,9094/UDP   7h46m
  prometheus-grafana                        ClusterIP   10.106.28.162    <none>        80/TCP                       7h46m
  prometheus-kube-prometheus-alertmanager   ClusterIP   10.108.125.245   <none>        9093/TCP                     7h46m
  prometheus-kube-prometheus-operator       ClusterIP   10.110.220.1     <none>        443/TCP                      7h46m
  prometheus-kube-prometheus-prometheus     ClusterIP   10.102.72.134    <none>        9090/TCP                     7h46m
  prometheus-kube-state-metrics             ClusterIP   10.104.231.181   <none>        8080/TCP                     7h46m
  prometheus-operated                       ClusterIP   None             <none>        9090/TCP                     7h46m
  prometheus-prometheus-node-exporter       ClusterIP   10.96.247.128    <none>        9100/TCP                     7h46m
  ```
  prometheus-grafana is the service we want to port forward to. We can do so using the following command:
  ```
  kubectl port-forward svc/prometheus-grafana  3000:80 -n prometheus
  ```
  When you run the above command, you should see something like:
  ```
  Forwarding from 127.0.0.1:3000 -> 3000
  Forwarding from [::1]:3000 -> 3000
  ```
- Open your browser and visit the following URL http://localhost:{port-forwarded-port} according to the above example it would be, http://localhost:3000
  The default username/ password is admin/prom-operator
- After the login you can import the Grafana dashboard from [official dashboards](https://github.com/kubernetes/ingress-nginx/tree/main/deploy/grafana/dashboards), by following steps given below :

  - Navigate to lefthand panel of grafana
  - Hover on the gearwheel icon for Configuration and click "Data Sources"
  - Click "Add data source"
  - Select "Prometheus"
  - Enter the details (note: I used http://10.102.72.134:9090 which is the CLUSTER-IP for Prometheus service)
  - Left menu (hover over +) -> Dashboard
  - Click "Import"
  - Enter the copy pasted json from https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/grafana/dashboards/nginx.json
  - Click Import JSON
  - Select the Prometheus data source
  - Click "Import"

  ![Grafana Dashboard](../images/grafana-dashboard1.png)


## Exposed metrics

Prometheus metrics are exposed on port 10254.

### Request metrics

* `nginx_ingress_controller_request_duration_seconds` Histogram

  The request processing time in milliseconds (affected by client speed)

  nginx var: `request_time`

* `nginx_ingress_controller_response_duration_seconds` Histogram

  The time spent on receiving the response from the upstream server (affected by client speed)

  nginx var: `upstream_response_time`

* `nginx_ingress_controller_header_duration_seconds` Histogram

  The time spent on receiving first header from the upstream server

  nginx var: `upstream_header_time`

* `nginx_ingress_controller_connect_duration_seconds` Histogram

  The time spent on establishing a connection with the upstream server

  nginx var: `upstream_connect_time`

* `nginx_ingress_controller_response_size` Histogram

  The response length (including request line, header, and request body)

  nginx var: `bytes_sent`

* `nginx_ingress_controller_request_size` Histogram

  The request length (including request line, header, and request body)

  nginx var: `request_length`

* `nginx_ingress_controller_requests` Counter

  The total number of client requests

* `nginx_ingress_controller_bytes_sent` Histogram

  The number of bytes sent to a client. **Deprecated**, use `nginx_ingress_controller_response_size`

  nginx var: `bytes_sent`

* `nginx_ingress_controller_ingress_upstream_latency_seconds` Summary

  Upstream service latency per Ingress. **Deprecated**, use `nginx_ingress_controller_connect_duration_seconds`

  nginx var: `upstream_connect_time`

```
# HELP nginx_ingress_controller_bytes_sent The number of bytes sent to a client. DEPRECATED! Use nginx_ingress_controller_response_size
# TYPE nginx_ingress_controller_bytes_sent histogram
# HELP nginx_ingress_controller_connect_duration_seconds The time spent on establishing a connection with the upstream server
# TYPE nginx_ingress_controller_connect_duration_seconds nginx_ingress_controller_connect_duration_seconds
* HELP nginx_ingress_controller_header_duration_seconds The time spent on receiving first header from the upstream server
# TYPE nginx_ingress_controller_header_duration_seconds histogram
# HELP nginx_ingress_controller_ingress_upstream_latency_seconds Upstream service latency per Ingress DEPRECATED! Use nginx_ingress_controller_connect_duration_seconds
# TYPE nginx_ingress_controller_ingress_upstream_latency_seconds summary
# HELP nginx_ingress_controller_request_duration_seconds The request processing time in milliseconds
# TYPE nginx_ingress_controller_request_duration_seconds histogram
# HELP nginx_ingress_controller_request_size The request length (including request line, header, and request body)
# TYPE nginx_ingress_controller_request_size histogram
# HELP nginx_ingress_controller_requests The total number of client requests.
# TYPE nginx_ingress_controller_requests counter
# HELP nginx_ingress_controller_response_duration_seconds The time spent on receiving the response from the upstream server
# TYPE nginx_ingress_controller_response_duration_seconds histogram
# HELP nginx_ingress_controller_response_size The response length (including request line, header, and request body)
# TYPE nginx_ingress_controller_response_size histogram
```


### Nginx process metrics
```
# HELP nginx_ingress_controller_nginx_process_connections current number of client connections with state {active, reading, writing, waiting}
# TYPE nginx_ingress_controller_nginx_process_connections gauge
# HELP nginx_ingress_controller_nginx_process_connections_total total number of connections with state {accepted, handled}
# TYPE nginx_ingress_controller_nginx_process_connections_total counter
# HELP nginx_ingress_controller_nginx_process_cpu_seconds_total Cpu usage in seconds
# TYPE nginx_ingress_controller_nginx_process_cpu_seconds_total counter
# HELP nginx_ingress_controller_nginx_process_num_procs number of processes
# TYPE nginx_ingress_controller_nginx_process_num_procs gauge
# HELP nginx_ingress_controller_nginx_process_oldest_start_time_seconds start time in seconds since 1970/01/01
# TYPE nginx_ingress_controller_nginx_process_oldest_start_time_seconds gauge
# HELP nginx_ingress_controller_nginx_process_read_bytes_total number of bytes read
# TYPE nginx_ingress_controller_nginx_process_read_bytes_total counter
# HELP nginx_ingress_controller_nginx_process_requests_total total number of client requests
# TYPE nginx_ingress_controller_nginx_process_requests_total counter
# HELP nginx_ingress_controller_nginx_process_resident_memory_bytes number of bytes of memory in use
# TYPE nginx_ingress_controller_nginx_process_resident_memory_bytes gauge
# HELP nginx_ingress_controller_nginx_process_virtual_memory_bytes number of bytes of memory in use
# TYPE nginx_ingress_controller_nginx_process_virtual_memory_bytes gauge
# HELP nginx_ingress_controller_nginx_process_write_bytes_total number of bytes written
# TYPE nginx_ingress_controller_nginx_process_write_bytes_total counter
```

### Controller metrics
```
# HELP nginx_ingress_controller_build_info A metric with a constant '1' labeled with information about the build.
# TYPE nginx_ingress_controller_build_info gauge
# HELP nginx_ingress_controller_check_success Cumulative number of Ingress controller syntax check operations
# TYPE nginx_ingress_controller_check_success counter
# HELP nginx_ingress_controller_config_hash Running configuration hash actually running
# TYPE nginx_ingress_controller_config_hash gauge
# HELP nginx_ingress_controller_config_last_reload_successful Whether the last configuration reload attempt was successful
# TYPE nginx_ingress_controller_config_last_reload_successful gauge
# HELP nginx_ingress_controller_config_last_reload_successful_timestamp_seconds Timestamp of the last successful configuration reload.
# TYPE nginx_ingress_controller_config_last_reload_successful_timestamp_seconds gauge
# HELP nginx_ingress_controller_ssl_certificate_info Hold all labels associated to a certificate
# TYPE nginx_ingress_controller_ssl_certificate_info gauge
# HELP nginx_ingress_controller_success Cumulative number of Ingress controller reload operations
# TYPE nginx_ingress_controller_success counter
```

### Admission metrics
```
# HELP nginx_ingress_controller_admission_config_size The size of the tested configuration
# TYPE nginx_ingress_controller_admission_config_size gauge
# HELP nginx_ingress_controller_admission_render_duration The processing duration of ingresses rendering by the admission controller (float seconds)
# TYPE nginx_ingress_controller_admission_render_duration gauge
# HELP nginx_ingress_controller_admission_render_ingresses The length of ingresses rendered by the admission controller
# TYPE nginx_ingress_controller_admission_render_ingresses gauge
# HELP nginx_ingress_controller_admission_roundtrip_duration The complete duration of the admission controller at the time to process a new event (float seconds)
# TYPE nginx_ingress_controller_admission_roundtrip_duration gauge
# HELP nginx_ingress_controller_admission_tested_duration The processing duration of the admission controller tests (float seconds)
# TYPE nginx_ingress_controller_admission_tested_duration gauge
# HELP nginx_ingress_controller_admission_tested_ingresses The length of ingresses processed by the admission controller
# TYPE nginx_ingress_controller_admission_tested_ingresses gauge
```

### Histogram buckets

You can configure buckets for histogram metrics using these command line options (here are their default values):
* `--time-buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]`
* `--length-buckets=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]`
* `--size-buckets=[10, 100, 1000, 10000, 100000, 1e+06, 1e+07]`

##
#
#######
#######
#
##



<!--
-----------------NOTICE------------------------
This file is referenced in code as
https://github.com/kubernetes/ingress-nginx/blob/main/docs/troubleshooting.md
Do not move it without providing redirects.
-----------------------------------------------
-->

# Troubleshooting

## Ingress-Controller Logs and Events

There are many ways to troubleshoot the ingress-controller. The following are basic troubleshooting
methods to obtain more information.

### Check the Ingress Resource Events

```console
$ kubectl get ing -n <namespace-of-ingress-resource>
NAME           HOSTS      ADDRESS     PORTS     AGE
cafe-ingress   cafe.com   10.0.2.15   80        25s

$ kubectl describe ing <ingress-resource-name> -n <namespace-of-ingress-resource>
Name:             cafe-ingress
Namespace:        default
Address:          10.0.2.15
Default backend:  default-http-backend:80 (172.17.0.5:8080)
Rules:
  Host      Path  Backends
  ----      ----  --------
  cafe.com
            /tea      tea-svc:80 (<none>)
            /coffee   coffee-svc:80 (<none>)
Annotations:
  kubectl.kubernetes.io/last-applied-configuration:  {"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"annotations":{},"name":"cafe-ingress","namespace":"default","selfLink":"/apis/networking/v1/namespaces/default/ingresses/cafe-ingress"},"spec":{"rules":[{"host":"cafe.com","http":{"paths":[{"backend":{"serviceName":"tea-svc","servicePort":80},"path":"/tea"},{"backend":{"serviceName":"coffee-svc","servicePort":80},"path":"/coffee"}]}}]},"status":{"loadBalancer":{"ingress":[{"ip":"169.48.142.110"}]}}}

Events:
  Type    Reason  Age   From                      Message
  ----    ------  ----  ----                      -------
  Normal  CREATE  1m    ingress-nginx-controller  Ingress default/cafe-ingress
  Normal  UPDATE  58s   ingress-nginx-controller  Ingress default/cafe-ingress
```

### Check the Ingress Controller Logs

```console
$ kubectl get pods -n <namespace-of-ingress-controller>
NAME                                        READY     STATUS    RESTARTS   AGE
ingress-nginx-controller-67956bf89d-fv58j   1/1       Running   0          1m

$ kubectl logs -n <namespace> ingress-nginx-controller-67956bf89d-fv58j
-------------------------------------------------------------------------------
NGINX Ingress controller
  Release:    0.14.0
  Build:      git-734361d
  Repository: https://github.com/kubernetes/ingress-nginx
-------------------------------------------------------------------------------
....
```

### Check the Nginx Configuration

```console
$ kubectl get pods -n <namespace-of-ingress-controller>
NAME                                        READY     STATUS    RESTARTS   AGE
ingress-nginx-controller-67956bf89d-fv58j   1/1       Running   0          1m

$ kubectl exec -it -n <namespace-of-ingress-controller> ingress-nginx-controller-67956bf89d-fv58j -- cat /etc/nginx/nginx.conf
daemon off;
worker_processes 2;
pid /run/nginx.pid;
worker_rlimit_nofile 523264;
worker_shutdown_timeout 240s;
events {
	multi_accept        on;
	worker_connections  16384;
	use                 epoll;
}
http {
....
```

### Check if used Services Exist

```console
$ kubectl get svc --all-namespaces
NAMESPACE     NAME                   TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)         AGE
default       coffee-svc             ClusterIP   10.106.154.35    <none>        80/TCP          18m
default       kubernetes             ClusterIP   10.96.0.1        <none>        443/TCP         30m
default       tea-svc                ClusterIP   10.104.172.12    <none>        80/TCP          18m
kube-system   default-http-backend   NodePort    10.108.189.236   <none>        80:30001/TCP    30m
kube-system   kube-dns               ClusterIP   10.96.0.10       <none>        53/UDP,53/TCP   30m
kube-system   kubernetes-dashboard   NodePort    10.103.128.17    <none>        80:30000/TCP    30m
```

## Debug Logging

Using the flag `--v=XX` it is possible to increase the level of logging. This is performed by editing
the deployment.

```console
$ kubectl get deploy -n <namespace-of-ingress-controller>
NAME                       DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
default-http-backend       1         1         1            1           35m
ingress-nginx-controller   1         1         1            1           35m

$ kubectl edit deploy -n <namespace-of-ingress-controller> ingress-nginx-controller
# Add --v=X to "- args", where X is an integer
```

- `--v=2` shows details using `diff` about the changes in the configuration in nginx
- `--v=3` shows details about the service, Ingress rule, endpoint changes and it dumps the nginx configuration in JSON format
- `--v=5` configures NGINX in [debug mode](https://nginx.org/en/docs/debugging_log.html)

## Authentication to the Kubernetes API Server

A number of components are involved in the authentication process and the first step is to narrow
down the source of the problem, namely whether it is a problem with service authentication or
with the kubeconfig file.

Both authentications must work:

```
+-------------+   service          +------------+
|             |   authentication   |            |
+  apiserver  +<-------------------+  ingress   |
|             |                    | controller |
+-------------+                    +------------+
```

**Service authentication**

The Ingress controller needs information from apiserver. Therefore, authentication is required, which can be achieved in a couple of ways:

* _Service Account:_ This is recommended, because nothing has to be configured. The Ingress controller will use information provided by the system to communicate with the API server. See 'Service Account' section for details.

* _Kubeconfig file:_ In some Kubernetes environments service accounts are not available. In this case a manual configuration is required. The Ingress controller binary can be started with the `--kubeconfig` flag. The value of the flag is a path to a file specifying how to connect to the API server. Using the `--kubeconfig` does not requires the flag `--apiserver-host`.
   The format of the file is identical to `~/.kube/config` which is used by kubectl to connect to the API server. See 'kubeconfig' section for details.

* _Using the flag `--apiserver-host`:_ Using this flag `--apiserver-host=http://localhost:8080` it is possible to specify an unsecured API server or reach a remote kubernetes cluster using [kubectl proxy](https://kubernetes.io/docs/user-guide/kubectl/kubectl_proxy/).
   Please do not use this approach in production.

In the diagram below you can see the full authentication flow with all options, starting with the browser
on the lower left hand side.

```
Kubernetes                                                  Workstation
+---------------------------------------------------+     +------------------+
|                                                   |     |                  |
|  +-----------+   apiserver        +------------+  |     |  +------------+  |
|  |           |   proxy            |            |  |     |  |            |  |
|  | apiserver |                    |  ingress   |  |     |  |  ingress   |  |
|  |           |                    | controller |  |     |  | controller |  |
|  |           |                    |            |  |     |  |            |  |
|  |           |                    |            |  |     |  |            |  |
|  |           |  service account/  |            |  |     |  |            |  |
|  |           |  kubeconfig        |            |  |     |  |            |  |
|  |           +<-------------------+            |  |     |  |            |  |
|  |           |                    |            |  |     |  |            |  |
|  +------+----+      kubeconfig    +------+-----+  |     |  +------+-----+  |
|         |<--------------------------------------------------------|        |
|                                                   |     |                  |
+---------------------------------------------------+     +------------------+
```

### Service Account

If using a service account to connect to the API server, the ingress-controller expects the file
`/var/run/secrets/kubernetes.io/serviceaccount/token` to be present. It provides a secret
token that is required to authenticate with the API server.

Verify with the following commands:

```console
# start a container that contains curl
$ kubectl run -it --rm test --image=curlimages/curl --restart=Never -- /bin/sh

# check if secret exists
/ $ ls /var/run/secrets/kubernetes.io/serviceaccount/
ca.crt     namespace  token
/ $

# check base connectivity from cluster inside
/ $ curl -k https://kubernetes.default.svc.cluster.local
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {

  },
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {

  },
  "code": 403
}/ $

# connect using tokens
}/ $ curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H  "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc.cluster.local
&& echo
{
  "paths": [
    "/api",
    "/api/v1",
    "/apis",
    "/apis/",
    ... TRUNCATED
    "/readyz/shutdown",
    "/version"
  ]
}
/ $

# when you type `exit` or `^D` the test pod will be deleted.
```

If it is not working, there are two possible reasons:

1. The contents of the tokens are invalid. Find the secret name with `kubectl get secrets | grep service-account` and
   delete it with `kubectl delete secret <name>`. It will automatically be recreated.

2. You have a non-standard Kubernetes installation and the file containing the token may not be present.
   The API server will mount a volume containing this file, but only if the API server is configured to use
   the ServiceAccount admission controller.
   If you experience this error, verify that your API server is using the ServiceAccount admission controller.
   If you are configuring the API server by hand, you can set this with the `--admission-control` parameter.
   > Note that you should use other admission controllers as well. Before configuring this option, you should read about admission controllers.

More information:

- [User Guide: Service Accounts](http://kubernetes.io/docs/user-guide/service-accounts/)
- [Cluster Administrator Guide: Managing Service Accounts](http://kubernetes.io/docs/admin/service-accounts-admin/)

## Kube-Config

If you want to use a kubeconfig file for authentication, follow the [deploy procedure](deploy/index.md) and
add the flag `--kubeconfig=/etc/kubernetes/kubeconfig.yaml` to the args section of the deployment.

## Using GDB with Nginx

[Gdb](https://www.gnu.org/software/gdb/) can be used to with nginx to perform a configuration
dump. This allows us to see which configuration is being used, as well as older configurations.

Note: The below is based on the nginx [documentation](https://docs.nginx.com/nginx/admin-guide/monitoring/debugging/#dumping-nginx-configuration-from-a-running-process).

1. SSH into the worker

    ```console
    $ ssh user@workerIP
    ```

2. Obtain the Docker Container Running nginx

    ```console
    $ docker ps | grep ingress-nginx-controller
    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    d9e1d243156a        registry.k8s.io/ingress-nginx/controller   "/usr/bin/dumb-init …"   19 minutes ago      Up 19 minutes                                                                            k8s_ingress-nginx-controller_ingress-nginx-controller-67956bf89d-mqxzt_kube-system_079f31ec-aa37-11e8-ad39-080027a227db_0
    ```

3. Exec into the container

    ```console
    $ docker exec -it --user=0 --privileged d9e1d243156a bash
    ```

4. Make sure nginx is running in `--with-debug`

    ```console
    $ nginx -V 2>&1 | grep -- '--with-debug'
    ```

5. Get list of processes running on container

    ```console
    $ ps -ef
    UID        PID  PPID  C STIME TTY          TIME CMD
    root         1     0  0 20:23 ?        00:00:00 /usr/bin/dumb-init /nginx-ingres
    root         5     1  0 20:23 ?        00:00:05 /ingress-nginx-controller --defa
    root        21     5  0 20:23 ?        00:00:00 nginx: master process /usr/sbin/
    nobody     106    21  0 20:23 ?        00:00:00 nginx: worker process
    nobody     107    21  0 20:23 ?        00:00:00 nginx: worker process
    root       172     0  0 20:43 pts/0    00:00:00 bash
    ```

6. Attach gdb to the nginx master process

    ```console
    $ gdb -p 21
    ....
    Attaching to process 21
    Reading symbols from /usr/sbin/nginx...done.
    ....
    (gdb)
    ```

7. Copy and paste the following:

    ```console
    set $cd = ngx_cycle->config_dump
    set $nelts = $cd.nelts
    set $elts = (ngx_conf_dump_t*)($cd.elts)
    while ($nelts-- > 0)
    set $name = $elts[$nelts]->name.data
    printf "Dumping %s to nginx_conf.txt\n", $name
    append memory nginx_conf.txt \
            $elts[$nelts]->buffer.start $elts[$nelts]->buffer.end
    end
    ```

8. Quit GDB by pressing CTRL+D

9. Open nginx_conf.txt

    ```console
    cat nginx_conf.txt
    ```
    
## Image related issues faced on Nginx 4.2.5 or other versions (Helm chart versions) 

1. Incase you face below error while installing Nginx using helm chart (either by helm commands or helm_release terraform provider ) 
```
Warning  Failed     5m5s (x4 over 6m34s)   kubelet            Failed to pull image "registry.k8s.io/ingress-nginx/kube-webhook-certgen:v1.3.0@sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47": rpc error: code = Unknown desc = failed to pull and unpack image "registry.k8s.io/ingress-nginx/kube-webhook-certgen@sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47": failed to resolve reference "registry.k8s.io/ingress-nginx/kube-webhook-certgen@sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47": failed to do request: Head "https://eu.gcr.io/v2/k8s-artifacts-prod/ingress-nginx/kube-webhook-certgen/manifests/sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47": EOF
```
   Then please follow the below steps.

2. During troubleshooting you can also execute the below commands to test the connectivities from you local machines and repositories  details

      a. curl registry.k8s.io/ingress-nginx/kube-webhook-certgen@sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47 > /dev/null
      ```
      (⎈ |myprompt)➜  ~ curl registry.k8s.io/ingress-nginx/kube-webhook-certgen@sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47 > /dev/null
                          % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                                          Dload  Upload   Total   Spent    Left  Speed
                          0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
       (⎈ |myprompt)➜  ~
      ```
      b. curl -I https://eu.gcr.io/v2/k8s-artifacts-prod/ingress-nginx/kube-webhook-certgen/manifests/sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47
      ```
      (⎈ |myprompt)➜  ~ curl -I https://eu.gcr.io/v2/k8s-artifacts-prod/ingress-nginx/kube-webhook-certgen/manifests/sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47
                                          HTTP/2 200
                                          docker-distribution-api-version: registry/2.0
                                          content-type: application/vnd.docker.distribution.manifest.list.v2+json
                                          docker-content-digest: sha256:549e71a6ca248c5abd51cdb73dbc3083df62cf92ed5e6147c780e30f7e007a47
                                          content-length: 1384
                                          date: Wed, 28 Sep 2022 16:46:28 GMT
                                          server: Docker Registry
                                          x-xss-protection: 0
                                          x-frame-options: SAMEORIGIN
                                          alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

        (⎈ |myprompt)➜  ~
      ```
   Redirection in the proxy is implemented to ensure the pulling of the images.

3. This is the solution recommended to whitelist the below image repositories : 
     ```
     *.appspot.com    
     *.k8s.io        
     *.pkg.dev
     *.gcr.io
     
     ```
     More details about the above repos : 
     a. *.k8s.io -> To ensure you can pull any images from registry.k8s.io
     b. *.gcr.io -> GCP services are used for image hosting. This is part of the domains suggested by GCP to allow and ensure users can pull images from their container registry services.
     c. *.appspot.com -> This a Google domain. part of the domain used for GCR.

## Unable to listen on port (80/443)
One possible reason for this error is lack of permission to bind to the port.  Ports 80, 443, and any other port < 1024 are Linux privileged ports which historically could only be bound by root.  The ingress-nginx-controller uses the CAP_NET_BIND_SERVICE [linux capability](https://man7.org/linux/man-pages/man7/capabilities.7.html) to allow binding these ports as a normal user (www-data / 101).  This involves two components:
1. In the image, the /nginx-ingress-controller file has the cap_net_bind_service capability added (e.g. via [setcap](https://man7.org/linux/man-pages/man8/setcap.8.html)) 
2. The NET_BIND_SERVICE capability is added to the container in the containerSecurityContext of the deployment.

If encountering this on one/some node(s) and not on others, try to purge and pull a fresh copy of the image to the affected node(s), in case there has been corruption of the underlying layers to lose the capability on the executable.

### Create a test pod
The /nginx-ingress-controller process exits/crashes when encountering this error, making it difficult to troubleshoot what is happening inside the container.  To get around this, start an equivalent container running "sleep 3600", and exec into it for further troubleshooting.  For example:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ingress-nginx-sleep
  namespace: default
  labels:
    app: nginx
spec:
  containers:
    - name: nginx
      image: ##_CONTROLLER_IMAGE_##
      resources:
        requests:
          memory: "512Mi"
          cpu: "500m"
        limits:
          memory: "1Gi"
          cpu: "1"
      command: ["sleep"]
      args: ["3600"]
      ports:
      - containerPort: 80
        name: http
        protocol: TCP
      - containerPort: 443
        name: https
        protocol: TCP
      securityContext:
        allowPrivilegeEscalation: true
        capabilities:
          add:
          - NET_BIND_SERVICE
          drop:
          - ALL
        runAsUser: 101
  restartPolicy: Never
  nodeSelector:
    kubernetes.io/hostname: ##_NODE_NAME_##
  tolerations:
  - key: "node.kubernetes.io/unschedulable"
    operator: "Exists"
    effect: NoSchedule
```
* update the namespace if applicable/desired
* replace `##_NODE_NAME_##` with the problematic node (or remove nodeSelector section if problem is not confined to one node)
* replace `##_CONTROLLER_IMAGE_##` with the same image as in use by your ingress-nginx deployment
* confirm the securityContext section matches what is in place for ingress-nginx-controller pods in your cluster

Apply the YAML and open a shell into the pod.
Try to manually run the controller process:
```console
$ /nginx-ingress-controller
```
You should get the same error as from the ingress controller pod logs.

Confirm the capabilities are properly surfacing into the pod:
```console
$ grep CapBnd /proc/1/status
CapBnd: 0000000000000400
```
The above value has only net_bind_service enabled (per security context in YAML which adds that and drops all). If you get a different value, then you can decode it on another linux box (capsh not available in this container) like below, and then figure out why specified capabilities are not propagating into the pod/container.
```console
$ capsh --decode=0000000000000400
0x0000000000000400=cap_net_bind_service
```

## Create a test pod as root
(Note, this may be restricted by PodSecurityPolicy, PodSecurityAdmission/Standards, OPA Gatekeeper, etc. in which case you will need to do the appropriate workaround for testing, e.g. deploy in a new namespace without the restrictions.)
To test further you may want to install additional utilities, etc.  Modify the pod yaml by:
* changing runAsUser from 101 to 0
* removing the "drop..ALL" section from the capabilities.

Some things to try after shelling into this container:

Try running the controller as the www-data (101) user:
```console
$ chmod 4755 /nginx-ingress-controller
$ /nginx-ingress-controller
```
Examine the errors to see if there is still an issue listening on the port or if it passed that and moved on to other expected errors due to running out of context.

Install the libcap package and check capabilities on the file:
```console
$ apk add libcap
(1/1) Installing libcap (2.50-r0)
Executing busybox-1.33.1-r7.trigger
OK: 26 MiB in 41 packages
$ getcap /nginx-ingress-controller
/nginx-ingress-controller cap_net_bind_service=ep
```
(if missing, see above about purging image on the server and re-pulling)

Strace the executable to see what system calls are being executed when it fails:
```console
$ apk add strace
(1/1) Installing strace (5.12-r0)
Executing busybox-1.33.1-r7.trigger
OK: 28 MiB in 42 packages
$ strace /nginx-ingress-controller
execve("/nginx-ingress-controller", ["/nginx-ingress-controller"], 0x7ffeb9eb3240 /* 131 vars */) = 0
arch_prctl(ARCH_SET_FS, 0x29ea690)      = 0
...
```
