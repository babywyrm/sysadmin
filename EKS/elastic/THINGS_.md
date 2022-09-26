

##
#
https://medium.com/kocsistem/elk-stack-in-kubernetes-using-helm-52398564f7fc
#
##


ELK Stack in Kubernetes Using Helm
What is ELK Stack?

    “ELK Stack is the leading open-source IT log management solution for companies who want the benefits of a centralized logging solution without the enterprise software price. Elasticsearch, Logstash, and Kibana when used together, form an end-to-end stack (ELK Stack) and real-time data analytics tool that provides actionable insights from almost any type of structured and unstructured data source.”

What are these tools and what are they doing?

Elasticsearch: Elasticsearch is a distributed, free and open search and analytics engine for all types of data, including textual, numerical, geospatial, structured, and unstructured.

Logstash: Logstash is a light-weight, open-source, server-side data processing pipeline that allows you to collect data from a variety of sources, transform it on the fly, and send it to your desired destination.

Kibana: Kibana is an free and open frontend application that sits on top of the Elastic Stack, providing search and data visualization capabilities for data indexed in Elasticsearch.

Filebeat: Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.
Why do we use ELK?

As benefits of ELK Stack, we can have a list as below.

    It is open-source and free.
    It can securely pull, analyze and visualize data, in real time, from any source and format.
    It is simple to set up and user friendly.
    It can perform centralized logging to help identify any server and application-related issues across multiple servers and correlate the logs in a particular time frame.
    It is a total log-analysis platform for search, analyses and visualization of log-generated data from different machine.

Configuration of ELK Stack

Firstly, we will import helm charts to our repository.

Helm is a Kubernetes package and operations manager and Helm Charts are used to deploy an application, or one component of a larger application.

Elasticsearch

Since we have a helm chart, we do not need to do many things but if you want to use elastic search without username and password like me, you need to add following line under elastic.yml in values.yaml

esConfig:
  elasticsearch.yml: |
    xpack.security.enabled: false

Also, I wanted to access elasticsearch from browser so I configured services as NodePort.

To do that, you need to change the configuration of service in values.yaml as following.

service:
  enabled: true
  labels: {}
  labelsHeadless: {}
  type: NodePort
  nodePort: "30234"
  annotations: {}
  httpPortName: http
  transportPortName: transport
  loadBalancerIP: ""
  loadBalancerSourceRanges: []
  externalTrafficPolicy: ""

Now, we can deploy it to our cluster. I used Azure Pipelines for deployment and here is my azure-pipelines.yml

- task: HelmDeploy@0
  inputs:
    connectionType: 'Kubernetes Service Connection'
    kubernetesServiceConnection: 'Kubernetes-Cluster'
    namespace: 'monitoring'
    command: 'install'
    chartType: 'FilePath'
    chartPath: '$(Build.SourcesDirectory)/elasticsearch'
    releaseName: 'elasticsearch'
    valueFile: '$(Build.SourcesDirectory)/elasticsearch/values.yaml'

After pipeline is finished, we can check resources in the cluster and its endpoint from browser.

Logstash

We need more touch for logstash because we will create pipeline for not only filebeat but also an external server.

Since we need to reach logstash from the external server, logstash service also must run as NodePort. To do that, we will edit service-headless.yaml under templates folder.

The reason why we edit the service-headless.yaml is logstash service will be created as headless by helm chart.

The only changes in service-headless.yaml is under spec.

spec:
 type: NodePort
 selector:
 app: “{{ template “logstash.fullname” . }}”
 ports:
 — name: http
 port: {{ .Values.httpPort }}
 nodePort: 31123
 — name: tcp
 port: 9500 
 nodePort: 30123

You may notice that I added another name, tcp. This will be used for external server’s pipeline.

There are some important changes in values.yaml.

First of all, we need to create separate pipelines for two different sources under logstashConfig.

logstashConfig:
  logstash.yml: |
    http.host: 0.0.0.0
    pipeline.ecs_compatibility: disabled
  pipelines.yml: |
    - pipeline.id: logstash
      path.config: "/usr/share/logstash/pipeline/logstash.conf"
    - pipeline.id: devopsdashboard
      path.config: "/usr/share/logstash/pipeline/devopsdashboard.conf"
      pipeline.workers: 3
  log4j2.properties: |
    logger.logstashpipeline.name = logstash.inputs.beats
    logger.logstashpipeline.level = error

(Optional) In the configuration above, I added a line for ecs_compability because there were too many logs as warning. Also edited log4j properties to collect only error logs from beats.

Then, we will create our pipelines under logstashPipeline.

logstashPipeline:
  logstash.conf: |
    input {
      beats {
        port => 5044
      }
    }
    filter {
    }
    output {
      elasticsearch {
        index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
        hosts => [ "elasticsearch-master:9200" ]
      }
    }
  devopsdashboard.conf: |
    input {
      tcp {
        port => 9500
        codec => json
      }
    }
    filter {
        }
    }
    output {
      elasticsearch {
        index => "devopsdashboard-%{+YYYY.MM.dd}"
        hosts => [ "elasticsearch-master:9200" ]
      }
    }

Filebeat will send logs to port 5044 and the external server will send logs to port 30123 which routes to 9500 in the cluster.

And finally I added extraPorts for logstash under extraPorts in values.yaml.

extraPorts:
  - name: tcpport
    containerPort: 9500

Now, we can deploy it to the cluster.

- task: HelmDeploy@0
  displayName: Helm Install
  inputs:
    connectionType: 'Kubernetes Service Connection'
    kubernetesServiceConnection: 'Kubernetes-Cluster'
    namespace: 'monitoring'
    command: 'install'
    chartType: 'FilePath'
    chartPath: '$(Build.SourcesDirectory)/logstash'
    releaseName: 'logstash'
    valueFile: '$(Build.SourcesDirectory)/logstash/values.yaml'

Let’s check our resources and endpoint.

Filebeat

We need to change output with logstash in values.yaml. Here is filebeatConfig.

filebeatConfig:
    filebeat.yml: |
      filebeat.inputs:
      - type: container
        paths:
          - /var/log/containers/*.log
        processors:
        - add_kubernetes_metadata:
            host: ${NODE_NAME}
            matchers:
            - logs_path:
                logs_path: "/var/log/containers/"
      logging.level: error
      output.logstash:
        hosts: ["logstash-logstash-0.logstash-logstash-headless.monitoring.svc.cluster.local:5044"]

Let’s deploy it.

- task: HelmDeploy@0
  displayName: Helm Install
  inputs:
    connectionType: 'Kubernetes Service Connection'
    kubernetesServiceConnection: 'Kubernetes-Cluster'
    namespace: 'monitoring'
    command: 'install'
    chartType: 'FilePath'
    chartPath: '$(Build.SourcesDirectory)/filebeat'
    releaseName: 'filebeat'
    valueFile: '$(Build.SourcesDirectory)/filebeat/values.yaml'

After pipelines is done, we can check our pods.

Kibana

To access Kibana through browser with a secure endpoint, we will configure ingress in values.yaml

ingress:
  enabled: false
  className: "nginx"
  pathtype: ImplementationSpecific
  annotations:
   kubernetes.io/ingress.class: nginx
  hosts:
    - host: your_host
      paths:
        - backend:
      serviceName: kibana-kibana
   servicePort: 5601
  tls: 
    - secretName: your_secret
      hosts:
        - your_host

Now, we can deploy Kibana.

- task: HelmDeploy@0
  inputs:
    connectionType: 'Kubernetes Service Connection'
    kubernetesServiceConnection: 'KubeOps-Cluster'
    namespace: 'monitoring'
    command: 'install'
    chartType: 'FilePath'
    chartPath: '$(Build.SourcesDirectory)/kibana'
    releaseName: 'kibana'
    valueFile: '$(Build.SourcesDirectory)/kibana/values.yaml'

Here our Kibana is.
Send Logs from External Server to Logstash

In the external server, I use NLog for logging and configured it for my new Logstash intance. You can edit the following line to send logs to Logstash via TCP.

<target name="logstashException" xsi:type="Network" address="tcp://your_cluster_ip:30123" newLine="true">

Warning: Do not forget to define firewall rules to reach Logstash.
View Logs in Kibana

We need to define index patterns to be able to see logs in Kibana.

From homepage, write Kibana / Index Patterns to search bar. Go to Index patterns page and click to Create index pattern on the right corner. You will see the list of index patterns here.
