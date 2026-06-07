
##
#
https://allthingsopen.org/articles/introduction-to-falco
#
##

Introduction to Falco and how to set up rules
Learn how this open source runtime security tool fits into the cloud, container, and software ecosystem.
By Nigel Douglas
Perched falcon with red and brown feathers
Image by Manfred Richter from Pixabay

Falco, a CNCF (Cloud Native Computing Foundation) project donated by Sysdig, has made significant strides in providing critical insights into the operations of cloud, container, and Linux environments. After achieving CNCF Graduation at KubeCon Europe earlier this year, Falco joined the ranks of other mature projects such as Kubernetes and Cilium. But what isFalco’s role in the cloud, container, and software ecosystems?
What is Falco?

Falco is an open source runtime security tool designed to monitor and detect anomalous behaviour in your cloud, container, and Linux environments. It acts as a security guard, keeping an eye on the activities within your systems and alerting you to any suspicious behaviour that could indicate a security threat. Falco can monitor system calls and other activity in real-time, providing deep visibility into the behaviour of your applications and infrastructure.
Extended use-cases

While Falco’s core strength lies in monitoring system calls, its functionality has been extended to other areas through the use of gRPC plugins. These plugin extensions enable Falco to integrate with 3rd party event streams from platforms such as GitHub and Okta. Set up Falco to serve events via the gRPC Server. For instance:

    GitHub: Falco can monitor GitHub events to detect suspicious activities such as unauthorised repository access or modifications.
    Okta: Integrating the Okta Plugin allows Falco to monitor authentication and authorization events, providing an additional layer of security for user management in the cloud.
    Bitcoin: Falco can even be used to analyse Bitcoin transactions to identify unusual patterns that might indicate fraudulent activities. While this use case goes beyond the scope of cloud security, it demonstrates the flexible nature of Falco in how plugins can be built for novel security incidents.

How to implement Falco

Getting started with Falco is straightforward, read the installation options.

Here are the steps to get it up and running in your environment:
Installation (the easy way)

Kubernetes: If you are running Kubernetes, you can deploy Falco using Helm.

First, add the Helm repository:

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

Then, install Falco with:

helm install falco falcosecurity/falco

Docker: To run Falco in Docker, you can install it with a single-line command:
```
docker run -d --name falco --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc -v /boot:/host/boot -v /lib/modules:/host/lib/modules falcosecurity/falco
```
Build Falco from source:
You can build Falco or its libraries yourself from the source code.
Installation (the real way)

Falco is also highly dynamic for production systems where large volumes of complex rules, deep security observability and response capabilities are required with limited downtime, limited effect on system performance as well as a need for real-time system forensics.

The below helm install command is certainly noisier than the previous simple install commands, but this shines a light on how far the Falco project has come since its inception.
```
helm install falco falcosecurity/falco --namespace falco \
 --create-namespace \
 --set tty=true \
 --set falcosidekick.enabled=true \
 --set falcosidekick.webui.enabled=true \
 --set falcosidekick.webui.redis.storageEnabled=false \
 --set falcosidekick.config.webhook.address=http://falco-talon:2803 \
 --set collectors.containerd.socket=/run/k3s/containerd/containerd.sock \
 --set "falcoctl.config.artifact.install.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
 --set "falcoctl.config.artifact.follow.refs={falco-rules:2,falco-incubating-rules:2,falco-sandbox-rules:2}" \
 --set "falco.rules_file={/etc/falco/falco_rules.yaml,/etc/falco/falco-incubating_rules.yaml,/etc/falco/falco-sandbox_rules.yaml,/etc/falco/rules.d}" \
 -f custom-rules.yaml
```

Breakdown of what’s happening:

    tty=true: Ensures events are handled in real time.
    falcosidekick: In this case, falcosidekick has 2 responsibilities; firstly, to serve as a web user interface (webui) for Falco security alerts, but secondly, to trigger automated webhook actions to the address http://falco-talon:2803.
    falco-talon: If Falco Talon is installed alongside Falco and falcosidekick, it operates as a dedicated response engine to threats detected by Falco via falcosidekick automation.
    containerd.enabled=true: If you are using K3s with containerd, you can set the CRI settings because the socket path would be different from the default setting configured in Falco.
    Falcoctl: The Falco command line tool is an out-of-the-box solution to manage the lifecycle of Falco rules (such as installation and updates) from different referenced artefacts.
    -f custom-rules.yaml: Other than the enabling/disabling rules sources (artefacts) via falcoctl, there is the option of writing, editing or disabling individual rules via a custom rules file.

What “the easy” installation methods fail to clarify is that they only make use of the stable rules by default. Default rules are maintained by the maintainers directly with contributions from the community. This ensures they are stable for production-ready environments, with fewer potential false/positive detections or require large amounts of customisation in order to detect threats appropriately in a unique environment.

In reality, organisations that use Falco are going to manage different sources and need to enable/disable these in a flexible manner. So, we know Falco provides flexibility for deployments and upgrades, but what about the rules, how do those work?
Setting up Falco rules

Falco uses rules to define the behaviour it monitors.  These rules are YAML files that specify what constitutes suspicious activity. This is great because cloud-native operations are mainly controlled via YAML – the language of cloud-native.

As mentioned earlier, rules feeds exist by default to get users up and running with Falco. These rule feeds are segregated based on the gRPC plugin associated with the rules feed (K8sAudit, Okta, AWS Cloudtrail etc), and are also segregated based on the rules maturity framework.

You can access the full list of default rules, and associated lists/macros via the Falco Rules Explorer:
https://thomas.labarussias.fr/falco-rules-explorer/?type=rule 
What to look out for

When setting up Falco rules, it’s important to define rules that are specific to your environment and its security needs. Consider:

    File Access: Monitoring access to sensitive files.
    Network Connections: Watching for unexpected network connections.
    Process Activity: Detect unusual process activity, such as running a shell inside a container.

Standard rule sets

Falco comes with a set of standard rules that cover a wide range of common security scenarios. These rules can be a great starting point. You can find them in the rules directory of the Falco GitHub repository or included with the default installation.
Implementing your own rules

To create your own rules, you need to understand the structure of a Falco rule:

- rule: Write below etc
 desc: An attempt to write to /etc directory
 condition: evt.type = write and fd.name startswith /etc
 output: "File below /etc opened for writing (user=%user.name, file=%fd.name)"
 priority: WARNING
 tags: [filesystem, mitre_persistence]

    Rule Name: A descriptive name for the rule.
    Description: A brief explanation of what the rule does.
    Condition: The logic that defines the rule’s trigger.
    This is typically based on system call events and their parameters.
    Output: The message that Falco will log when the rule is triggered.
    Priority: The severity level of the alert can classified by arbitary names.
    (e.g., EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG).
    Tags: Arbitrary keywords can also be assigned to help categorise those rules.
    (eg., MITRE ATT&CK Tactic IDs, PCI-DSS Controls, or app-specific contexts).

Insights delivered by Falco

Falco provides real-time visibility into your workloads, 
offering insights that are crucial for maintaining security and operational efficiency. 
Falco’s architecture allows you to capture events from different data sources, as already discussed. 
This process delivers raw data, which can be very rich but isn’t very useful for runtime security unless paired with the right context. 

That’s why Falco first extracts and then enriches the raw data with contextual information so that the rule author can comfortably use it. Typically, we refer to this information as the event metadata. Getting metadata is normally a complex task, and getting it efficiently is even more complex. So, having Falco do data enrichment behind the scenes means we get the deepest level of visibility.
