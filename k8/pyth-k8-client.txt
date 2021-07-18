Kubernetes Python Client

##
##

https://travis-ci.org/kubernetes-client/python.svg?branch=master https://badge.fury.io/py/kubernetes.svg https://codecov.io/gh/kubernetes-client/python/branch/master/graph/badge.svg https://img.shields.io/pypi/pyversions/kubernetes.svg https://img.shields.io/badge/Kubernetes%20client-Silver-blue.svg?style=flat&colorB=C0C0C0&colorA=306CE8 https://img.shields.io/badge/kubernetes%20client-beta-green.svg?style=flat&colorA=306CE8

Python client for the kubernetes API.
Installation

From source:

git clone --recursive https://github.com/kubernetes-client/python.git
cd python
python setup.py install

From PyPi directly:

pip install kubernetes

Examples

list all pods:

from kubernetes import client, config

# Configs can be set in Configuration class directly or using helper utility
config.load_kube_config()

v1 = client.CoreV1Api()
print("Listing pods with their IPs:")
ret = v1.list_pod_for_all_namespaces(watch=False)
for i in ret.items:
    print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))

watch on namespace object:

from kubernetes import client, config, watch

# Configs can be set in Configuration class directly or using helper utility
config.load_kube_config()

v1 = client.CoreV1Api()
count = 10
w = watch.Watch()
for event in w.stream(v1.list_namespace, _request_timeout=60):
    print("Event: %s %s" % (event['type'], event['object'].metadata.name))
    count -= 1
    if not count:
        w.stop()

print("Ended.")

More examples can be found in examples folder. To run examples, run this command:

python -m examples.example1

