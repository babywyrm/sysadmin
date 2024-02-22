##
##
## https://gist.github.com/sneumann/c6976aaf771dbb6b2de7d6291f688778
##
##


import pykube
from os import environ as os_environ

# pykube imports:
try:
    from pykube.config import KubeConfig
    from pykube.http import HTTPClient
    from pykube.objects import (
        Job,
        Pod
    )
except ImportError as exc:
    KubeConfig = None
    print ('The Python pykube package is required to use '
           'this feature, please install it or correct the '
           'following error:\nImportError %s' % str(exc))

# This creates the PyKube configuration from ~/.kube/config
pykube_api = HTTPClient(KubeConfig.from_file())

# This creates the PyKube configuration if run from inside a Pod
# pykube_api = HTTPClient(KubeConfig.from_service_account())

k8s_job_name = "newjob"
k8s_job_obj = {
  "apiVersion": "batch/v1", #runner_param_specs['k8s_job_api_version'],
  "kind": "Job",
  "metadata": {
          # metadata.name is the name of the pod resource created, and must be unique
          # http://kubernetes.io/docs/user-guide/configuring-containers/
          "name": k8s_job_name,
          "namespace": "tapir", # "default",  # TODO this should be set
          "labels": {"app": k8s_job_name},
      },
  "spec": {
    "template": {
    "metadata": {
            "name": k8s_job_name,
            "namespace": "tapir", # "default",  # TODO this should be set
            "labels": {"app": k8s_job_name},
        },
    "spec": {
      "containers": [{
          "name": "c",
          "image": "debian:latest",
          "command": ["sh", "-c", "date ; sleep 60"]
      }],
      "restartPolicy": "Never"
     }
    }
  }    
}

# Actually create that job
Job(pykube_api, k8s_job_obj).create()

##
##
