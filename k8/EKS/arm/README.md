# EKS on Arm

The `xarm-install-graviton2.sh` script allows you to install and use [Amazon EKS on Arm](https://docs.aws.amazon.com/eks/latest/userguide/arm-support.html) (xARM) with a single command.
In essence, it automates the steps described in the docs.

Make sure you have `aws`, `eksctl`, `kubectl`, and `jq` installed, this will be checked on start-up and the script will fail if these deps are not present. So far tested with bash on macOS.

```sh
$ chmod +x xarm-install-graviton2.sh
$ ./xarm-install-graviton2.sh
```

After some 15min the install should complete and you should see `DONE`. That means you can check the data plane:

```sh
$ kubectl get nodes --show-labels
NAME                                           STATUS   ROLES    AGE   VERSION               LABELS
ip-192-168-15-231.eu-west-1.compute.internal   Ready    <none>   48m   v1.15.11-eks-065dce   beta.kubernetes.io/arch=arm64,beta.kubernetes.io/instance-type=m6g.medium,beta.kubernetes.io/os=linux,failure-domain.beta.kubernetes.io/region=eu-west-1,failure-domain.beta.kubernetes.io/zone=eu-west-1a,kubernetes.io/arch=arm64,kubernetes.io/hostname=ip-192-168-15-231.eu-west-1.compute.internal,kubernetes.io/os=linux
ip-192-168-33-98.eu-west-1.compute.internal    Ready    <none>   48m   v1.15.11-eks-065dce   beta.kubernetes.io/arch=arm64,beta.kubernetes.io/instance-type=m6g.medium,beta.kubernetes.io/os=linux,failure-domain.beta.kubernetes.io/region=eu-west-1,failure-domain.beta.kubernetes.io/zone=eu-west-1c,kubernetes.io/arch=arm64,kubernetes.io/hostname=ip-192-168-33-98.eu-west-1.compute.internal,kubernetes.io/os=linux
ip-192-168-48-242.eu-west-1.compute.internal   Ready    <none>   47m   v1.15.11-eks-065dce   beta.kubernetes.io/arch=arm64,beta.kubernetes.io/instance-type=m6g.medium,beta.kubernetes.io/os=linux,failure-domain.beta.kubernetes.io/region=eu-west-1,failure-domain.beta.kubernetes.io/zone=eu-west-1c,kubernetes.io/arch=arm64,kubernetes.io/hostname=ip-192-168-48-242.eu-west-1.compute.internal,kubernetes.io/os=linux
```
