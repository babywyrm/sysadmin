
##
#
https://stackoverflow.com/questions/55672498/kubernetes-cluster-stuck-on-removing-pv-pvc
#
https://github.com/kubernetes/kubernetes/issues/120756
#
https://github.com/rook/rook/issues/2746
#
##


```
applying:
kubectl patch pvc 593b32132d4d2435-volume-claim -p '{"metadata":{"finalizers":null}}'

did work.

here is the describe result of a stuck pvc and its pv::

Name:          5c798ebd14d899e4-volume-claim
Namespace:     default
StorageClass:  rook-ceph-block
Status:        Terminating (lasts <invalid>)
Volume:        pvc-ecdcb328-3c4b-11e9-b109-06d2222521f6
Labels:        <none>
Annotations:   pv.kubernetes.io/bind-completed: yes
               pv.kubernetes.io/bound-by-controller: yes
               volume.beta.kubernetes.io/storage-provisioner: ceph.rook.io/block
Finalizers:    [kubernetes.io/pvc-protection]
Capacity:      200Gi
Access Modes:  RWO
Events:        <none>
Mounted By:    5c798ebd14d899e4-0-m1-main-job-hrvcg
               5c798ebd14d899e4-1-m2-main-job-nhqlp
               5c798ebd14d899e4-workflow-initializer-job-9rw92
               5c798ebd14d899e4-workflow-uploader-job-d7vsx
------------------------------------------------------------
Name:            pvc-ecdcb328-3c4b-11e9-b109-06d2222521f6
Labels:          <none>
Annotations:     pv.kubernetes.io/provisioned-by: ceph.rook.io/block
Finalizers:      [kubernetes.io/pv-protection]
StorageClass:    rook-ceph-block
Status:          Bound
Claim:           default/5c798ebd14d899e4-volume-claim
Reclaim Policy:  Delete
Access Modes:    RWO
Capacity:        200Gi
Node Affinity:   <none>
Message:
Source:
    Type:       FlexVolume (a generic volume resource that is provisioned/attached using an exec based plugin)
    Driver:     ceph.rook.io/rook-ceph-system
    FSType:
    SecretRef:  nil
    ReadOnly:   false
    Options:    map[dataBlockPool: image:pvc-ecdcb328-3c4b-11e9-b109-06d2222521f6 pool:replicapool storageClass:rook-ceph-block clusterNamespace:rook-ceph]
Events:         <none>```

```

I am been struggling to get my simple 3 node Kubernetes cluster running.

$ kubectl get nodes                                                                                    NAME   STATUS   ROLES         AGE   VERSION
ubu1   Ready    master        31d   v1.13.4
ubu2   Ready    master,node   31d   v1.13.4
ubu3   Ready    node          31d   v1.13.4

I tried creating a PVC, which was stuck in Pending forever. So I deleted it, but now it is stuck in Terminating status.

$ kubectl get pvc
NAME                        STATUS        VOLUME           CAPACITY   ACCESS MODES   STORAGECLASS      AGE
task-pv-claim               Terminating   task-pv-volume   100Gi      RWO            manual            26d

How can I create a PV that is properly created and useable for the demos described on the official kubernetes web site?

PS: I used kubespray to get this up and running.

On my Ubuntu 16.04 VMs, this is the Docker version installed:

ubu1:~$ docker version
Client:
 Version:           18.06.2-ce
 API version:       1.38
 Go version:        go1.10.3
 Git commit:        6d37f41
 Built:             Sun Feb 10 03:47:56 2019
 OS/Arch:           linux/amd64
 Experimental:      false

Thanks in advance.

    kubernetes

Share
Improve this question
Follow
edited Nov 22, 2023 at 8:55
Jesper Vikkelsø Riemer's user avatar
Jesper Vikkelsø Riemer
65511 gold badge88 silver badges2121 bronze badges
asked Apr 14, 2019 at 6:19
farhany's user avatar
farhany
1,50133 gold badges2121 silver badges3333 bronze badges

    1
    Have you tried first removing .metadata.finalizers from your PV/PVC and then delete the PV/PVC? – 
    Shudipta Sharma
    Commented Apr 14, 2019 at 6:29
    @ShudiptaSharma where do I find this to remove? I don't have it in the YAML deployment files. – 
    farhany
    Commented Apr 14, 2019 at 6:57
    1
    You can use $ kubectl edit pvc <pvc_name> command. Then the yaml configuration will appear on your terminal with the default editor (specified by $KUBE_EDITOR environment variable may be). If it is open with vim or vi then run appropriate command to remove those line or do as what you need for the editor. – 
    Shudipta Sharma
    Commented Apr 14, 2019 at 8:32

Add a comment
6 Answers
Sorted by:
119

kubectl edit pv (pv name)

Find the following in the manifest file

finalizers:
  -  kubernetes.io/pv-protection

... and delete it.

Then exit, and run this command to delete the pv

kubectl delete pv (pv name) --grace-period=0 --force

Share
Improve this answer
Follow
edited Sep 14, 2022 at 15:13
Gerardo Lima's user avatar
Gerardo Lima
6,67333 gold badges3333 silver badges4949 bronze badges
answered Jan 24, 2020 at 16:16
Dragomir Ivanov's user avatar
Dragomir Ivanov
1,27522 gold badges77 silver badges44 bronze badges

    1
    I had an issue with deleting both PV and PVC. This solution also works for deleting pvc. – 
    jsuen
    Commented Oct 3, 2021 at 3:12 

    confirm. works well. – 
    Vladimir Titkov
    Commented Jul 18, 2022 at 17:29
    This is what worked, the patch command didn't. Thanks! – 
    Akash Agarwal
    Commented Aug 27, 2022 at 0:58
    3
    Still hangs for me, even with the grace period and force options. – 
    Draemon
    Commented Feb 17, 2023 at 10:55
    14
    It's 2023 why do I have to do this – 
    Jan Martin
    Commented Feb 21, 2023 at 1:45

Show 1 more comment
71

kubectl patch pvc {PVC_NAME} -p '{"metadata":{"finalizers":null}}'

You need to patch the PVC to set the “finalizers” setting to null, this allows the final unmount from the node, and the PVC can be deleted.
Share
Improve this answer
Follow
answered Jul 17, 2021 at 23:10
yasin lachini's user avatar
yasin lachini
5,92888 gold badges3636 silver badges5858 bronze badges

    6
    The same can be done with pv – 
    Vishrant
    Commented Nov 5, 2021 at 22:55
    5
    on windows you need to escape the quotes, but you knew that right? kubectl patch pvc {PVC_NAME} -p '{\"metadata\":{\"finalizers\":null}}' – 
    BikerP
    Commented Oct 20, 2022 at 7:07 

1
how do i do this for all the pvc's instead of doing one by one.. I have lots of pvs stuck in terminating state – 
anandhu
Commented Dec 7, 2022 at 4:49
1
This is the same solution as the top answer, I think, just better because it also deletes any other finalizers that are blocking you and doesn't require a hand edit. – 
Noumenon
Commented Mar 17, 2023 at 15:30

    GPT-4 missed this step ! – 
    aayoubi
    Commented Apr 24 at 10:43

Add a comment
18

For quick eyes :

kubectl patch pvc <pvc_name> -p '{"metadata":{"finalizers":null}}'

kubectl delete pvc <pvc_name> --grace-period=0 --force 

kubectl patch pv <pv_name> -p '{"metadata":{"finalizers":null}}'

kubectl delete pv <pv_name> --grace-period=0 --force 

Share
Improve this answer
Follow
answered Sep 30, 2022 at 19:53
codeX's user avatar
codeX
5,31822 gold badges3333 silver badges3939 bronze badges
Add a comment
17

You can use following command to delete the PV or PVC forcefully.

#kubectl delete pvc <PVC_NAME> --grace-period=0 --force 

in your case

#kubectl delete pvc task-pv-claim  --grace-period=0 --force 

Share
Improve this answer
Follow
answered Apr 14, 2019 at 7:04
yasin lachini's user avatar
yasin lachini
5,92888 gold badges3636 silver badges5858 bronze badges

    I've marked it as the correct answer. Thank you! That worked flawlessly. I can now bang my head against sharing a local dir on all 2 nodes (ubu2 and ubu3). Any hints there? – 
    farhany
    Commented Apr 14, 2019 at 7:17
    do you want to share one direction in one host to 2 ubuntu? – 
    yasin lachini
    Commented Apr 14, 2019 at 7:20
    @yasin_lachini I'll take one or bi-directional at this point to just get this off the ground. :( Thanks for your help! – 
    farhany
    Commented Apr 14, 2019 at 23:32
    1
    My understanding of your setup is: 1 server running 3 VMs contatinig Ubuntu cluster nodes. To share local directory you need to mount local directory to your VMs (way to do this is dependent upon your VM engine), and then create PV with volume type hostPath and Access Mode ReadWriteMany so it can be claimed by many pods. – 
    MWZ
    Commented Apr 15, 2019 at 9:14

Add a comment
4

if your PV or PVC stuck then delete related pods and your terminating status PV or PVC will no longer exist.
Share
Improve this answer
Follow
answered Jun 22, 2023 at 8:30
AniketGole's user avatar
AniketGole
1,26522 gold badges1717 silver badges2626 bronze badges
Add a comment
3

If you execute a describe command

kubectl describe pvc <pvcname>
