# k3s etcd commands

##
#
https://gist.github.com/superseb/0c06164eef5a097c66e810fe91a9d408
#
##

## etcd

Setup etcdctl using the instructions at https://github.com/etcd-io/etcd/releases/tag/v3.4.13 (changed path to `/usr/local/bin`):

**Note:** if you want to match th etcdctl binaries with the embedded k3s etcd version, please run the curl command for getting the version first and adjust `ETCD_VER` below accordingly:

```
curl -L --cacert /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt --cert /var/lib/rancher/k3s/server/tls/etcd/server-client.crt --key /var/lib/rancher/k3s/server/tls/etcd/server-client.key https://127.0.0.1:2379/version
```

```
ETCD_VER=v3.4.13

# choose either URL
GOOGLE_URL=https://storage.googleapis.com/etcd
GITHUB_URL=https://github.com/etcd-io/etcd/releases/download
DOWNLOAD_URL=${GOOGLE_URL}

rm -f /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
rm -rf /tmp/etcd-download-test && mkdir -p /tmp/etcd-download-test

curl -L ${DOWNLOAD_URL}/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz -o /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
tar xzvf /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz -C /usr/local/bin --strip-components=1
rm -f /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz

etcd --version
etcdctl version
```

* `etcdctl check perf`

```
ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl check perf
```

* `etcdctl endpoint status`

```
ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl endpoint status --cluster --write-out=table
```

* `etcdctl endpoint health`

```
ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl endpoint health --cluster --write-out=table
```

* `etcdctl alarm list`

```
ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl alarm list
```

* `etcdctl compact`

```
rev=$(ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl endpoint status --write-out fields | grep Revision | cut -d: -f2)
ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl compact $rev
```

* `etcdctl defrag`

```
ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl defrag --cluster
```

* `etcdctl get`

```
ETCDCTL_ENDPOINTS='https://127.0.0.1:2379' ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt' ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt' ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key' ETCDCTL_API=3 etcdctl get / --prefix --keys-only
```

* curl metrics

**NOTE** Since the following k3s versions, the HTTP port moved to 2382 (the example below uses port 2379):
* v1.25.15+k3s1
* v1.26.10+k3s1
* v1.27.7+k3s1
* v1.28.3+k3s1
* v1.29.0+k3s1

```
curl -L --cacert /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt --cert /var/lib/rancher/k3s/server/tls/etcd/server-client.crt --key /var/lib/rancher/k3s/server/tls/etcd/server-client.key https://127.0.0.1:2379/metrics
```

* curl version

**NOTE** Since the following k3s versions, the HTTP port moved to 2382 (the example below uses port 2379):
* v1.25.15+k3s1
* v1.26.10+k3s1
* v1.27.7+k3s1
* v1.28.3+k3s1
* v1.29.0+k3s1

```
curl -L --cacert /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt --cert /var/lib/rancher/k3s/server/tls/etcd/server-client.crt --key /var/lib/rancher/k3s/server/tls/etcd/server-client.key https://127.0.0.1:2379/version
```

* export all environment variables (thanks to @clementnuss)

```
export ETCDCTL_ENDPOINTS='https://127.0.0.1:2379'
export ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt'
export ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt'
export ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key'
export ETCDCTL_API=3
```
