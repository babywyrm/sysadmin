
# k3s etcd Commands (2026 Update)

## Setup etcdctl

Check your k3s embedded etcd version first:

```bash
curl -L --cacert /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt \
  --cert /var/lib/rancher/k3s/server/tls/etcd/server-client.crt \
  --key /var/lib/rancher/k3s/server/tls/etcd/server-client.key \
  https://127.0.0.1:2382/version
```

Install matching etcdctl (check latest at https://github.com/etcd-io/etcd/releases):

```bash
ETCD_VER=v3.5.16  # Update to match your etcd version

DOWNLOAD_URL=https://github.com/etcd-io/etcd/releases/download

curl -L ${DOWNLOAD_URL}/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz \
  -o /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
  
tar xzvf /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz \
  -C /usr/local/bin --strip-components=1
  
rm -f /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz

etcdctl version
```

## Environment Setup

Export credentials once (recommended):

```bash
export ETCDCTL_ENDPOINTS='https://127.0.0.1:2379'
export ETCDCTL_CACERT='/var/lib/rancher/k3s/server/tls/etcd/server-ca.crt'
export ETCDCTL_CERT='/var/lib/rancher/k3s/server/tls/etcd/server-client.crt'
export ETCDCTL_KEY='/var/lib/rancher/k3s/server/tls/etcd/server-client.key'
export ETCDCTL_API=3
```

## Common Operations

**Health & Status:**
```bash
etcdctl endpoint health --cluster --write-out=table
etcdctl endpoint status --cluster --write-out=table
etcdctl check perf
```

**Data Operations:**
```bash
# List all keys
etcdctl get / --prefix --keys-only

# Get specific key
etcdctl get /registry/secrets/default/my-secret

# Watch for changes
etcdctl watch / --prefix
```

**Maintenance:**
```bash
# Check alarms
etcdctl alarm list

# Compact and defrag
rev=$(etcdctl endpoint status --write-out=fields | grep Revision | cut -d: -f2)
etcdctl compact $rev
etcdctl defrag --cluster
```

**Member Management:**
```bash
etcdctl member list --write-out=table
etcdctl member update <id> --peer-urls=https://new-ip:2380
```

## Metrics & Monitoring

**Note:** Since k3s v1.25.15+, v1.26.10+, v1.27.7+, v1.28.3+, v1.29.0+, the HTTP metrics port is **2382** (not 2379).

```bash
# Metrics
curl -L --cacert /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt \
  --cert /var/lib/rancher/k3s/server/tls/etcd/server-client.crt \
  --key /var/lib/rancher/k3s/server/tls/etcd/server-client.key \
  https://127.0.0.1:2382/metrics

# Version
curl -L --cacert /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt \
  --cert /var/lib/rancher/k3s/server/tls/etcd/server-client.crt \
  --key /var/lib/rancher/k3s/server/tls/etcd/server-client.key \
  https://127.0.0.1:2382/version
```

## CTF/Security Notes

For xxxxxx or similar scenarios:
- Secrets stored in `/registry/secrets/`
- ConfigMaps in `/registry/configmaps/`
- ServiceAccounts in `/registry/serviceaccounts/`
- Direct etcd access = cluster admin equivalent


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
