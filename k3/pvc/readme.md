# Kubernetes PV/PVC Security: Threat Modeling Guide, (DRAFT, RC1)

## 1. Storage Architecture Overview

**Persistent Volumes (PVs)** and **Persistent Volume Claims (PVCs)** form Kubernetes' storage abstraction layer:

- **PVs**: Cluster-wide storage resources provisioned by administrators
- **PVCs**: Namespace-scoped requests for storage by applications
- **StorageClasses**: Define provisioners and storage parameters
- **Volume Plugins**: Implement different storage backends (local, NFS, cloud providers)

## 2. Threat Model for Kubernetes Storage

### 2.1. Key Security Properties

| Property | Description | Relevance to PV/PVC |
|----------|-------------|---------------------|
| **Confidentiality** | Prevention of unauthorized data access | Contents of volumes should be protected from unauthorized pods |
| **Integrity** | Prevention of unauthorized data modification | Storage should resist tampering attempts |
| **Availability** | Ensuring data is accessible when needed | Protection against DoS through resource exhaustion |

### 2.2. Attack Surfaces

- **Control Plane**: API server handling PV/PVC creation operations
- **Node Level**: Kubelet and container runtime handling volume mounting
- **Storage Backend**: The actual storage system (NFS, cloud storage, local disks)
- **Network Layer**: Communication between nodes and storage systems

## 3. Common Vulnerabilities and Attack Vectors

### 3.1. Privilege Escalation

- **Host Path Volumes**: May allow container breakout by mounting sensitive host directories
- **NodeAffinity Manipulation**: Could force pods onto specific compromised nodes
- **Cross-Pod Access**: Improper RWX (ReadWriteMany) volumes enabling unauthorized access

### 3.2. Data Exfiltration/Injection

- **Volume Snapshots**: May extract sensitive data through unauthorized snapshots
- **Unencrypted Volumes**: Data at rest may be readable on underlying infrastructure
- **Volume Remnants**: Improper cleanup leaving data accessible to subsequent users

### 3.3. Denial of Service

- **Storage Quota Abuse**: Excessive PVC creation consuming all available storage
- **Volume Spam**: Creating many small PVCs to exhaust metadata/inodes
- **Volume Churn**: Rapid create/delete operations overwhelming storage controller

### 3.4. k3s-Specific Concerns

- **Local-Path Provisioner**: Default k3s storage has node-specific security implications
- **Single Node Clusters**: Data locality creating unique attack opportunities
- **Embedded etcd**: Storage metadata often on same node as data in k3s

## 4. Security Mitigation Strategies

### 4.1. Access Control

```yaml
# Example: StorageClass with restricted access
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: restricted-storage
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
allowedTopologies:
- matchLabelExpressions:
  - key: security-zone
    values:
    - trusted
```

- Use **RBAC** to limit who can create PVs and PVCs
- Implement **PodSecurityPolicies** or **Pod Security Standards** to restrict volume types
- Consider **NetworkPolicies** to restrict storage-related traffic

### 4.2. Data Protection

- Enable **encryption at rest** for PVs (use StorageClass parameters)
- Implement proper **volume recycling policies** (`Delete` vs `Retain`)
- Use **PVC finalizers** to ensure proper cleanup
- Consider **StorageClass quotas** to prevent resource exhaustion

### 4.3. Isolation

```yaml
# Example: PV with specific nodeAffinity for isolation
apiVersion: v1
kind: PersistentVolume
metadata:
  name: secured-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  nodeAffinity:
    required:
      nodeSelectorTerms:
      - matchExpressions:
        - key: security-zone
          operator: In
          values:
          - high
```

- Implement **volume namespacing** with proper naming conventions
- Use restrictive **nodeAffinity** for sensitive storage
- Implement **multi-tenancy** with namespace-level segregation
- Consider dedicated nodes for sensitive storage workloads

## 5. k3s Hardening Recommendations

### 5.1. Local-Path Storage Hardening

- Mount dedicated filesystems with `noexec` and encryption
- Use node labels to restrict which nodes can provide storage
- Apply proper Linux permissions on local storage paths
- Consider replacing default local-path with more robust options

### 5.2. Small Cluster Considerations

- Implement **strict resource quotas** to prevent DoS
- Use **anti-affinity** to separate storage from compute when possible
- Enable **audit logging** for all PV/PVC operations
- Consider external storage solutions when security is critical

## 6. Incident Response Checklist

1. **Identify**: Check for unauthorized volume access or abnormal patterns
   ```bash
   kubectl get pv,pvc --all-namespaces
   kubectl describe pv <suspicious-pv>
   ```

2. **Contain**: Isolate affected volumes and workloads
   ```bash
   kubectl cordon <node>  # If using local storage
   kubectl patch pv <pv-name> -p '{"spec":{"claimRef": null}}'
   ```

3. **Investigate**: Examine volume contents and audit logs
   ```bash
   kubectl exec -it <debug-pod> -- ls -la /mnt/volume
   ```

4. **Recover**: Restore from clean backups, recreate affected storage

## 7. Recommended Security Testing

- Regular **permission auditing** of PVs and PVCs
- **Storage penetration testing** against your volume configurations
- **Resource exhaustion testing** to validate quota effectiveness
- **Node isolation verification** to ensure proper segmentation

