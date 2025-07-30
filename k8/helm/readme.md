# WordPress Helm Chart Upgrade Guide .. Lol 

## 🎯 Overview
This guide documents the complete process of upgrading a Bitnami WordPress Helm chart in Kubernetes, including common pitfalls and solutions discovered during a real-world upgrade scenario.

## 📋 Scenario
- **Source**: WordPress 6.6.2 (Chart 23.1.16) - deployed 9 days ago
- **Target**: WordPress 6.8.1+ (Chart 24.2.11+ or 25.0.5)
- **Platform**: k3s Kubernetes cluster
- **Issues Encountered**: StatefulSet immutability, image overrides, failed upgrade attempts

## 🚫 Critical Understanding: Why WordPress Admin Upgrades Don't Work

### The Container Reality
```bash
# WordPress core files location
/opt/bitnami/wordpress/    # ❌ EPHEMERAL (EmptyDir volume)
├── wp-admin/              # Lost on pod restart
├── wp-includes/           # Lost on pod restart  
└── wp-config.php          # Lost on pod restart

# WordPress persistent data location  
/bitnami/wordpress/        # ✅ PERSISTENT (PVC)
├── wp-config.php          # Custom config persists
└── wp-content/            # Themes, plugins, uploads persist
    ├── themes/
    ├── plugins/
    └── uploads/
```

### Mount Points Explained
```yaml
# From pod description
Mounts:
  /bitnami/wordpress from wordpress-data (rw,path="wordpress")     # PERSISTENT
  /opt/bitnami/wordpress from empty-dir (rw,path="app-base-dir")   # EPHEMERAL
```

**Result**: WordPress admin upgrades update core files in `/opt/bitnami/wordpress/` (ephemeral), which are lost on pod restart.

## 🛡️ Pre-Upgrade Backup Strategy

### 1. Database Backup
```bash
# Find correct database name
kubectl exec -it [MARIADB_POD] -- mysql -u root -p[DB_ROOT_PASSWORD] -e "SHOW DATABASES;"

# Common database names in Bitnami WordPress:
# - bitnami_wordpress (most common)
# - wordpress (alternative)

# Backup (replace with your actual DB name)
kubectl exec -it [MARIADB_POD] -- mysqldump -u root -p[DB_ROOT_PASSWORD] --single-transaction --routines --triggers [DATABASE_NAME] > wp-backup-$(date +%Y%m%d).sql

# Verify backup size (should be > 1KB for real data)
ls -la wp-backup-*.sql
```

### 2. WordPress Content Backup
```bash
# Get current WordPress pod name
kubectl get pods -l app.kubernetes.io/name=wordpress

# Backup themes, plugins, uploads
kubectl exec -it [WORDPRESS_POD] -- tar -czf /tmp/wp-content.tar.gz /bitnami/wordpress/wp-content
kubectl cp [WORDPRESS_POD]:/tmp/wp-content.tar.gz ./wp-content-backup-$(date +%Y%m%d).tar.gz

# Verify backup
ls -la wp-content-backup-*.tar.gz
```

### 3. Helm Values Backup
```bash
# Save current configuration
helm get values [RELEASE_NAME] > my-current-values.yaml
helm get values [RELEASE_NAME] --all > my-all-values.yaml
```

## 🚨 Common Upgrade Issues & Solutions

### Issue 1: StatefulSet Immutability Error
```
Error: cannot patch "[RELEASE_NAME]-mariadb" with kind StatefulSet: 
StatefulSet.apps "[RELEASE_NAME]-mariadb" is invalid: spec: Forbidden: 
updates to statefulset spec for fields other than 'replicas', 'ordinals', 
'template', 'updateStrategy', 'persistentVolumeClaimRetentionPolicy' 
and 'minReadySeconds' are forbidden
```

**Solution**: Delete StatefulSet with orphaned pods
```bash
# Delete StatefulSet but keep pods running
kubectl delete statefulset [RELEASE_NAME]-mariadb --cascade=orphan

# Verify MariaDB pod still running
kubectl get pods | grep mariadb

# Retry upgrade
helm upgrade [RELEASE_NAME] bitnami/wordpress --version 24.2.11 --reuse-values --timeout=15m
```

### Issue 2: Image Override Preventing Upgrades
**Problem**: Hardcoded `image.tag` in values prevents image updates

```bash
# Check for image overrides
helm get values [RELEASE_NAME] --all | grep -A5 -B5 image

# Example problematic override:
# image:
#   tag: 6.6.2-debian-12-r4  # ← This locks the version!
```

**Solution**: Explicitly override the image tag
```bash
helm upgrade [RELEASE_NAME] bitnami/wordpress --version 24.2.11 \
  --set image.tag=6.8.1-debian-12-r6 \
  -f my-current-values.yaml --timeout=15m
```

### Issue 3: Helm Connection Issues in k3s
```
Error: Kubernetes cluster unreachable: Get "http://localhost:8080/version": 
dial tcp 127.0.0.1:8080: connect: connection refused
```

**Solution**: Export k3s kubeconfig
```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
# Or permanently:
mkdir -p ~/.kube
cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
```

## 📝 Step-by-Step Upgrade Process

### 1. Environment Setup
```bash
# Set k3s kubeconfig
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# Update Helm repos
helm repo update

# Check current status
kubectl get pods -A
helm list
helm history [RELEASE_NAME]
```

### 2. Pre-Upgrade Checks
```bash
# Check current versions
helm list
kubectl describe pod [WORDPRESS_POD] | grep Image:
kubectl exec -it [WORDPRESS_POD] -- wp core version

# Check available upgrades
helm search repo bitnami/wordpress --versions | head -10

# Check PVCs (your data safety net)
kubectl get pvc -A
```

### 3. Get Required Passwords
```bash
# Get MySQL root password from secret
kubectl get secret [RELEASE_NAME]-mariadb -o jsonpath="{.data.mariadb-root-password}" | base64 -d

# Get WordPress admin password
kubectl get secret [RELEASE_NAME]-wordpress -o jsonpath="{.data.wordpress-password}" | base64 -d
```

### 4. Backup Everything
```bash
# Database backup (use actual password from step 3)
kubectl exec -it [MARIADB_POD] -- mysqldump -u root -p[DB_ROOT_PASSWORD] --single-transaction [DATABASE_NAME] > backup-$(date +%Y%m%d).sql

# Content backup
kubectl exec -it [WORDPRESS_POD] -- tar -czf /tmp/wp-content.tar.gz /bitnami/wordpress/wp-content
kubectl cp [WORDPRESS_POD]:/tmp/wp-content.tar.gz ./wp-content-backup-$(date +%Y%m%d).tar.gz

# Helm values backup
helm get values [RELEASE_NAME] > my-values.yaml
```

### 5. Attempt Incremental Upgrade
```bash
# Try smaller version jump first
helm upgrade [RELEASE_NAME] bitnami/wordpress --version 24.2.11 --reuse-values --timeout=15m
```

### 6. Handle StatefulSet Issues (if needed)
```bash
# If you get StatefulSet errors:
kubectl delete statefulset [RELEASE_NAME]-mariadb --cascade=orphan
helm upgrade [RELEASE_NAME] bitnami/wordpress --version 24.2.11 --reuse-values --timeout=15m
```

### 7. Handle Image Override Issues (if needed)
```bash
# If WordPress version doesn't change after upgrade:
helm upgrade [RELEASE_NAME] bitnami/wordpress --version 24.2.11 \
  --set image.tag=6.8.1-debian-12-r6 \
  -f my-values.yaml --timeout=15m

# Force pod recreation
kubectl rollout restart deployment [RELEASE_NAME]-wordpress
```

### 8. Verification
```bash
# Check upgrade success
helm status [RELEASE_NAME]
kubectl get pods
kubectl exec -it [NEW_WORDPRESS_POD] -- wp core version

# Test website access
export SERVICE_IP=$(kubectl get svc [RELEASE_NAME]-wordpress --template "{{ range (index .status.loadBalancer.ingress 0) }}{{ . }}{{ end }}")
echo "WordPress URL: http://$SERVICE_IP/"
```

## 🔧 Troubleshooting Commands

### Pod and Deployment Inspection
```bash
# Get current pods
kubectl get pods -l app.kubernetes.io/name=wordpress

# Check pod details
kubectl describe pod [POD_NAME]

# Check deployment image
kubectl get deployment [RELEASE_NAME]-wordpress -o jsonpath='{.spec.template.spec.containers[?(@.name=="wordpress")].image}'

# Check mount points
kubectl describe pod [POD_NAME] | grep -A20 "Mounts:"
```

### Helm Debugging
```bash
# Check release history
helm history [RELEASE_NAME]

# Check current values
helm get values [RELEASE_NAME]
helm get values [RELEASE_NAME] --all

# Check what chart should provide
helm show values bitnami/wordpress --version 24.2.11 | grep -A10 image:

# Debug upgrade
helm upgrade [RELEASE_NAME] bitnami/wordpress --version 24.2.11 --debug --dry-run
```

### Database Debugging
```bash
# List databases
kubectl exec -it [MARIADB_POD] -- mysql -u root -p[DB_ROOT_PASSWORD] -e "SHOW DATABASES;"

# Check WordPress tables
kubectl exec -it [MARIADB_POD] -- mysql -u root -p[DB_ROOT_PASSWORD] -e "USE [DATABASE_NAME]; SHOW TABLES;"

# Count content
kubectl exec -it [MARIADB_POD] -- mysql -u root -p[DB_ROOT_PASSWORD] -e "USE [DATABASE_NAME]; SELECT COUNT(*) FROM wp_posts; SELECT COUNT(*) FROM wp_users;"
```

## 🚧 Nuclear Option: Complete Reinstall

If all else fails and you have good backups:

```bash
# 1. Save values
helm get values [RELEASE_NAME] > my-values.yaml

# 2. Uninstall (keeps PVCs by default)
helm uninstall [RELEASE_NAME]

# 3. Verify PVCs remain
kubectl get pvc

# 4. Reinstall with latest version
helm install [RELEASE_NAME] bitnami/wordpress --version 25.0.5 -f my-values.yaml --timeout=15m
```

## 🔄 Restore Procedures (If Needed)

### Database Restore
```bash
# If you need to restore database backup
kubectl exec -it [MARIADB_POD] -- mysql -u root -p[DB_ROOT_PASSWORD] [DATABASE_NAME] < wp-backup-[DATE].sql
```

### WordPress Content Restore
```bash
# If you need to restore wp-content
kubectl cp ./wp-content-backup-[DATE].tar.gz [WORDPRESS_POD]:/tmp/
kubectl exec -it [WORDPRESS_POD] -- tar -xzf /tmp/wp-content-backup-[DATE].tar.gz -C /
```

## ✅ Best Practices

### 1. Always Backup Before Upgrades
- Database dump with proper credentials
- WordPress content (`wp-content/` directory)
- Helm values configuration

### 2. Use Incremental Upgrades
- Don't jump too many chart versions at once
- Test 23.x → 24.x → 25.x rather than 23.x → 25.x directly

### 3. Understand Your Storage
- Know what's persistent vs ephemeral
- Check mount points with `kubectl describe pod`
- Verify PVC configurations

### 4. Handle Image Overrides Carefully
- Avoid hardcoding `image.tag` in values
- Use `--set image.tag=` during upgrades when needed
- Check `helm get values --all` for hidden overrides

### 5. Monitor Upgrade Process
- Use `kubectl get pods -w` to watch rollouts
- Check `helm status` after upgrades
- Verify actual running versions, not just chart versions

## 🔍 Useful Commands Reference

```bash
# Quick status check
kubectl get pods,pvc,svc -l app.kubernetes.io/instance=[RELEASE_NAME]

# Get WordPress admin password
kubectl get secret [RELEASE_NAME]-wordpress -o jsonpath="{.data.wordpress-password}" | base64 -d

# Get MySQL root password  
kubectl get secret [RELEASE_NAME]-mariadb -o jsonpath="{.data.mariadb-root-password}" | base64 -d

# Access WordPress pod shell
kubectl exec -it [WORDPRESS_POD] -- /bin/bash

# Check WordPress CLI commands
kubectl exec -it [WORDPRESS_POD] -- wp --info

# Follow pod logs
kubectl logs -f [POD_NAME]

# Get pod names dynamically
WORDPRESS_POD=$(kubectl get pods -l app.kubernetes.io/name=wordpress -o jsonpath='{.items[0].metadata.name}')
MARIADB_POD=$(kubectl get pods -l app.kubernetes.io/name=mariadb -o jsonpath='{.items[0].metadata.name}')
```

## 📊 Example Successful Upgrade Output

```bash
# Before upgrade
$ kubectl exec -it [WORDPRESS_POD] -- wp core version
6.6.2

# After upgrade
$ helm status [RELEASE_NAME]
NAME: [RELEASE_NAME]
LAST DEPLOYED: [DATE]
NAMESPACE: default
STATUS: deployed
REVISION: 12
CHART VERSION: 24.2.11
APP VERSION: 6.8.1

$ kubectl exec -it [NEW_WORDPRESS_POD] -- wp core version
6.8.1

# Verify image
$ kubectl get deployment [RELEASE_NAME]-wordpress -o jsonpath='{.spec.template.spec.containers[?(@.name=="wordpress")].image}'
docker.io/bitnami/wordpress:6.8.1-debian-12-r6
```

## 🎯 Key Takeaways

1. **Container WordPress ≠ Traditional WordPress**: Core files are ephemeral
2. **StatefulSets are immutable**: Use `--cascade=orphan` for problematic upgrades  
3. **Image overrides persist**: Check values for hardcoded tags
4. **Backups are essential**: Database + wp-content + helm values
5. **Incremental upgrades are safer**: Smaller version jumps reduce complexity
6. **Always verify**: Check actual running versions, not just chart versions
7. **Secrets contain passwords**: Use kubectl to extract from secrets
8. **Database names vary**: Check actual database name before backup

## 📚 Additional Resources

- [Bitnami WordPress Chart Documentation](https://github.com/bitnami/charts/tree/main/bitnami/wordpress)
- [Kubernetes StatefulSet Concepts](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)
- [Helm Upgrade Documentation](https://helm.sh/docs/helm/helm_upgrade/)
- [k3s Configuration](https://docs.k3s.io/cluster-access)
- [WordPress CLI Documentation](https://wp-cli.org/)

---

**Remember**: When in doubt, backup first, test incrementally, and verify everything works before declaring success! 🚀

**Security Note**: Always protect your database passwords and secrets. Never commit actual passwords to version control.
