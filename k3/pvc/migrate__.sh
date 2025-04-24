#!/bin/bash
# k8s-node-migrator.sh - Kubernetes Node Migration Helper  (sane edition)

set -e

# Default values
DRY_RUN=false
OLD_NODE=""
NEW_NODE=""
NAMESPACE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --old-node)
      OLD_NODE="$2"
      shift 2
      ;;
    --new-node)
      NEW_NODE="$2"
      shift 2
      ;;
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Try to auto-detect node changes
if [[ -z "$OLD_NODE" || -z "$NEW_NODE" ]]; then
  CURRENT_HOSTNAME=$(hostname)
  echo "Current hostname: $CURRENT_HOSTNAME"
  
  # Get ready nodes
  READY_NODES=$(kubectl get nodes -o jsonpath='{.items[?(@.status.conditions[?(@.type=="Ready")].status=="True")].metadata.name}')
  NOT_READY_NODES=$(kubectl get nodes -o jsonpath='{.items[?(@.status.conditions[?(@.type=="Ready")].status!="True")].metadata.name}')
  
  echo "Ready nodes: $READY_NODES"
  echo "NotReady nodes: $NOT_READY_NODES"
  
  if [[ -z "$OLD_NODE" && ! -z "$NOT_READY_NODES" ]]; then
    OLD_NODE="$NOT_READY_NODES"
    echo "Auto-detected old node name: $OLD_NODE"
  fi
  
  if [[ -z "$NEW_NODE" && ! -z "$READY_NODES" ]]; then
    NEW_NODE="$READY_NODES"
    echo "Auto-detected new node name: $NEW_NODE"
  fi
fi

if [[ -z "$OLD_NODE" || -z "$NEW_NODE" ]]; then
  echo "Error: Both old-node and new-node must be specified if auto-detection fails"
  exit 1
fi

echo "Migrating from node $OLD_NODE to $NEW_NODE"
if [[ ! -z "$NAMESPACE" ]]; then
  echo "Targeting namespace: $NAMESPACE"
fi

# Find PVs with nodeAffinity to old node
echo "Finding PVs with nodeAffinity to $OLD_NODE..."
PVS=$(kubectl get pv -o json | jq -r ".items[] | select(.spec.nodeAffinity.required.nodeSelectorTerms[].matchExpressions[].values[] | contains(\"$OLD_NODE\")) | .metadata.name")

if [[ -z "$PVS" ]]; then
  echo "No PVs found with nodeAffinity to $OLD_NODE"
  exit 0
fi

echo "Found PVs with nodeAffinity to $OLD_NODE:"
echo "$PVS"

for PV in $PVS; do
  echo "Processing PV: $PV"
  
  # Get PV details
  PV_YAML=$(kubectl get pv "$PV" -o yaml)
  PV_SIZE=$(echo "$PV_YAML" | grep -A 2 capacity | grep storage | sed 's/.*: //')
  PV_PATH=$(echo "$PV_YAML" | grep -A 2 local: | grep path | sed 's/.*: //')
  PV_STORAGE_CLASS=$(echo "$PV_YAML" | grep storageClassName | head -1 | sed 's/.*: //')
  
  # Check if bound to PVC
  CLAIM_NAME=$(echo "$PV_YAML" | grep -A 3 claimRef | grep name | head -1 | sed 's/.*: //')
  CLAIM_NS=$(echo "$PV_YAML" | grep -A 3 claimRef | grep namespace | head -1 | sed 's/.*: //')
  
  if [[ ! -z "$NAMESPACE" && "$CLAIM_NS" != "$NAMESPACE" ]]; then
    echo "Skipping PV $PV as it's bound to PVC in namespace $CLAIM_NS, not $NAMESPACE"
    continue
  fi
  
  # Create new PV name
  NEW_PV="${PV}-${NEW_NODE}"
  
  echo "Creating new PV $NEW_PV with nodeAffinity to $NEW_NODE"
  echo "  Storage: $PV_SIZE"
  echo "  Path: $PV_PATH"
  echo "  StorageClass: $PV_STORAGE_CLASS"
  
  if [[ ! -z "$CLAIM_NAME" ]]; then
    echo "  Bound to: $CLAIM_NS/$CLAIM_NAME"
  fi
  
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[DRY RUN] Would create new PV $NEW_PV"
    continue
  fi
  
  # Create new PV manifest
  cat <<EOF > /tmp/new-pv.yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: $NEW_PV
spec:
  capacity:
    storage: $PV_SIZE
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  storageClassName: $PV_STORAGE_CLASS
  persistentVolumeReclaimPolicy: Delete
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - $NEW_NODE
  local:
    path: $PV_PATH
EOF
  
  # Create the new PV
  kubectl create -f /tmp/new-pv.yaml
  rm /tmp/new-pv.yaml
  
  if [[ ! -z "$CLAIM_NAME" ]]; then
    echo "Unbinding old PV $PV from PVC $CLAIM_NS/$CLAIM_NAME"
    kubectl patch pv "$PV" --type=json -p='[{"op":"remove","path":"/spec/claimRef"}]'
    
    echo "Binding new PV $NEW_PV to PVC $CLAIM_NS/$CLAIM_NAME"
    kubectl patch pv "$NEW_PV" --type=merge -p="{\"spec\":{\"claimRef\":{\"namespace\":\"$CLAIM_NS\",\"name\":\"$CLAIM_NAME\"}}}"
  fi
  
  echo "Successfully migrated PV $PV to $NEW_PV"
  
  if [[ "$DRY_RUN" != "true" ]]; then
    read -p "Delete old PV $PV? (y/N): " DELETE_PV
    if [[ "$DELETE_PV" == "y" ]]; then
      kubectl delete pv "$PV"
      echo "Deleted old PV $PV"
    fi
  fi
done

echo "Migration complete!"
