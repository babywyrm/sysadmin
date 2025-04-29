#!/usr/bin/env bash
set -euo pipefail

# Default options
USE_PLAIN=false
SINGLE_FILE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--plain)
      USE_PLAIN=true
      shift
      ;;
    -s|--single-file)
      SINGLE_FILE=true
      shift
      ;;
    *)
      break
      ;;
  esac
done

if (( $# != 3 )); then
  echo "Usage: $0 [--plain] [--single-file] <RELEASE_NAME> <CHART_PATH> <NAMESPACE>"
  echo
  echo "Options:"
  echo "  --plain, -p        Generate plain YAML (no Kustomize)"
  echo "  --single-file, -s  Keep all resources in one file"
  echo
  echo "Examples:"
  echo "  # Kustomize with split files (default)"
  echo "  $0 my-release ./chart default"
  echo
  echo "  # Kustomize with single file"
  echo "  $0 --single-file my-release ./chart default"
  echo
  echo "  # Plain YAML with split files"
  echo "  $0 --plain my-release ./chart default"
  echo
  echo "  # Plain YAML with single file"
  echo "  $0 --plain --single-file my-release ./chart default"
  exit 1
fi

RELEASE_NAME=$1
CHART_PATH=$2
NAMESPACE=$3

# Set up directories
if $USE_PLAIN; then
  OUT_DIR=manifests
  rm -rf $OUT_DIR
  mkdir -p $OUT_DIR
else
  BASE_DIR=base
  OVERLAYS=(dev prod)
  rm -rf $BASE_DIR overlays
  mkdir -p $BASE_DIR
fi

# Render helm chart
TMP_RENDER=$(mktemp)
helm template "$RELEASE_NAME" "$CHART_PATH" \
  --namespace "$NAMESPACE" > "$TMP_RENDER"

# Handle single file mode
if $SINGLE_FILE; then
  if $USE_PLAIN; then
    # Plain YAML + Single File
    cp "$TMP_RENDER" "$OUT_DIR/all-resources.yaml"
    echo "Generated single file in '$OUT_DIR/all-resources.yaml'."
    echo "Commit it and point your ArgoCD Application at the '$OUT_DIR' directory."
  else
    # Kustomize + Single File
    cp "$TMP_RENDER" "$BASE_DIR/all-resources.yaml"
    
    # Create base/kustomization.yaml referencing the single file
    cat > $BASE_DIR/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: $NAMESPACE

resources:
  - all-resources.yaml
EOF
    
    # Create overlays
    for env in "${OVERLAYS[@]}"; do
      mkdir -p overlays/$env
      cat > overlays/$env/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../base

# Uncomment these as needed:
# patchesStrategicMerge:
#   - patches.yaml
# configMapGenerator:
#   - name: ${RELEASE_NAME}-config
#     literals:
#       - ENV=$env
# secretGenerator:
#   - name: ${RELEASE_NAME}-creds
#     literals:
#       - USERNAME=${env}user
#       - PASSWORD=${env}pass
EOF

      # Create a stub patch file
      cat > overlays/$env/patches.yaml <<EOF
# Example patch for a deployment. Uncomment and modify as needed:
# apiVersion: apps/v1
# kind: Deployment
# metadata:
#   name: $RELEASE_NAME
# spec:
#   replicas: 1
#   template:
#     spec:
#       containers:
#       - name: $RELEASE_NAME
#         image: your-image:${env}-tag
EOF
    done
    
    echo "Generated Kustomize structure with a single manifest file:"
    echo "  base/all-resources.yaml   ← your merged K8s resources"
    echo "  base/kustomization.yaml   ← base kustomization"
    echo "  overlays/{dev,prod}/      ← environment overlays"
  fi
  
  rm "$TMP_RENDER"
  exit 0
fi

# Split file mode
FRAG_PREFIX=$([[ $USE_PLAIN == true ]] && echo "$OUT_DIR/rsrc-" || echo "$BASE_DIR/rsrc-")
csplit -q --suppress-matched \
  --prefix="$FRAG_PREFIX" --suffix-format='%02d.yaml' \
  "$TMP_RENDER" '/^---$/' '{*}'
rm "$TMP_RENDER"

# Rename fragments by kind and name
for f in $FRAG_PREFIX*.yaml; do
  kind=$(yq e '.kind' "$f" 2>/dev/null || echo "null")
  name=$(yq e '.metadata.name' "$f" 2>/dev/null || echo "null")
  if [[ "$kind" != "null" && "$name" != "null" ]]; then
    target_dir=$([[ $USE_PLAIN == true ]] && echo "$OUT_DIR" || echo "$BASE_DIR")
    # Clean up name for filename friendliness
    safe_name=$(echo "$name" | tr -d '"'\'' /()*:')
    newfile="$target_dir/$(tr '[:upper:]' '[:lower:]' <<<"$kind")-$safe_name.yaml"
    mv "$f" "$newfile"
  else
    rm "$f"
  fi
done

# Plain YAML is done
if $USE_PLAIN; then
  echo "Generated individual manifest files in '$OUT_DIR/'."
  echo "Commit them and point your ArgoCD Application at this directory."
  exit 0
fi

# Kustomize scaffolding
cat > $BASE_DIR/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: $NAMESPACE

resources:
$(for f in $BASE_DIR/*.yaml; do
    [[ $(basename $f) == "kustomization.yaml" ]] && continue
    echo "  - $(basename $f)"
  done)

# Optional generators:
# secretGenerator:
#   - name: ${RELEASE_NAME}-creds
#     literals:
#       - USERNAME=\$(USERNAME)
#       - PASSWORD=\$(PASSWORD)
# configMapGenerator:
#   - name: ${RELEASE_NAME}-config
#     files:
#       - config.properties=app.properties
# generatorOptions:
#   disableNameSuffixHash: true
EOF

# Create overlays for split-file kustomize mode
for env in "${OVERLAYS[@]}"; do
  mkdir -p overlays/$env
  cat > overlays/$env/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../base

# Uncomment and modify as needed:
# patchesStrategicMerge:
#   - patch-deployment.yaml
# configMapGenerator:
#   - name: ${RELEASE_NAME}-config
#     files:
#       - config.properties=${env}.properties
# secretGenerator:
#   - name: ${RELEASE_NAME}-creds
#     literals:
#       - USERNAME=${env}user
#       - PASSWORD=${env}pass
EOF

  # Find a deployment to patch as example
  deploy_file=$(find $BASE_DIR -name 'deployment-*.yaml' -o -name 'statefulset-*.yaml' | head -1)
  if [[ -n "$deploy_file" ]]; then
    deploy_kind=$(yq e '.kind' "$deploy_file")
    deploy_name=$(yq e '.metadata.name' "$deploy_file")
    container_name=$(yq e '.spec.template.spec.containers[0].name' "$deploy_file")
    
    cat > overlays/$env/patch-deployment.yaml <<EOF
apiVersion: apps/v1
kind: $deploy_kind
metadata:
  name: $deploy_name
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: $container_name
        # Uncomment and adjust:
        # image: registry/image:${env}-tag
        # resources:
        #   limits:
        #     cpu: 500m
        #     memory: 512Mi
        # env:
        # - name: LOG_LEVEL
        #   value: INFO
EOF
  fi
done

echo "Generated Kustomize structure with individual manifest files:"
echo "  base/              ← your split K8s resources"
echo "  base/kustomization.yaml ← base kustomization"  
echo "  overlays/{dev,prod}/    ← environment overlays"
echo
echo "Next steps:"
echo "1) Review and edit the generated files"
echo "2) Commit to Git"
echo "3) Point ArgoCD Application at the appropriate directory"
