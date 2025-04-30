#!/usr/bin/env bash
set -euo pipefail

# Function to display help
show_help() {
  cat <<EOF
UNHELM - Convert Helm charts to plain Kubernetes YAML or Kustomize
=====================================================================

USAGE:
  $0 [OPTIONS] <RELEASE_NAME> <CHART_PATH> <NAMESPACE>

OPTIONS:
  -p, --plain       Generate plain YAML without Kustomize structure
  -s, --single-file Keep all resources in a single YAML file
  -v, --values      Path to values file (can be used multiple times)
  -o, --output-dir  Output directory (default: current directory)
  -e, --envs        List of environments for overlays (default: dev,prod)
  -c, --crds        Extract CRDs into separate directory
  -h, --help        Show this help message

EXAMPLES:
  # Basic usage - convert chart to Kustomize with split files
  $0 my-app ./charts/my-app my-namespace
  
  # With custom values file
  $0 my-app ./charts/my-app my-namespace --values my-values.yaml
  
  # Extract CRDs and use custom environments
  $0 my-app ./charts/my-app my-namespace --crds --envs dev,staging,prod
  
  # Convert to plain YAML files
  $0 my-app ./charts/my-app my-namespace --plain

EOF
}

# Default options
USE_PLAIN=false
SINGLE_FILE=false
VALUES_FILES=()
OUTPUT_DIR="."
ENVIRONMENTS=("dev" "prod")
EXTRACT_CRDS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--plain) USE_PLAIN=true; shift ;;
    -s|--single-file) SINGLE_FILE=true; shift ;;
    -v|--values)
      if [[ -f "$2" ]]; then
        VALUES_FILES+=("$2")
        shift 2
      else
        echo "Error: Values file $2 not found."
        exit 1
      fi
      ;;
    -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    -e|--envs) IFS=',' read -ra ENVIRONMENTS <<< "$2"; shift 2 ;;
    -c|--crds) EXTRACT_CRDS=true; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) break ;;
  esac
done

if (( $# != 3 )); then
  echo "Error: Missing required arguments"
  echo "Usage: $0 [OPTIONS] <RELEASE_NAME> <CHART_PATH> <NAMESPACE>"
  echo "Run '$0 --help' for details"
  exit 1
fi

RELEASE_NAME=$1
CHART_PATH=$2
NAMESPACE=$3

# Setup directories
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

if $USE_PLAIN; then
  OUT_DIR=manifests
  rm -rf $OUT_DIR
  mkdir -p $OUT_DIR
else
  BASE_DIR=base
  rm -rf $BASE_DIR overlays
  mkdir -p $BASE_DIR
fi

# Create CRDs directory if needed
if $EXTRACT_CRDS; then
  CRDS_DIR=crds
  rm -rf $CRDS_DIR
  mkdir -p $CRDS_DIR
fi

# Build the Helm template command
HELM_CMD=("helm" "template" "$RELEASE_NAME" "$CHART_PATH" "--namespace" "$NAMESPACE")
for values_file in "${VALUES_FILES[@]}"; do
  HELM_CMD+=("--values" "$values_file")
done

# Render helm chart
echo "Rendering Helm chart '$CHART_PATH'..."
TMP_RENDER=$(mktemp)
"${HELM_CMD[@]}" > "$TMP_RENDER"

# Extract CRDs if requested
if $EXTRACT_CRDS; then
  echo "Extracting CRDs..."
  TMP_CRDS=$(mktemp)
  TMP_NON_CRDS=$(mktemp)
  
  # Split into CRDs and non-CRDs
  awk '/^---$/{if(file) close(file); file="'"$TMP_NON_CRDS"'"; next} /kind: CustomResourceDefinition/{file="'"$TMP_CRDS"'"; next} {if(file) print > file}' "$TMP_RENDER"
  
  # Process CRDs
  if [[ -s "$TMP_CRDS" ]]; then
    csplit -q --suppress-matched \
      --prefix="$CRDS_DIR/crd-" --suffix-format='%02d.yaml' \
      "$TMP_CRDS" '/^---$/' '{*}'
    
    # Rename CRD files
    for f in $CRDS_DIR/crd-*.yaml; do
      [[ ! -s "$f" ]] && rm "$f" && continue
      
      kind=$(yq e '.kind' "$f" 2>/dev/null || echo "null")
      name=$(yq e '.metadata.name' "$f" 2>/dev/null || echo "null")
      if [[ "$kind" == "CustomResourceDefinition" && "$name" != "null" ]]; then
        safe_name=$(echo "$name" | tr -d '"'\'' /()*:')
        mv "$f" "$CRDS_DIR/crd-$safe_name.yaml"
      fi
    done
    
    # Create kustomization.yaml for CRDs
    cat > crds/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
$(for f in crds/crd-*.yaml; do
    [[ $(basename $f) == "kustomization.yaml" ]] && continue
    echo "  - $(basename $f)"
  done)
EOF
    
    echo "CRDs extracted to $CRDS_DIR/"
  fi
  
  # Replace original manifest with non-CRDs only
  if [[ -s "$TMP_NON_CRDS" ]]; then
    mv "$TMP_NON_CRDS" "$TMP_RENDER"
  fi
  
  rm -f "$TMP_CRDS" "$TMP_NON_CRDS" 2>/dev/null || true
fi

# Handle single file mode
if $SINGLE_FILE; then
  if $USE_PLAIN; then
    # Plain YAML + Single File
    cp "$TMP_RENDER" "$OUT_DIR/all-resources.yaml"
    echo "✅ Generated single file in '$OUT_DIR/all-resources.yaml'"
  else
    # Kustomize + Single File
    cp "$TMP_RENDER" "$BASE_DIR/all-resources.yaml"
    
    # Create base/kustomization.yaml
    cat > $BASE_DIR/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: $NAMESPACE

resources:
  - all-resources.yaml
EOF
    
    # Create overlays
    for env in "${ENVIRONMENTS[@]}"; do
      mkdir -p overlays/$env
      cat > overlays/$env/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../base

# Uncomment as needed:
# patchesStrategicMerge:
#   - patches.yaml
# configMapGenerator:
#   - name: ${RELEASE_NAME}-config
#     literals:
#       - ENV=$env
EOF

      # Create a stub patch file
      cat > overlays/$env/patches.yaml <<EOF
# Example patches - uncomment and modify as needed:
# ---
# apiVersion: apps/v1
# kind: Deployment
# metadata:
#   name: example-deployment
# spec:
#   replicas: 1
#   template:
#     spec:
#       containers:
#       - name: example-container
#         image: registry/image:${env}-tag
#         resources:
#           limits:
#             cpu: 500m
#             memory: 512Mi
EOF
    done
    
    echo "✅ Generated Kustomize structure with single file"
  fi
  
  rm "$TMP_RENDER"
  exit 0
fi

# Split file mode - parse manifest into separate files
echo "Splitting resources into individual files..."
FRAG_PREFIX=$([[ $USE_PLAIN == true ]] && echo "$OUT_DIR/rsrc-" || echo "$BASE_DIR/rsrc-")
csplit -q --suppress-matched \
  --prefix="$FRAG_PREFIX" --suffix-format='%02d.yaml' \
  "$TMP_RENDER" '/^---$/' '{*}'
rm "$TMP_RENDER"

# Process and rename resource files
count=0
for f in $FRAG_PREFIX*.yaml; do
  # Skip empty files
  [[ ! -s "$f" ]] && rm "$f" && continue
  
  kind=$(yq e '.kind' "$f" 2>/dev/null || echo "null")
  name=$(yq e '.metadata.name' "$f" 2>/dev/null || echo "null")
  if [[ "$kind" != "null" && "$name" != "null" ]]; then
    target_dir=$([[ $USE_PLAIN == true ]] && echo "$OUT_DIR" || echo "$BASE_DIR")
    # Clean up name for filename friendliness
    safe_name=$(echo "$name" | tr -d '"'\'' /()*:')
    newfile="$target_dir/$(tr '[:upper:]' '[:lower:]' <<<"$kind")-$safe_name.yaml"
    mv "$f" "$newfile"
    count=$((count+1))
  else
    rm "$f"
  fi
done

echo "Created $count resource files"

# Plain YAML is done
if $USE_PLAIN; then
  echo "✅ Generated individual manifest files in '$OUT_DIR/'"
  exit 0
fi

# Kustomize scaffolding for base
cat > $BASE_DIR/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: $NAMESPACE

resources:
$(for f in $BASE_DIR/*.yaml; do
    [[ $(basename $f) == "kustomization.yaml" ]] && continue
    echo "  - $(basename $f)"
  done)
EOF

# Create environment overlays
for env in "${ENVIRONMENTS[@]}"; do
  mkdir -p overlays/$env
  cat > overlays/$env/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../base

# Uncomment and modify as needed:
# patchesStrategicMerge:
#   - patches.yaml
EOF

  # Create generic patch examples
  cat > overlays/$env/patches.yaml <<EOF
# Example patches for ${env} environment - uncomment and modify as needed

# ---
# apiVersion: apps/v1
# kind: Deployment
# metadata:
#   name: example-deployment
# spec:
#   replicas: ${env == "prod" ? 3 : 1}
#   template:
#     spec:
#       containers:
#       - name: example-container
#         image: registry/image:${env}-tag
#         resources:
#           limits:
#             cpu: ${env == "prod" ? "1000m" : "500m"}
#             memory: ${env == "prod" ? "2Gi" : "1Gi"}
EOF

  # Create ArgoCD Application sample template
  cat > overlays/$env/argocd-application-template.yaml <<EOF
# Template for ArgoCD Application - customize and apply separately
# ---
# apiVersion: argoproj.io/v1alpha1
# kind: Application
# metadata:
#   name: ${RELEASE_NAME}-${env}
#   namespace: argocd
# spec:
#   project: default
#   source:
#     repoURL: https://your-git-repo.git
#     targetRevision: HEAD
#     path: overlays/${env}
#   destination:
#     server: https://kubernetes.default.svc
#     namespace: ${NAMESPACE}
#   syncPolicy:
#     automated:
#       prune: true
#       selfHeal: true
EOF
done

echo "✅ Generated Kustomize structure with individual resource files:"
echo "   base/                    ← your K8s resources"
echo "   overlays/{${ENVIRONMENTS[*]}}/  ← environment overlays"
echo
echo "Next steps:"
echo "1) Review generated files"
echo "2) Edit environment overlays as needed"
echo "3) Commit to Git"
echo "4) Apply with ArgoCD"

