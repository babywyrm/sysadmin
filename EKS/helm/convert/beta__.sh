#!/usr/bin/env bash

# UNHELM - Convert Helm charts to Kubernetes YAML/Kustomize (Beta)
# Author: DevOps Team, Lol
# Usage: ./unhelm.sh [OPTIONS] <RELEASE_NAME> <CHART_PATH> <NAMESPACE>

set -euo pipefail

# ----- Configuration -----
# Default options
USE_PLAIN=false
SINGLE_FILE=false
VALUES_FILES=()
OUTPUT_DIR="."
ENVIRONMENTS=("dev" "prod")
EXTRACT_CRDS=false

# ----- Helper Functions -----

# Display usage information
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

  # Working with specific charts:
  #   - For Prometheus Operator:
  #     $0 kube-prom kube-prometheus-stack/ monitoring --crds
  
  #   - For Istio:
  #     $0 istio istio-*/manifests/charts/base istio-system --crds --single-file
  
  #   - For Cert-Manager:
  #     $0 cert-manager cert-manager cert-manager --crds --envs prod
EOF
}

# Parse command line arguments
parse_args() {
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
}

# Create the basic directory structure
setup_directories() {
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
}

# Render the helm chart to YAML
render_helm_chart() {
  echo "Rendering Helm chart '$CHART_PATH'..."
  
  # Build the Helm template command
  local cmd=("helm" "template" "$RELEASE_NAME" "$CHART_PATH" "--namespace" "$NAMESPACE")
  for values_file in "${VALUES_FILES[@]}"; do
    cmd+=("--values" "$values_file")
  done

  # Execute the helm command
  TMP_RENDER=$(mktemp)
  "${cmd[@]}" > "$TMP_RENDER"
  
  # Return the path to the rendered template
  echo "$TMP_RENDER"
}

# Extract CRDs from the rendered YAML
extract_crds() {
  local rendered_file=$1
  echo "Extracting CRDs..."
  
  TMP_CRDS=$(mktemp)
  TMP_NON_CRDS=$(mktemp)
  
  # Split into CRDs and non-CRDs
  awk '/^---$/{if(file) close(file); file="'"$TMP_NON_CRDS"'"; next} /kind: CustomResourceDefinition/{file="'"$TMP_CRDS"'"; next} {if(file) print > file}' "$rendered_file"
  
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
    mv "$TMP_NON_CRDS" "$rendered_file"
  fi
  
  rm -f "$TMP_CRDS" 2>/dev/null || true
}

# Process for single file output mode
handle_single_file() {
  local rendered_file=$1
  
  if $USE_PLAIN; then
    # Plain YAML + Single File
    cp "$rendered_file" "$OUT_DIR/all-resources.yaml"
    echo "Generated single file in '$OUT_DIR/all-resources.yaml'"
  else
    # Kustomize + Single File
    cp "$rendered_file" "$BASE_DIR/all-resources.yaml"
    
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
      create_patch_example "overlays/$env/patches.yaml" "$env"
    done
    
    echo "Generated Kustomize structure with single file"
  fi
}

# Split rendered YAML into individual resource files
split_resources() {
  local rendered_file=$1
  echo "Splitting resources into individual files..."
  
  FRAG_PREFIX=$([[ $USE_PLAIN == true ]] && echo "$OUT_DIR/rsrc-" || echo "$BASE_DIR/rsrc-")
  csplit -q --suppress-matched \
    --prefix="$FRAG_PREFIX" --suffix-format='%02d.yaml' \
    "$rendered_file" '/^---$/' '{*}'
  
  # Process and rename resource files
  local count=0
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
  return $count
}

# Create a kustomization file for base directory
create_base_kustomization() {
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
}

# Create overlay directories with appropriate files
create_overlays() {
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
    create_patch_example "overlays/$env/patches.yaml" "$env"
    
    # Create ArgoCD Application template
    create_argocd_template "overlays/$env/argocd-application-template.yaml" "$env"
  done
}

# Create example patch file with common patterns
create_patch_example() {
  local filename=$1
  local env=$2
  
  cat > "$filename" <<EOF
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
#
# ---
# apiVersion: v1
# kind: ConfigMap
# metadata:
#   name: example-configmap
# data:
#   config.json: |
#     {
#       "environment": "${env}",
#       "logLevel": "${env == "prod" ? "warn" : "debug"}"
#     }
EOF
}

# Create ArgoCD application template
create_argocd_template() {
  local filename=$1
  local env=$2
  
  cat > "$filename" <<EOF
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
}

# Print a summary of what was generated
print_summary() {
  echo "Generated resources:"
  
  if $USE_PLAIN; then
    echo "- manifests/            <- Kubernetes YAML manifests"
  else
    echo "- base/                 <- Base Kubernetes resources"
    echo "- overlays/             <- Environment-specific overlays"
    for env in "${ENVIRONMENTS[@]}"; do
      echo "  - $env/               <- $env environment configuration"
    done
  fi
  
  if $EXTRACT_CRDS; then
    echo "- crds/                 <- Custom Resource Definitions"
  fi
  
  echo ""
  echo "Next steps:"
  echo "1) Review generated files"
  echo "2) Edit environment overlays as needed"
  echo "3) Commit to Git"
  echo "4) Apply with ArgoCD or kubectl"
  
  # Provide helpful commands based on the generation mode
  echo ""
  echo "Helpful commands:"
  
  if $USE_PLAIN; then
    echo "# To apply these resources directly:"
    echo "kubectl apply -f manifests/ -n $NAMESPACE"
  else
    echo "# To preview the resources with kustomize:"
    if [[ "${#ENVIRONMENTS[@]}" -gt 0 ]]; then
      echo "kustomize build overlays/${ENVIRONMENTS[0]}"
      echo ""
      echo "# To apply with kubectl:"
      echo "kubectl apply -k overlays/${ENVIRONMENTS[0]}"
    fi
  fi
}

# ----- Main Execution -----

main() {
  # Parse command line arguments
  parse_args "$@"
  
  # Set up directory structure
  setup_directories
  
  # Render Helm chart to YAML
  rendered_file=$(render_helm_chart)
  
  # Extract CRDs if requested
  if $EXTRACT_CRDS; then
    extract_crds "$rendered_file"
  fi
  
  # Process based on output mode
  if $SINGLE_FILE; then
    handle_single_file "$rendered_file"
  else
    split_resources "$rendered_file"
    
    # If not plain YAML, create Kustomize structure
    if ! $USE_PLAIN; then
      create_base_kustomization
      create_overlays
    fi
  fi
  
  # Clean up
  rm -f "$rendered_file"
  
  # Print summary
  print_summary
}

# Execute main function with all arguments
main "$@"
