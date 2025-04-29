#!/usr/bin/env bash
set -euo pipefail

# Parse args
USE_PLAIN=false
if [[ "${1:-}" =~ ^(-p|--plain)$ ]]; then
  USE_PLAIN=true
  shift
fi

if (( $# != 3 )); then
  echo "Usage: $0 [--plain] <RELEASE_NAME> <CHART_PATH> <NAMESPACE>"
  exit 1
fi

RELEASE_NAME=$1
CHART_PATH=$2
NAMESPACE=$3

# Directories
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

# 1) Render all resources
TMP_RENDER=$(mktemp)
helm template "$RELEASE_NAME" "$CHART_PATH" \
  --namespace "$NAMESPACE" > "$TMP_RENDER"

# 2) Split into fragments
FRAG_PREFIX=$([[ $USE_PLAIN == true ]] && echo "$OUT_DIR/rsrc-" || echo "$BASE_DIR/rsrc-")
csplit -q --suppress-matched \
  --prefix="$FRAG_PREFIX" --suffix-format='%02d.yaml' \
  "$TMP_RENDER" '/^---$/' '{*}'
rm "$TMP_RENDER"

# 3) Rename fragments by kind-name
for f in $FRAG_PREFIX*.yaml; do
  kind=$(yq e '.kind' "$f" 2>/dev/null || echo "null")
  name=$(yq e '.metadata.name' "$f" 2>/dev/null || echo "null")
  if [[ "$kind" != "null" && "$name" != "null" ]]; then
    target_dir=$([[ $USE_PLAIN == true ]] && echo "$OUT_DIR" || echo "$BASE_DIR")
    newfile="$target_dir/$(tr '[:upper:]' '[:lower:]' <<<"$kind")-$name.yaml"
    mv "$f" "$newfile"
  else
    rm "$f"
  fi
done

# 4a) If plain mode, finish
if $USE_PLAIN; then
  echo "Generated plain manifests in '$OUT_DIR/'."
  echo "Commit them and point your ArgoCD Application at this directory."
  exit 0
fi

# 4b) Kustomize mode scaffolding

# base/kustomization.yaml
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

# overlays/dev & overlays/prod
for env in "${OVERLAYS[@]}"; do
  mkdir -p overlays/$env
  cat > overlays/$env/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../base

# Uncomment & tune:
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

  cat > overlays/$env/patch-deployment.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $RELEASE_NAME
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: $RELEASE_NAME
        # image: your-image:${env}-tag
        # env:
        # - name: LOG_LEVEL
        #   value: DEBUG
EOF
done

echo "Kustomize scaffold created:"
echo "  base/          ← static manifests + base kustomization.yaml"
echo "  overlays/dev/  ← dev overlay stub"
echo "  overlays/prod/ ← prod overlay stub"
echo
echo "Next steps:"
echo "1) Edit base/*.yaml to remove inlined secrets/config as needed."
echo "2) Uncomment & configure secretGenerator/configMapGenerator or patches."
echo "3) Commit to Git."
echo "4) Point ArgoCD at overlays/{dev,prod}."
