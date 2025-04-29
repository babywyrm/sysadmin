#!/usr/bin/env bash
set -euo pipefail

# Usage: ./unhelm.sh <RELEASE_NAME> <CHART_PATH> <NAMESPACE>
# Example: ./unhelm.sh my-release ./charts/mychart default

RELEASE_NAME=$1
CHART_PATH=$2
NAMESPACE=$3

# dirs
BASE_DIR=base
OVERLAYS=(dev prod)

# 1. Clean & prep
rm -rf $BASE_DIR overlays
mkdir -p $BASE_DIR

# 2. Helm-render all resources to a single file
helm template "$RELEASE_NAME" "$CHART_PATH" \
  --namespace "$NAMESPACE" > $BASE_DIR/all.yaml

# 3. Split by `---` into per-resource files
csplit -q --suppress-matched \
  --prefix=$BASE_DIR/rsrc- \
  --suffix-format='%02d.yaml' \
  $BASE_DIR/all.yaml '/^---$/' '{*}'

# 4. For each fragment, detect its kind/name and rename it
for f in $BASE_DIR/rsrc-*.yaml; do
  kind=$(yq e '.kind' $f)
  name=$(yq e '.metadata.name' $f)
  if [[ "$kind" != "null" && "$name" != "null" ]]; then
    newfile="$BASE_DIR/$(echo $kind | tr '[:upper:]' '[:lower:]')-$name.yaml"
    mv $f $newfile
  else
    rm $f
  fi
done

# 5. Create base/kustomization.yaml
cat > $BASE_DIR/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: $NAMESPACE

resources:
$(for f in $BASE_DIR/*.yaml; do
    [[ "$f" == *kustomization.yaml ]] && continue
    echo "  - $(basename $f)"
  done)

# uncomment to generate secrets/configmaps instead of static
# secretGenerator:
#   - name: ${RELEASE_NAME}-creds
#     literals:
#       - USERNAME=\$(USERNAME)
#       - PASSWORD=\$(PASSWORD)
# generatorOptions:
#   disableNameSuffixHash: true

EOF

# 6. Scaffold overlays
for env in "${OVERLAYS[@]}"; do
  mkdir -p overlays/$env
  cat > overlays/$env/kustomization.yaml <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

bases:
  - ../../base

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

  # example patch stub
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
        # override image or env here
        # image: your-image:${env}-tag
EOF
done

echo "Done.  
