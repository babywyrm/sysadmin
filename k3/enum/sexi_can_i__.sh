cat << 'EOF' > /tmp/omni_hunter.sh
#!/bin/sh
T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
A="https://kubernetes.default.svc"
MY_NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Colors
B='\033[1;34m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; NC='\033[0m'

echo "${B}--- K8S DYNAMIC OMNI-HUNTER ---${NC}"

# 1. DYNAMIC NAMESPACE DISCOVERY
echo "[*] Discovering namespaces..."
# Method A: Try listing namespaces directly
NS_LIST=$(curl -sk -H "Authorization: Bearer $T" "$A/api/v1/namespaces" | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | sort -u)

# Method B: If A fails, try to find namespaces via the 'SubjectRulesReview' or 'SelfSubjectAccessReview'
if [ -z "$NS_LIST" ]; then
    echo "[!] List namespaces denied. Probing environment..."
    # Every pod knows its own namespace
    NS_LIST="$MY_NS"
    # Brute-force common system namespaces that are nearly universal
    for g in default kube-system kube-public; do
        curl -sk -H "Authorization: Bearer $T" "$A/api/v1/namespaces/$g/configmaps" | grep -q "List" && NS_LIST="$NS_LIST $g"
    done
fi

echo -e "${G}[+] Active Namespaces: $NS_LIST${NC}"

# 2. CORE RESOURCE PROBE
# We iterate through standard resources and API groups
CORE="pods secrets configmaps services serviceaccounts"
APPS="deployments daemonsets statefulsets"
RBAC="roles rolebindings clusterroles clusterrolebindings"

for ns in $NS_LIST; do
    echo "\n${B}📁 NAMESPACE: $ns${NC}"
    
    # Check Core API (/api/v1)
    for r in $CORE; do
        OUT=$(curl -sk -H "Authorization: Bearer $T" "$A/api/v1/namespaces/$ns/$r")
        if echo "$OUT" | grep -q '"metadata"'; then
            ITEMS=$(echo "$OUT" | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | grep -v "system:" | tr '\n' ' ')
            [ -n "$ITEMS" ] && printf "  %-22s : %s\n" "$r" "$ITEMS"
        fi
    done

    # Check Apps API (/apis/apps/v1)
    for r in $APPS; do
        OUT=$(curl -sk -H "Authorization: Bearer $T" "$A/apis/apps/v1/namespaces/$ns/$r")
        if echo "$OUT" | grep -q '"metadata"'; then
            ITEMS=$(echo "$OUT" | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | grep -v "system:" | tr '\n' ' ')
            [ -n "$ITEMS" ] && printf "  %-22s : %s\n" "$r" "$ITEMS"
        fi
    done

    # Check RBAC API (/apis/rbac.authorization.k8s.io/v1)
    for r in $RBAC; do
        URL="$A/apis/rbac.authorization.k8s.io/v1/namespaces/$ns/$r"
        # If it's a Cluster resource, path is different
        [ "$r" = "clusterroles" ] || [ "$r" = "clusterrolebindings" ] && URL="$A/apis/rbac.authorization.k8s.io/v1/$r"
        
        OUT=$(curl -sk -H "Authorization: Bearer $T" "$URL")
        if echo "$OUT" | grep -q '"metadata"'; then
            ITEMS=$(echo "$OUT" | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | grep -v "system:" | tr '\n' ' ')
            [ -n "$ITEMS" ] && printf "  %-22s : %s\n" "$r" "$ITEMS"
        fi
    done
done

# 3. GLOBAL INFRASTRUCTURE
echo "\n${B}🌐 CLUSTER-WIDE ATTEMPTS${NC}"
for r in nodes persistentvolumes; do
    OUT=$(curl -sk -H "Authorization: Bearer $T" "$A/api/v1/$r")
    if echo "$OUT" | grep -q '"metadata"'; then
        ITEMS=$(echo "$OUT" | grep -o '"name": "[^"]*"' | cut -d'"' -f4 | tr '\n' ' ')
        [ -n "$ITEMS" ] && printf "  %-22s : %s\n" "$r" "$ITEMS"
    fi
done

echo "\n${B}--- ENUMERATION COMPLETE ---${NC}"
EOF
sh /tmp/omni_hunter.sh
