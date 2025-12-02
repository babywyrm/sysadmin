#!/bin/bash
# ============================================================================
# Kubernetes Pod Deduplication & Container Image Analysis
# ============================================================================
# Purpose: Analyze pod distribution, workload patterns, and container image
#          usage across namespaces
# Usage: ./k8s_analysis.sh [options]
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration & Defaults
# ============================================================================
NAMESPACE=""
KUBECTL_CMD="${KUBECTL_CMD:-kubectl}"
TOP_N="${TOP_N:-30}"
REPLICA_THRESHOLD="${REPLICA_THRESHOLD:-1}"
SAMPLE_SIZE="${SAMPLE_SIZE:-10}"
IMAGE_PATTERNS=""

# ============================================================================
# Help & Usage
# ============================================================================
show_help() {
    cat << EOF
Kubernetes Pod Deduplication & Container Image Analysis

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -n, --namespace NAMESPACE    Limit analysis to specific namespace
    -k, --kubectl COMMAND        kubectl command to use (default: kubectl)
    -t, --top N                  Show top N results (default: 30)
    -r, --replicas N             Min replicas to show (default: 1)
    -s, --sample N               Sample size for examples (default: 10)
    -p, --patterns "P1,P2"       Comma-separated image patterns to analyze
    -h, --help                   Show this help message

EXAMPLES:
    # Analyze entire cluster
    $0

    # Analyze specific namespace
    $0 -n production

    # Use with teleport kubectl
    $0 -k "tsh kubectl" -n staging

    # Search for specific image patterns
    $0 -p "nginx,redis,postgres" -t 50

ENVIRONMENT VARIABLES:
    KUBECTL_CMD          Override kubectl command (default: kubectl)
    TOP_N                Default number of top results to show
    REPLICA_THRESHOLD    Minimum replica count to display
    SAMPLE_SIZE          Number of normalization examples

EOF
    exit 0
}

# ============================================================================
# Argument Parsing
# ============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -k|--kubectl)
                KUBECTL_CMD="$2"
                shift 2
                ;;
            -t|--top)
                TOP_N="$2"
                shift 2
                ;;
            -r|--replicas)
                REPLICA_THRESHOLD="$2"
                shift 2
                ;;
            -s|--sample)
                SAMPLE_SIZE="$2"
                shift 2
                ;;
            -p|--patterns)
                IMAGE_PATTERNS="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Function: Normalize workload names
# ============================================================================
# Removes transient identifiers (replica hashes, ordinals, etc.) to group
# related pods into logical workloads
normalize_workload() {
    echo "$1" | awk '{
        name=$1;
        # Remove ReplicaSet/Deployment hash suffixes
        gsub(/-[a-z0-9]{8,10}(-[a-z0-9]{5})?$/, "", name);
        # Normalize numbered suffixes with common patterns
        gsub(/-[0-9]+-[a-z]+$/, "-\\1", name);
        # Remove job/worker suffixes
        gsub(/-(taskmanager|worker|job)(-[0-9]+)?(-[0-9]+)?$/, "", name);
        # Remove StatefulSet ordinals (preserve version patterns)
        if (name !~ /-[0-9]+-[0-9]+$/) {
            gsub(/-[0-9]+$/, "", name);
        }
        print name;
    }'
}

# ============================================================================
# Data Collection
# ============================================================================
collect_pod_data() {
    if [ -z "$NAMESPACE" ]; then
        $KUBECTL_CMD get pods -A -o json
    else
        $KUBECTL_CMD get pods -n "$NAMESPACE" -o json
    fi
}

# ============================================================================
# Report Header
# ============================================================================
print_header() {
    echo "================================================================================"
    echo "KUBERNETES POD DEDUPLICATION & IMAGE ANALYSIS REPORT"
    echo "Date: $(date)"
    [ -n "$NAMESPACE" ] && echo "Namespace: $NAMESPACE" || echo "Scope: All Namespaces"
    echo "================================================================================"
    echo ""
}

# ============================================================================
# Section Divider
# ============================================================================
print_section() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "$1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ============================================================================
# SECTION 1: Deduplication Statistics
# ============================================================================
analyze_deduplication() {
    local pods_data="$1"
    
    print_section "1. DEDUPLICATION ANALYSIS"
    
    local total_pods=$(echo "$pods_data" | jq -r '.items | length')
    echo "Total Pods: $total_pods"
    
    local unique_workloads=$(echo "$pods_data" | jq -r '
        .items[] | "\(.metadata.namespace)/\(.metadata.name)"
    ' | while read line; do
        local ns=$(echo "$line" | cut -d'/' -f1)
        local pod=$(echo "$line" | cut -d'/' -f2)
        local normalized=$(normalize_workload "$pod")
        echo "$ns/$normalized"
    done | sort -u | wc -l)
    
    echo "Unique Workloads (normalized): $unique_workloads"
    
    if [ "$unique_workloads" -gt 0 ]; then
        local ratio=$(echo "scale=2; $total_pods / $unique_workloads" | bc)
        echo "Deduplication Ratio: ${ratio}x (avg pods per workload)"
    fi
    echo ""
}

# ============================================================================
# SECTION 2: Shared Images Analysis
# ============================================================================
analyze_shared_images() {
    local pods_data="$1"
    
    print_section "2. SHARED CONTAINER IMAGES (Top $TOP_N)"
    echo "Format: [workload_count] [image_name]"
    echo ""
    
    echo "$pods_data" | jq -r '
        .items[] | 
        .metadata.namespace as $ns | 
        .metadata.name as $pod | 
        .spec.containers[0] | 
        "\(.image)\t\($ns)\t\($pod)"
    ' | while IFS=$'\t' read image ns pod; do
        local normalized=$(normalize_workload "$pod")
        echo "$image	$ns/$normalized"
    done | sort -u | awk '{
        images[$2]=$1; 
    } END {
        for (w in images) {
            img=images[w]; 
            count[img]++;
        } 
        for (i in count) {
            print count[i], i;
        }
    }' | sort -rn | head -n "$TOP_N"
    
    echo ""
}

# ============================================================================
# SECTION 3: Multi-Replica Workloads
# ============================================================================
analyze_replicas() {
    local pods_data="$1"
    
    print_section "3. MULTI-REPLICA WORKLOADS (Top 20, min: $REPLICA_THRESHOLD)"
    echo "Format: [replica_count] [namespace/workload]"
    echo ""
    
    echo "$pods_data" | jq -r '
        .items[] | "\(.metadata.namespace)/\(.metadata.name)"
    ' | while read line; do
        local ns=$(echo "$line" | cut -d'/' -f1)
        local pod=$(echo "$line" | cut -d'/' -f2)
        local normalized=$(normalize_workload "$pod")
        echo "$ns/$normalized"
    done | sort | uniq -c | sort -rn | \
        awk -v thresh="$REPLICA_THRESHOLD" '$1 > thresh' | head -20
    
    echo ""
}

# ============================================================================
# SECTION 4: Normalization Examples
# ============================================================================
show_normalization_examples() {
    local pods_data="$1"
    
    print_section "4. NORMALIZATION EXAMPLES (Sample: $SAMPLE_SIZE)"
    echo "Format: [original_pod_name] → [normalized_workload_name]"
    echo ""
    
    echo "$pods_data" | jq -r '.items[] | .metadata.name' | \
        shuf | head -n "$SAMPLE_SIZE" | while read pod; do
        local normalized=$(normalize_workload "$pod")
        printf "%-70s → %s\n" "$pod" "$normalized"
    done
    
    echo ""
}

# ============================================================================
# SECTION 5: Pattern-Based Image Analysis
# ============================================================================
analyze_image_patterns() {
    local pods_data="$1"
    
    if [ -z "$IMAGE_PATTERNS" ]; then
        return
    fi
    
    print_section "5. PATTERN-BASED IMAGE ANALYSIS"
    
    IFS=',' read -ra patterns <<< "$IMAGE_PATTERNS"
    
    for pattern in "${patterns[@]}"; do
        pattern=$(echo "$pattern" | xargs)  # trim whitespace
        
        local count=$(echo "$pods_data" | jq -r --arg pattern "$pattern" '
            .items[] | 
            select(.spec.containers[0].image | contains($pattern)) | 
            "\(.metadata.namespace)/\(.metadata.name)"
        ' | while read line; do
            local ns=$(echo "$line" | cut -d'/' -f1)
            local pod=$(echo "$line" | cut -d'/' -f2)
            local normalized=$(normalize_workload "$pod")
            echo "$ns/$normalized"
        done | sort -u | wc -l)
        
        if [ "$count" -gt 0 ]; then
            echo "Pattern '$pattern': $count unique workloads"
        fi
    done
    
    echo ""
}

# ============================================================================
# SECTION 6: Summary Statistics
# ============================================================================
print_summary() {
    local pods_data="$1"
    
    print_section "6. SUMMARY STATISTICS"
    
    local total_namespaces=$(echo "$pods_data" | \
        jq -r '.items[].metadata.namespace' | sort -u | wc -l)
    local total_images=$(echo "$pods_data" | \
        jq -r '.items[].spec.containers[0].image' | sort -u | wc -l)
    local avg_containers=$(echo "$pods_data" | \
        jq '[.items[].spec.containers | length] | add / length' 2>/dev/null)
    
    echo "Namespaces: $total_namespaces"
    echo "Unique Images: $total_images"
    [ -n "$avg_containers" ] && \
        printf "Avg Containers/Pod: %.2f\n" "$avg_containers"
    
    echo ""
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    parse_args "$@"
    
    print_header
    
    echo "Collecting pod data..."
    local pods_data=$(collect_pod_data)
    echo ""
    
    analyze_deduplication "$pods_data"
    analyze_shared_images "$pods_data"
    analyze_replicas "$pods_data"
    show_normalization_examples "$pods_data"
    analyze_image_patterns "$pods_data"
    print_summary "$pods_data"
    
    echo "================================================================================"
    echo "REPORT COMPLETE"
    echo "================================================================================"
}

# ============================================================================
# Entry Point
# ============================================================================
main "$@"
