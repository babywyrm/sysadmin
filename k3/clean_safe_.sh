#!/bin/bash

# Safe K3s/CTF Cleanup Script with Human Verification ..beta..
# Run as root
# Usage: 
#   ./safe-cleanup.sh                      # Dry-run (default, safe)
#   ./safe-cleanup.sh --execute            # Actually perform cleanup
#   ./safe-cleanup.sh --verbose            # Dry-run with verbose output
#   ./safe-cleanup.sh --execute --verbose  # Execute with detailed logging

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Default to dry-run (safe mode)
DRY_RUN=true
VERBOSE=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --execute)
            DRY_RUN=false
            ;;
        --verbose|-v)
            VERBOSE=true
            ;;
    esac
done

if [ "$DRY_RUN" = false ]; then
    echo -e "${RED}=== EXECUTE MODE - Changes WILL be made ===${NC}"
    echo -e "${YELLOW}Press Ctrl+C within 5 seconds to abort...${NC}"
    sleep 5
    echo ""
else
    echo -e "${BLUE}=== DRY RUN MODE (Default) - No changes will be made ===${NC}"
    echo -e "${GREEN}Run with --execute flag to perform actual cleanup${NC}"
    echo ""
fi

if [ "$VERBOSE" = true ]; then
    echo -e "${CYAN}=== VERBOSE MODE ENABLED ===${NC}"
    echo ""
fi

echo -e "${GREEN}=== Safe CTF VM Cleanup Script ===${NC}"
echo "This script will guide you through cleanup with confirmation at each step"
echo ""

# Function to show disk usage
show_disk() {
    echo -e "${YELLOW}Current disk usage:${NC}"
    df -h / | grep -v Filesystem
    if [ "$VERBOSE" = true ]; then
        echo ""
        echo -e "${CYAN}[VERBOSE] Detailed disk breakdown by mount:${NC}"
        df -h | grep -E "(Filesystem|/dev/|overlay|tmpfs)" | head -15
        echo ""
        echo -e "${CYAN}[VERBOSE] Top 10 directories by size in /:${NC}"
        du -sh /* 2>/dev/null | sort -rh | head -10
        echo ""
        echo -e "${CYAN}[VERBOSE] Inode usage:${NC}"
        df -i / | grep -v Filesystem
    fi
    echo ""
}

# Function for verbose logging
log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}[VERBOSE] $1${NC}"
    fi
}

# Function to ask for confirmation
confirm() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${BLUE}[DRY-RUN] Would ask: $1${NC}"
        return 0
    fi
    read -p "$(echo -e ${YELLOW}$1 [y/N]: ${NC})" response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            echo -e "${RED}Skipped.${NC}"
            return 1
            ;;
    esac
}

# Function to execute or simulate command
execute() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${BLUE}[DRY-RUN] Would execute: $@${NC}"
    else
        if [ "$VERBOSE" = true ]; then
            echo -e "${CYAN}[VERBOSE] Executing: $@${NC}"
        fi
        eval "$@"
        local exit_code=$?
        if [ "$VERBOSE" = true ]; then
            if [ $exit_code -eq 0 ]; then
                echo -e "${CYAN}[VERBOSE] Command completed successfully (exit code: 0)${NC}"
            else
                echo -e "${CYAN}[VERBOSE] Command returned exit code: $exit_code${NC}"
            fi
        fi
    fi
}

# Initial disk state
echo "=== INITIAL STATE ==="
show_disk

if [ "$VERBOSE" = true ]; then
    log_verbose "System uptime and load:"
    uptime
    echo ""
    log_verbose "Memory usage:"
    free -h
    echo ""
fi

# Step 1: List unused container images
echo -e "${GREEN}=== Step 1: Check for unused container images ===${NC}"
echo "Currently running images:"
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | sort -u

if [ "$VERBOSE" = true ]; then
    log_verbose "Full pod to image mapping:"
    kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.spec.containers[].image)"'
    echo ""
    log_verbose "Image pull policies by pod:"
    kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.spec.containers[0].imagePullPolicy)"'
    echo ""
    log_verbose "Init containers (if any):"
    kubectl get pods -A -o json | jq -r '.items[] | select(.spec.initContainers != null) | "\(.metadata.namespace)/\(.metadata.name): \(.spec.initContainers[].image)"' || echo "  None found"
fi

echo ""
echo "All images on system:"
crictl images

if [ "$VERBOSE" = true ]; then
    echo ""
    log_verbose "Image details with creation dates:"
    crictl images --digests | head -20
    echo ""
    log_verbose "Image size breakdown:"
    crictl images | awk 'NR>1 {print $NF}' | awk '{sum+=$1; count++} END {print "  Total images: " count "\n  Average size: " sum/count/1024 " MB\n  Total size: " sum/1024 " MB"}'
    echo ""
    log_verbose "Containerd storage location size:"
    du -sh /var/lib/rancher/k3s/agent/containerd 2>/dev/null || echo "  Path not accessible"
fi

echo ""

if confirm "Review unused images and continue?"; then
    echo "Identifying unused images..."
    RUNNING_IMAGES=$(kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | sort -u)
    
    if [ "$VERBOSE" = true ]; then
        log_verbose "Running images list (${RUNNING_IMAGES} total):"
        echo "$RUNNING_IMAGES" | nl | while read num img; do
            echo -e "${CYAN}  $num. $img${NC}"
        done
        echo ""
        log_verbose "Comparing all images to running images..."
        crictl images --quiet | while read img_id; do
            img_name=$(crictl images | grep $img_id | awk '{print $1":"$2}')
            if echo "$RUNNING_IMAGES" | grep -q "$img_name"; then
                echo -e "${GREEN}  ✓ IN USE: $img_name ($img_id)${NC}"
            else
                echo -e "${YELLOW}  ⚠ UNUSED: $img_name ($img_id)${NC}"
            fi
        done
    fi
    
    echo ""
    echo -e "${YELLOW}Safe to remove (old WordPress):${NC}"
    OLD_WP_IMAGES=$(crictl images | grep "6.8.1-debian" || echo "")
    if [ ! -z "$OLD_WP_IMAGES" ]; then
        echo "$OLD_WP_IMAGES"
    else
        echo "None found"
    fi
    echo ""
    
    if confirm "Remove old WordPress 6.8.1 image?"; then
        OLD_WP=$(crictl images | grep "6.8.1-debian" | awk '{print $3}' | head -1)
        if [ ! -z "$OLD_WP" ]; then
            if [ "$VERBOSE" = true ]; then
                OLD_WP_SIZE=$(crictl images | grep "$OLD_WP" | awk '{print $NF}')
                OLD_WP_REPO=$(crictl images | grep "$OLD_WP" | awk '{print $1":"$2}')
                log_verbose "Image details:"
                log_verbose "  ID: $OLD_WP"
                log_verbose "  Repository: $OLD_WP_REPO"
                log_verbose "  Size: $OLD_WP_SIZE"
                log_verbose "Checking for dependent containers..."
                crictl ps -a | grep $OLD_WP || log_verbose "  No containers using this image"
            fi
            execute "crictl rmi $OLD_WP"
            echo -e "${GREEN}✓ Removed old WordPress image${NC}"
        else
            echo "No old WordPress image to remove"
        fi
    fi
    
    echo ""
    if confirm "Run crictl prune to remove dangling images?"; then
        if [ "$VERBOSE" = true ]; then
            log_verbose "Checking for dangling images before prune..."
            DANGLING=$(crictl images | grep '<none>' | wc -l)
            if [ $DANGLING -gt 0 ]; then
                log_verbose "Found $DANGLING dangling images:"
                crictl images | grep '<none>'
            else
                log_verbose "No dangling images found"
            fi
        fi
        execute "crictl rmi --prune"
        echo -e "${GREEN}✓ Pruned dangling images${NC}"
        if [ "$VERBOSE" = true ] && [ "$DRY_RUN" = false ]; then
            log_verbose "Images after prune:"
            crictl images | wc -l
            echo "  images remaining"
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        show_disk
    fi
fi

# Step 2: Clean up exited containers
echo -e "${GREEN}=== Step 2: Check for exited containers ===${NC}"
EXITED=$(crictl ps -a --state=exited -q 2>/dev/null | wc -l)
RUNNING=$(crictl ps -q 2>/dev/null | wc -l)

if [ "$VERBOSE" = true ]; then
    log_verbose "Container statistics:"
    log_verbose "  Running: $RUNNING"
    log_verbose "  Exited: $EXITED"
    CREATED=$(crictl ps -a --state=created -q 2>/dev/null | wc -l)
    log_verbose "  Created (not started): $CREATED"
    echo ""
fi

if [ "$EXITED" -gt 0 ]; then
    echo "Found $EXITED exited containers:"
    crictl ps -a --state=exited
    
    if [ "$VERBOSE" = true ]; then
        log_verbose "Exited container detailed information:"
        crictl ps -a --state=exited --no-trunc | head -20
        echo ""
        log_verbose "Exit reasons (if available):"
        crictl ps -a --state=exited -o json 2>/dev/null | jq -r '.containers[] | "  \(.metadata.name): Exit code \(.state.exitCode) - \(.state.reason // "Unknown")"' | head -10
    fi
    
    echo ""
    
    if confirm "Remove these exited containers?"; then
        EXITED_IDS=$(crictl ps -a --state=exited -q)
        if [ ! -z "$EXITED_IDS" ]; then
            if [ "$VERBOSE" = true ]; then
                NUM_CONTAINERS=$(echo $EXITED_IDS | wc -w)
                log_verbose "Removing $NUM_CONTAINERS exited containers"
                log_verbose "Container IDs: $(echo $EXITED_IDS | head -c 100)..."
            fi
            execute "crictl rm \$(crictl ps -a --state=exited -q) 2>/dev/null || true"
            echo -e "${GREEN}✓ Removed exited containers${NC}"
            if [ "$VERBOSE" = true ] && [ "$DRY_RUN" = false ]; then
                NEW_EXITED=$(crictl ps -a --state=exited -q 2>/dev/null | wc -l)
                log_verbose "Exited containers remaining: $NEW_EXITED"
            fi
        fi
        if [ "$DRY_RUN" = false ]; then
            show_disk
        fi
    fi
else
    echo "No exited containers found."
    if [ "$VERBOSE" = true ]; then
        log_verbose "All $RUNNING containers are running"
        log_verbose "Top 5 containers by uptime:"
        crictl ps -o json | jq -r '.containers[] | "\(.metadata.name): \(.createdAt)"' | head -5
    fi
fi

# Step 3: Clean journal logs
echo -e "${GREEN}=== Step 3: Check journal logs size ===${NC}"
JOURNAL_SIZE=$(journalctl --disk-usage | grep -oP '\d+\.\d+[GM]' | head -1)
journalctl --disk-usage

if [ "$VERBOSE" = true ]; then
    log_verbose "Current journal size: $JOURNAL_SIZE"
    echo ""
    log_verbose "Journal file locations and sizes:"
    ls -lh /var/log/journal/*/*.journal* 2>/dev/null | head -10 || log_verbose "  No journal files found in expected location"
    echo ""
    log_verbose "Oldest journal entry:"
    journalctl --no-pager -n 1 --reverse | head -5
    echo ""
    log_verbose "Newest journal entry:"
    journalctl --no-pager -n 1 | head -5
    echo ""
    log_verbose "Journal entries per unit (top 10):"
    journalctl --no-pager --output=json | jq -r '._SYSTEMD_UNIT' | sort | uniq -c | sort -rn | head -10
fi

echo ""

if confirm "Vacuum journal logs to 100M?"; then
    execute "journalctl --vacuum-size=100M"
    echo -e "${GREEN}✓ Journal logs cleaned${NC}"
    if [ "$DRY_RUN" = false ]; then
        show_disk
        if [ "$VERBOSE" = true ]; then
            NEW_SIZE=$(journalctl --disk-usage | grep -oP '\d+\.\d+[GM]' | head -1)
            log_verbose "New journal size: $NEW_SIZE"
            log_verbose "Space saved: Approximately $(echo "$JOURNAL_SIZE - $NEW_SIZE" | bc 2>/dev/null || echo "N/A")"
        fi
    fi
fi

# Step 4: APT cache cleanup
echo -e "${GREEN}=== Step 4: Check APT cache ===${NC}"
APT_SIZE=$(du -sh /var/cache/apt/archives 2>/dev/null | cut -f1 || echo "0")
echo "APT cache size: $APT_SIZE"

if [ "$VERBOSE" = true ]; then
    APT_FILES=$(ls /var/cache/apt/archives/*.deb 2>/dev/null | wc -l)
    log_verbose "Number of cached .deb files: $APT_FILES"
    echo ""
    if [ $APT_FILES -gt 0 ]; then
        log_verbose "Largest cached packages (top 10):"
        du -h /var/cache/apt/archives/*.deb 2>/dev/null | sort -rh | head -10 | nl
        echo ""
        log_verbose "Smallest cached packages (bottom 5):"
        du -h /var/cache/apt/archives/*.deb 2>/dev/null | sort -h | head -5 | nl
    fi
    echo ""
    log_verbose "APT lists size:"
    du -sh /var/lib/apt/lists/ 2>/dev/null || echo "  N/A"
fi

echo ""

if confirm "Clean APT cache?"; then
    if [ "$VERBOSE" = true ]; then
        log_verbose "Files to be removed:"
        ls -lh /var/cache/apt/archives/*.deb 2>/dev/null | wc -l
        echo "  .deb files"
    fi
    execute "apt clean"
    echo -e "${GREEN}✓ APT cache cleaned${NC}"
    if [ "$DRY_RUN" = false ]; then
        show_disk
        if [ "$VERBOSE" = true ]; then
            NEW_APT_SIZE=$(du -sh /var/cache/apt/archives 2>/dev/null | cut -f1 || echo "0")
            log_verbose "New APT cache size: $NEW_APT_SIZE"
        fi
    fi
fi

# Step 5: Check for autoremovable packages
echo -e "${GREEN}=== Step 5: Check for unused packages ===${NC}"
INSTALLED=$(apt list --installed 2>/dev/null | wc -l)
echo "$INSTALLED packages installed"
AUTOREMOVE=$(apt-get --dry-run autoremove 2>/dev/null | grep -c "^Remov" || echo "0")
echo "$AUTOREMOVE packages can be autoremoved"

if [ "$VERBOSE" = true ]; then
    echo ""
    log_verbose "Recently installed packages (last 20):"
    grep " install " /var/log/dpkg.log 2>/dev/null | tail -20 | awk '{print "  " $1 " " $2 " - " $4}' || log_verbose "  Log not available"
    echo ""
    
    if [ "$AUTOREMOVE" -gt 0 ]; then
        log_verbose "Packages that would be removed (showing all):"
        apt-get --dry-run autoremove 2>/dev/null | grep "^Remov" | nl
        echo ""
        log_verbose "Estimated space to be freed:"
        apt-get --dry-run autoremove 2>/dev/null | grep "freed" || log_verbose "  Estimate not available"
    fi
fi

echo ""

if [ "$AUTOREMOVE" -gt 0 ]; then
    if confirm "Run apt autoremove (removes $AUTOREMOVE unused dependencies)?"; then
        execute "apt autoremove -y"
        echo -e "${GREEN}✓ Unused packages removed${NC}"
        if [ "$DRY_RUN" = false ]; then
            show_disk
            if [ "$VERBOSE" = true ]; then
                NEW_INSTALLED=$(apt list --installed 2>/dev/null | wc -l)
                log_verbose "Packages after cleanup: $NEW_INSTALLED (removed $((INSTALLED - NEW_INSTALLED)))"
            fi
        fi
    fi
else
    echo "No packages to autoremove"
fi

# Step 6: Check large files (informational only)
echo -e "${GREEN}=== Step 6: Check for large files ===${NC}"

if [ "$VERBOSE" = true ]; then
    echo "Scanning for files >100M... (showing top 30, this may take a minute)"
    echo ""
    LARGE_FILES=$(find / -type f -size +100M 2>/dev/null | head -30)
    
    if [ ! -z "$LARGE_FILES" ]; then
        log_verbose "Large files with full details:"
        echo "$LARGE_FILES" | while read file; do
            if [ -f "$file" ]; then
                size=$(du -h "$file" 2>/dev/null | cut -f1)
                perms=$(ls -lh "$file" 2>/dev/null | awk '{print $1}')
                owner=$(ls -lh "$file" 2>/dev/null | awk '{print $3":"$4}')
                modified=$(stat -c %y "$file" 2>/dev/null | cut -d'.' -f1)
                echo -e "${CYAN}  Size: $size | Owner: $owner | Modified: $modified${NC}"
                echo "    Path: $file"
                echo "    Permissions: $perms"
            fi
        done
        echo ""
        
        log_verbose "Additional scans:"
        echo ""
        log_verbose "Files >500M:"
        find / -type f -size +500M 2>/dev/null | while read f; do
            du -h "$f" 2>/dev/null
        done | head -10 || echo "  None found"
        
        echo ""
        log_verbose "Files >1G:"
        find / -type f -size +1G 2>/dev/null | while read f; do
            du -h "$f" 2>/dev/null
        done | head -5 || echo "  None found"
        
        echo ""
        log_verbose "Large log files (>50M):"
        find /var/log -type f -size +50M 2>/dev/null | while read f; do
            du -h "$f" 2>/dev/null
        done || echo "  None found"
        
        echo ""
        log_verbose "Largest directories in /var:"
        du -sh /var/* 2>/dev/null | sort -rh | head -10
        
    else
        echo "No files >100M found"
    fi
else
    echo "Scanning for files >100M... (showing top 10)"
    echo ""
    LARGE_FILES=$(find / -type f -size +100M 2>/dev/null | head -10)
    if [ ! -z "$LARGE_FILES" ]; then
        echo "$LARGE_FILES" | while read file; do
            size=$(du -h "$file" 2>/dev/null | cut -f1)
            echo "  $size - $file"
        done
    else
        echo "No large files found"
    fi
fi

echo ""
echo -e "${YELLOW}Review these manually if needed. NOT automatically removing.${NC}"
echo -e "${CYAN}Tip: Run with --verbose to see files >500M and >1G as well${NC}"
echo ""

if confirm "Continue to final verification?"; then
    echo ""
fi

# Step 7: Verify CTF services still running
echo -e "${GREEN}=== Step 7: VERIFY CTF SERVICES ===${NC}"
echo "Checking all pods are running..."
kubectl get pods -A

if [ "$VERBOSE" = true ]; then
    echo ""
    log_verbose "Detailed pod status:"
    kubectl get pods -A -o wide
    echo ""
    log_verbose "Pod resource requests and limits:"
    kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): CPU: \(.spec.containers[0].resources.requests.cpu // "none") / Mem: \(.spec.containers[0].resources.requests.memory // "none")"' | head -10
    echo ""
    log_verbose "Pod restart counts:"
    kubectl get pods -A -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name): \(.status.containerStatuses[0].restartCount) restarts"' | grep -v " 0 restarts" || echo "  No pods with restarts"
    echo ""
    log_verbose "Pod resource usage (if metrics available):"
    kubectl top pods -A 2>/dev/null | head -15 || log_verbose "  metrics-server not ready or kubectl top unavailable"
    echo ""
    log_verbose "Node status:"
    kubectl get nodes -o wide
fi

echo ""

echo "Checking WordPress version:"
WP_VERSION=$(kubectl exec -n wordpress deploy/wordpress -- wp core version 2>/dev/null || echo "Could not check")
echo "WordPress: $WP_VERSION"

if [ "$VERBOSE" = true ]; then
    log_verbose "WordPress detailed status:"
    kubectl exec -n wordpress deploy/wordpress -- wp core check-update 2>/dev/null || log_verbose "  Update check unavailable"
    echo ""
    log_verbose "WordPress plugins:"
    kubectl exec -n wordpress deploy/wordpress -- wp plugin list 2>/dev/null | head -10 || log_verbose "  Plugin list unavailable"
    echo ""
    log_verbose "WordPress themes:"
    kubectl exec -n wordpress deploy/wordpress -- wp theme list 2>/dev/null | head -5 || log_verbose "  Theme list unavailable"
    echo ""
    log_verbose "WordPress database status:"
    kubectl exec -n wordpress deploy/wordpress -- wp db check 2>/dev/null || log_verbose "  Database check unavailable"
    echo ""
    log_verbose "PVC status and usage:"
    kubectl get pvc -n wordpress
    echo ""
    kubectl get pvc -n wordpress -o json | jq -r '.items[] | "\(.metadata.name): \(.status.capacity.storage) capacity"'
fi

echo ""

echo "Checking available images:"
crictl images

if [ "$VERBOSE" = true ]; then
    echo ""
    log_verbose "Container runtime information:"
    crictl info 2>/dev/null | grep -E "(version|runtime|storage)" | head -10 || log_verbose "  Runtime info unavailable"
    echo ""
    log_verbose "K3s service status:"
    systemctl status k3s --no-pager -l | head -15 || log_verbose "  K3s service status unavailable"
    echo ""
    log_verbose "Recent K3s logs:"
    journalctl -u k3s --no-pager -n 10 --since "5 minutes ago" 2>/dev/null || log_verbose "  Recent logs unavailable"
fi

echo ""

# Final summary
echo -e "${GREEN}=== CLEANUP COMPLETE ===${NC}"
show_disk

if [ "$VERBOSE" = true ]; then
    log_verbose "Final system statistics:"
    log_verbose "  Uptime: $(uptime -p)"
    log_verbose "  Load average: $(uptime | awk -F'load average:' '{print $2}')"
    log_verbose "  Memory available: $(free -h | awk 'NR==2{print $7}')"
    log_verbose "  Swap used: $(free -h | awk 'NR==3{print $3}')"
    echo ""
fi

echo ""
if [ "$DRY_RUN" = true ]; then
    echo -e "${BLUE}✓ Dry-run finished - no changes were made${NC}"
    echo -e "${GREEN}Run with --execute flag to perform actual cleanup:${NC}"
    echo -e "${YELLOW}  ./safe-cleanup.sh --execute${NC}"
    if [ "$VERBOSE" = false ]; then
        echo -e "${CYAN}Add --verbose flag for much more detailed output${NC}"
    fi
else
    echo -e "${GREEN}✓ Cleanup finished safely${NC}"
    echo -e "${YELLOW}Verify your CTF challenges are still accessible!${NC}"
fi
