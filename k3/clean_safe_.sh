#!/bin/bash

# Safe K3s/CTF Cleanup Script with Human Verification
# Run as root
# Usage: ./safe-cleanup.sh [--dry-run]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check for dry-run flag
DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo -e "${BLUE}=== DRY RUN MODE - No changes will be made ===${NC}"
    echo ""
fi

echo -e "${GREEN}=== Safe CTF VM Cleanup Script ===${NC}"
echo "This script will guide you through cleanup with confirmation at each step"
echo ""

# Function to show disk usage
show_disk() {
    echo -e "${YELLOW}Current disk usage:${NC}"
    df -h / | grep -v Filesystem
    echo ""
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
        eval "$@"
    fi
}

# Initial disk state
echo "=== INITIAL STATE ==="
show_disk

# Step 1: List unused container images
echo -e "${GREEN}=== Step 1: Check for unused container images ===${NC}"
echo "Currently running images:"
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | sort -u
echo ""
echo "All images on system:"
crictl images
echo ""

if confirm "Review unused images and continue?"; then
    echo "Identifying unused images..."
    RUNNING_IMAGES=$(kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | sort -u)
    echo ""
    echo -e "${YELLOW}Safe to remove (old WordPress):${NC}"
    crictl images | grep "6.8.1-debian" || echo "None found"
    echo ""
    
    if confirm "Remove old WordPress 6.8.1 image?"; then
        OLD_WP=$(crictl images | grep "6.8.1-debian" | awk '{print $3}')
        if [ ! -z "$OLD_WP" ]; then
            execute "crictl rmi $OLD_WP"
            echo -e "${GREEN}✓ Removed old WordPress image${NC}"
        else
            echo "No old WordPress image to remove"
        fi
    fi
    
    echo ""
    if confirm "Run crictl prune to remove dangling images?"; then
        execute "crictl rmi --prune"
        echo -e "${GREEN}✓ Pruned dangling images${NC}"
    fi
    
    if [ "$DRY_RUN" = false ]; then
        show_disk
    fi
fi

# Step 2: Clean up exited containers
echo -e "${GREEN}=== Step 2: Check for exited containers ===${NC}"
EXITED=$(crictl ps -a --state=exited -q | wc -l)
if [ "$EXITED" -gt 0 ]; then
    echo "Found $EXITED exited containers:"
    crictl ps -a --state=exited
    echo ""
    
    if confirm "Remove these exited containers?"; then
        EXITED_IDS=$(crictl ps -a --state=exited -q)
        if [ ! -z "$EXITED_IDS" ]; then
            execute "crictl rm \$(crictl ps -a --state=exited -q)"
            echo -e "${GREEN}✓ Removed exited containers${NC}"
        fi
        if [ "$DRY_RUN" = false ]; then
            show_disk
        fi
    fi
else
    echo "No exited containers found."
fi

# Step 3: Clean journal logs
echo -e "${GREEN}=== Step 3: Check journal logs size ===${NC}"
journalctl --disk-usage
echo ""

if confirm "Vacuum journal logs to 100M?"; then
    execute "journalctl --vacuum-size=100M"
    echo -e "${GREEN}✓ Journal logs cleaned${NC}"
    if [ "$DRY_RUN" = false ]; then
        show_disk
    fi
fi

# Step 4: APT cache cleanup
echo -e "${GREEN}=== Step 4: Check APT cache ===${NC}"
APT_SIZE=$(du -sh /var/cache/apt/archives 2>/dev/null | cut -f1 || echo "0")
echo "APT cache size: $APT_SIZE"
echo ""

if confirm "Clean APT cache?"; then
    execute "apt clean"
    echo -e "${GREEN}✓ APT cache cleaned${NC}"
    if [ "$DRY_RUN" = false ]; then
        show_disk
    fi
fi

# Step 5: Check for autoremovable packages
echo -e "${GREEN}=== Step 5: Check for unused packages ===${NC}"
INSTALLED=$(apt list --installed 2>/dev/null | wc -l)
echo "$INSTALLED packages installed"
AUTOREMOVE=$(apt-get --dry-run autoremove 2>/dev/null | grep -c "^Remov" || echo "0")
echo "$AUTOREMOVE packages can be autoremoved"
echo ""

if [ "$AUTOREMOVE" -gt 0 ]; then
    if confirm "Run apt autoremove (removes $AUTOREMOVE unused dependencies)?"; then
        execute "apt autoremove -y"
        echo -e "${GREEN}✓ Unused packages removed${NC}"
        if [ "$DRY_RUN" = false ]; then
            show_disk
        fi
    fi
else
    echo "No packages to autoremove"
fi

# Step 6: Check large files (informational only)
echo -e "${GREEN}=== Step 6: Check for large files (>100M) ===${NC}"
echo "Scanning... this may take a minute..."
echo ""
LARGE_FILES=$(find / -type f -size +100M 2>/dev/null | head -10)
if [ ! -z "$LARGE_FILES" ]; then
    echo "$LARGE_FILES"
    echo ""
    echo -e "${YELLOW}Review these manually if needed. NOT automatically removing.${NC}"
else
    echo "No large files found"
fi
echo ""

if confirm "Continue to final verification?"; then
    echo ""
fi

# Step 7: Verify CTF services still running
echo -e "${GREEN}=== Step 7: VERIFY CTF SERVICES ===${NC}"
echo "Checking all pods are running..."
kubectl get pods -A
echo ""

echo "Checking WordPress version:"
WP_VERSION=$(kubectl exec -n wordpress deploy/wordpress -- wp core version 2>/dev/null || echo "Could not check")
echo "WordPress: $WP_VERSION"
echo ""

echo "Checking available images:"
crictl images
echo ""

# Final summary
echo -e "${GREEN}=== CLEANUP COMPLETE ===${NC}"
show_disk

echo ""
if [ "$DRY_RUN" = true ]; then
    echo -e "${BLUE}✓ Dry-run finished - no changes were made${NC}"
    echo -e "${YELLOW}Run without --dry-run to perform actual cleanup${NC}"
else
    echo -e "${GREEN}✓ Cleanup finished safely${NC}"
    echo -e "${YELLOW}Verify your CTF challenges are still accessible!${NC}"
fi
