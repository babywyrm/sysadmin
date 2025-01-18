##
##
## https://gist.github.com/superseb/aaee8d3c6e5b95ee3a09e40966f55ecb
##
##

TMPDIR=$(mktemp -d $MKTEMP_BASEDIR)
# k3s
if $(command -v k3s >/dev/null 2>&1); then
        mkdir -p $TMPDIR/k3s/crictl
        mkdir -p $TMPDIR/k3s/logs
        mkdir -p $TMPDIR/k3s/podlogs
        mkdir -p $TMPDIR/k3s/kubectl
        k3s check-config > $TMPDIR/k3s/check-config 2>&1
        k3s kubectl get nodes -o json > $TMPDIR/k3s/kubectl/nodes 2>&1
        k3s kubectl version > $TMPDIR/k3s/kubectl/version 2>&1
        k3s kubectl get pods --all-namespaces > $TMPDIR/k3s/kubectl/pods 2>&1
        if $(grep "k3s.service" $TMPDIR/systeminfo/systemd-units > /dev/null 2>&1); then
                journalctl --unit=k3s > $TMPDIR/k3s/logs/journalctl-k3s
        fi
        for SYSTEMNAMESPACE in "${SYSTEMNAMESPACES[@]}"; do
                for SYSTEMPOD in $(k3s kubectl -n $SYSTEMNAMESPACE get pods --no-headers -o custom-columns=NAME:.metadata.name); do
                        k3s kubectl -n $SYSTEMNAMESPACE logs $SYSTEMPOD > $TMPDIR/k3s/podlogs/$SYSTEMNAMESPACE-$SYSTEMPOD 2>&1
                done
        done
        k3s crictl ps -a > $TMPDIR/k3s/crictl/psa 2>&1
        k3s crictl pods > $TMPDIR/k3s/crictl/pods 2>&1
        k3s crictl info > $TMPDIR/k3s/crictl/info 2>&1
        k3s crictl stats > $TMPDIR/k3s/crictl/stats 2>&1
        k3s crictl version > $TMPDIR/k3s/crictl/version 2>&1
        k3s crictl images > $TMPDIR/k3s/crictl/images 2>&1
        k3s crictl imagefsinfo > $TMPDIR/k3s/crictl/imagefsinfo 2>&1
fi

##
##
