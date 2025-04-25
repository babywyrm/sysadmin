#!/usr/bin/env python3
"""
docker-run → Kustomize Overlay Generator (Really Really Should Be Tested..)
----------------------------------------

This script parses a `docker run …` command and emits a Kustomize overlay
consisting of:
  - deployment.yaml
  - (optional) service.yaml
  - kustomization.yaml

Examples:
  # Basic conversion, no Service
  ./krun2kustomize.py \
    --docker-run "docker run --name myapp -e FOO=bar myimage:1.2" \
    --output-dir ./kustomize/overlays/dev

  # With Service, replicas, resources & probes
  ./krun2kustomize.py \
    --docker-run "docker run -d --name webapp -p 8080:80 -e MODE=prod myimage:latest --auth-token 1234" \
    --output-dir ./kustomize/overlays/prod \
    --service \
    --replicas 3 \
    --cpu-request 100m --cpu-limit 200m \
    --memory-request 128Mi --memory-limit 256Mi \
    --liveness-path /healthz --liveness-port 80 \
    --readiness-path /ready --readiness-port 80
"""

import os
import shlex
import argparse
import itertools
import yaml
from typing import Dict, List, Optional

def parse_docker_run(cmd: str) -> Dict:
    """
    Tokenize and extract fields from a `docker run` string.
    Known flags (name, env, port, volume) go into structured fields;
    all other flags/values are captured as container args.
    """
    tokens = shlex.split(cmd)
    info = {
        "name": None,
        "image": None,
        "args": [],
        "env": [],
        "ports": [],
        "volumes": []
    }
    it = iter(tokens)
    for tok in it:
        if tok in ("docker", "run", "-d", "--rm", "--detach"):
            continue
        if tok == "--name":
            info["name"] = next(it)
        elif tok in ("-e", "--env"):
            k, v = next(it).split("=", 1)
            info["env"].append({"name": k, "value": v})
        elif tok in ("-p", "--publish"):
            _, ctr = next(it).split(":", 1)
            info["ports"].append(int(ctr))
        elif tok in ("-v", "--volume"):
            host, ctr = next(it).split(":", 1)
            info["volumes"].append({"hostPath": host, "mountPath": ctr})
        elif tok.startswith("-"):
            # unknown flag → send downstream as container arg
            info["args"].append(tok)
            if "=" not in tok:
                # maybe its value is next
                try:
                    nxt = next(it)
                    if not nxt.startswith("-"):
                        info["args"].append(nxt)
                    else:
                        it = itertools.chain([nxt], it)
                except StopIteration:
                    pass
        else:
            if info["image"] is None:
                info["image"] = tok
            else:
                info["args"].append(tok)
    return info

def build_deployment(parsed: Dict, args) -> Dict:
    name = parsed["name"] or parsed["image"].split("/")[-1].replace(":", "-")
    container: Dict = {"name": name, "image": parsed["image"]}

    if parsed["args"]:
        container["args"] = parsed["args"]
    if parsed["env"]:
        container["env"] = parsed["env"]
    if parsed["ports"]:
        container["ports"] = [{"containerPort": p} for p in parsed["ports"]]

    vols = []
    if parsed["volumes"]:
        mounts = []
        for i, v in enumerate(parsed["volumes"]):
            volname = f"vol{i}"
            mounts.append({"name": volname, "mountPath": v["mountPath"]})
            vols.append({"name": volname, **v})
        container["volumeMounts"] = mounts

    # Resources
    resources = {}
    if args.cpu_request or args.memory_request:
        resources.setdefault("requests", {})
        if args.cpu_request:    resources["requests"]["cpu"]    = args.cpu_request
        if args.memory_request: resources["requests"]["memory"] = args.memory_request
    if args.cpu_limit or args.memory_limit:
        resources.setdefault("limits", {})
        if args.cpu_limit:    resources["limits"]["cpu"]    = args.cpu_limit
        if args.memory_limit: resources["limits"]["memory"] = args.memory_limit
    if resources:
        container["resources"] = resources

    # Probes
    if args.liveness_path and args.liveness_port:
        container["livenessProbe"] = {
            "httpGet": {"path": args.liveness_path, "port": args.liveness_port},
            "initialDelaySeconds": 10, "periodSeconds": 10
        }
    if args.readiness_path and args.readiness_port:
        container["readinessProbe"] = {
            "httpGet": {"path": args.readiness_path, "port": args.readiness_port},
            "initialDelaySeconds": 5, "periodSeconds": 5
        }

    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": args.replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [container]}
            }
        }
    }
    if vols:
        deployment["spec"]["template"]["spec"]["volumes"] = vols

    return deployment

def build_service(parsed: Dict) -> Optional[Dict]:
    if not parsed["ports"]:
        return None
    name = (parsed["name"] or parsed["image"].split("/")[-1]).replace(":", "-")
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": f"{name}-svc"},
        "spec": {
            "selector": {"app": name},
            "ports": [{"port": p, "targetPort": p} for p in parsed["ports"]]
        }
    }

def build_kustomization(parsed: Dict, include_svc: bool) -> Dict:
    name = (parsed["name"] or parsed["image"].split("/")[-1].replace(":", "-"))
    resources = ["deployment.yaml"]
    if include_svc:
        resources.append("service.yaml")
    img, tag = parsed["image"].split(":", 1) if ":" in parsed["image"] else (parsed["image"], "latest")
    return {
        "resources": resources,
        "images": [{"name": img, "newTag": tag}]
    }

def write_yaml(obj: Dict, path: str):
    with open(path, "w") as f:
        yaml.safe_dump(obj, f, sort_keys=False)

def main():
    parser = argparse.ArgumentParser(
        description="Generate a Kustomize overlay from a docker run command",
        epilog="""
Examples:
  # No Service
  krun2kustomize.py \\
    --docker-run "docker run --name myapp -e FOO=bar myimage:1.2" \\
    --output-dir ./kustomize/overlays/dev

  # With Service, resources, probes & auth args
  krun2kustomize.py \\
    --docker-run "docker run -d --name webapp -p 8080:80 -e MODE=prod myimage:latest --auth-token abc123" \\
    --output-dir ./kustomize/overlays/prod \\
    --service --replicas 2 \\
    --cpu-request 100m --cpu-limit 200m \\
    --memory-request 128Mi --memory-limit 256Mi \\
    --liveness-path /healthz --liveness-port 80 \\
    --readiness-path /ready --readiness-port 80
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--docker-run", required=True, help="Quoted docker run command")
    parser.add_argument("--output-dir", required=True, help="Path for kustomize overlay")
    parser.add_argument("--service", action="store_true", help="Generate a Service resource")
    parser.add_argument("--replicas", type=int, default=1)
    parser.add_argument("--cpu-request")
    parser.add_argument("--cpu-limit")
    parser.add_argument("--memory-request")
    parser.add_argument("--memory-limit")
    parser.add_argument("--liveness-path")
    parser.add_argument("--liveness-port", type=int)
    parser.add_argument("--readiness-path")
    parser.add_argument("--readiness-port", type=int)
    args = parser.parse_args()

    parsed = parse_docker_run(args.docker_run)
    os.makedirs(args.output_dir, exist_ok=True)

    # Write Deployment
    dep = build_deployment(parsed, args)
    write_yaml(dep, os.path.join(args.output_dir, "deployment.yaml"))

    # Optionally write Service
    if args.service:
        svc = build_service(parsed)
        if svc:
            write_yaml(svc, os.path.join(args.output_dir, "service.yaml"))

    # Write kustomization.yaml
    kust = build_kustomization(parsed, args.service)
    write_yaml(kust, os.path.join(args.output_dir, "kustomization.yaml"))

    abs_path = os.path.abspath(args.output_dir)
    print(f"[✓] Generated overlay at: {abs_path}")
    print("You can now point ArgoCD (or `kubectl kustomize`) at this directory.")

if __name__ == "__main__":
    main()


"""
./kustomize/overlays/dev/
├── deployment.yaml
├── service.yaml    # if --service
└── kustomization.yaml
