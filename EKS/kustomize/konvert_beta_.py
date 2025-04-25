#!/usr/bin/env python3
import os
import shlex
import argparse
import itertools
import yaml
from typing import Dict, List, Optional

def parse_docker_run(cmd: str) -> Dict:
    """
    Parse a 'docker run ...' string into its components.
    Known docker flags are mapped to env/ports/volumes/name.
    Any other flags (e.g. auth flags) are captured as container args.
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

        # Container name
        if tok == "--name":
            info["name"] = next(it)

        # Environment variables
        elif tok in ("-e", "--env"):
            kv = next(it)
            k, v = kv.split("=", 1)
            info["env"].append({"name": k, "value": v})

        # Port mappings
        elif tok in ("-p", "--publish"):
            mapping = next(it)
            _, ctr = mapping.split(":", 1)
            info["ports"].append(int(ctr))

        # Volume mounts
        elif tok in ("-v", "--volume"):
            mapping = next(it)
            host, ctr = mapping.split(":", 1)
            info["volumes"].append({"hostPath": host, "mountPath": ctr})

        # Unknown flags → send to container args
        elif tok.startswith("-"):
            # handle --flag=value case
            info["args"].append(tok)
            if "=" not in tok:
                # maybe the value is the next token
                try:
                    nxt = next(it)
                    if not nxt.startswith("-"):
                        info["args"].append(nxt)
                    else:
                        # push it back
                        it = itertools.chain([nxt], it)
                except StopIteration:
                    pass

        # Image and trailing command/args
        else:
            if info["image"] is None:
                info["image"] = tok
            else:
                info["args"].append(tok)

    return info


def build_deployment(parsed, args) -> Dict:
    name = parsed["name"] or parsed["image"].split("/")[-1].replace(":", "-")
    container: Dict = {
        "name": name,
        "image": parsed["image"],
    }
    if parsed["args"]:
        container["args"] = parsed["args"]
    if parsed["env"]:
        container["env"] = parsed["env"]
    if parsed["ports"]:
        container["ports"] = [{"containerPort": p} for p in parsed["ports"]]

    # Volumes
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


def build_service(parsed) -> Optional[Dict]:
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


def build_kustomization(parsed, include_svc) -> Dict:
    name = (parsed["name"] or parsed["image"].split("/")[-1].replace(":", "-"))
    resources = ["deployment.yaml"]
    if include_svc:
        resources.append("service.yaml")
    img, tag = (parsed["image"].split(":", 1) if ":" in parsed["image"]
                else (parsed["image"], "latest"))
    return {
        "resources": resources,
        "images": [{"name": img, "newTag": tag}]
    }


def write_yaml(obj: Dict, path: str):
    with open(path, "w") as f:
        yaml.safe_dump(obj, f, sort_keys=False)


def main():
    p = argparse.ArgumentParser(
        description="Generate Kustomize YAML from a docker run syntax"
    )
    p.add_argument("--docker-run", required=True, help="Quoted docker run command")
    p.add_argument("--output-dir", required=True, help="e.g. ./kustomize/overlays/dev")
    p.add_argument("--service", action="store_true", help="Also generate Service.yaml")
    p.add_argument("--replicas", type=int, default=1)
    p.add_argument("--cpu-request")
    p.add_argument("--cpu-limit")
    p.add_argument("--memory-request")
    p.add_argument("--memory-limit")
    p.add_argument("--liveness-path")
    p.add_argument("--liveness-port", type=int)
    p.add_argument("--readiness-path")
    p.add_argument("--readiness-port", type=int)
    args = p.parse_args()

    parsed = parse_docker_run(args.docker_run)
    os.makedirs(args.output_dir, exist_ok=True)

    dep = build_deployment(parsed, args)
    write_yaml(dep, os.path.join(args.output_dir, "deployment.yaml"))

    if args.service:
        svc = build_service(parsed)
        if svc:
            write_yaml(svc, os.path.join(args.output_dir, "service.yaml"))

    kust = build_kustomization(parsed, args.service)
    write_yaml(kust, os.path.join(args.output_dir, "kustomization.yaml"))

    print(f"[✓] Generated files in {args.output_dir}")

if __name__ == "__main__":
    main()
