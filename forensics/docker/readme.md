# Docker Forensics – Modern Techniques & Tools

In today's containerized environments, investigating and securing Docker containers is crucial for incident response. 
This guide covers methods to inspect running containers, analyze image modifications, and extract forensic artifacts from container layers. 

It also integrates modern vulnerability scanning and security benchmarking tools.

---

## Container Modification Analysis

When you suspect that a Docker container has been compromised, you can examine modifications relative to its base image.

### 1. List Running Containers

```
docker ps 
CONTAINER ID   IMAGE            COMMAND         CREATED         STATUS         PORTS    NAMES
cc03e43a052a   lamp-wordpress   "./run.sh"      2 minutes ago   Up 2 minutes   80/tcp   wordpress
```
2. Identify Filesystem Changes with docker diff
```
docker diff wordpress
C = Changed
A = Added
D = Deleted

C /var
C /var/lib
A /var/lib/mysql/ib_logfile0
A /etc/shadow
...
3. Extract Files for Offline Analysis
If a critical file (e.g., /etc/shadow) appears modified:
```
docker cp wordpress:/etc/shadow ./shadow_from_container


4. Compare with a Clean Container
Run a fresh container from the same image and extract the same file:

```
docker run -d lamp-wordpress
docker cp <new_container_ID>:/etc/shadow ./original_shadow
diff ./original_shadow ./shadow_from_container
```

5. Interactive Investigation
Enter the container for a live investigation:
```
docker exec -it wordpress bash
```
Image Modification Analysis
When provided with a Docker image (typically exported as a .tar file), you can compare it against known baselines.

1. Inspect Image Metadata

```
docker inspect <image_name>
```

2. Review Image History
```
docker history --no-trunc <image_name>
```
This command shows all layers and modifications. Look for unexpected changes or unusually large layers.

3. Reconstruct the Dockerfile
Generate an approximation of the Dockerfile used to create the image:
```
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 <image_name>
```
4. Use container-diff for Layer Analysis

Install container-diff and run:

```
docker save <image_name> > image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
container-diff analyze -t sizelayer image.tar
```


5. Visual Inspection with Dive
dive lets you explore image layers interactively:

```
# First, load the image into Docker:
docker load < image.tar

# Then, open it with dive:
dive <image_name>
```

Red indicates added files.
Yellow indicates modifications.
Use Tab to switch views and Space to expand/collapse directories.


6. Manual Layer Extraction
Decompress the image and inspect each layer:

```
tar -xf image.tar
for d in $(find . -maxdepth 1 -type d | tail -n +2); do
    cd "$d"
    tar -xf layer.tar
    # Inspect the extracted files as needed
    cd ..
done
```


Advanced Vulnerability Scanning & Hardening
Modern container security involves not only forensic analysis but also vulnerability scanning and compliance checks.

1. Vulnerability Scanning with Trivy
Trivy quickly scans container images:

```
trivy image <image_name>
```

2. Docker Scan (Snyk Integration)
Use Docker's built-in scanning to identify known vulnerabilities:

```
docker scan <image_name>
```


3. Security Benchmarking with Docker Bench & Dockle
Docker Bench for Security: Check your host and container configurations:
```
docker run -it --rm --net host --pid host --cap-add audit_control \
    -v /var/lib/docker/:/var/lib/docker:ro \
    -v /etc:/etc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/run/docker.sock:/var/run/docker.sock \
    docker/docker-bench-security
```

Dockle: Analyze your Docker images against best practices:

```
dockle <image_name>
```

Install Dockle from its GitHub releases if needed.

Memory and Process Forensics
Investigating running processes and memory can reveal credentials and signs of compromise.

1. Dump Process Memory
As root on the host, use gcore to dump memory from a suspicious process:

```
gcore -o /tmp/process_dump <PID>
```

2. Analyze Memory Dumps with Volatility3

```
volatility3 -f /path/to/memdump.raw windows.pslist
```

3. Monitor and Trace Processes
From within the container, run tools like strace or ltrace on processes:

```
docker exec -it wordpress bash
strace -p <PID>
```

Alternatively, use pspy for lightweight, continuous process monitoring:

```
docker run -it --rm --privileged -v /:/host:ro forensic-container
```

# Inside the container, run:
```
pspy
```

Additional Modern Tools and Commands
1. Radare2 for Deep Binary Analysis
Use radare2 via r2pipe to perform advanced binary analysis:
```
python -c "import r2pipe; r2 = r2pipe.open('binary'); print(r2.cmd('aa; afl'))"
```

2. Docker Image Scanning & Hardening Tools
Trivy & Docker Scan: For vulnerability assessments.
Dockle: For checking image best practices.
Docker Bench for Security: For host and container configuration assessments.


4. Automated Layer Analysis
You can script the extraction of image layers and automate searches for suspicious files or modifications:

```
#!/bin/bash
tar -xf image.tar
for d in $(find . -maxdepth 1 -type d | tail -n +2); do
    cd "$d"
    tar -xf layer.tar
    # Search for known suspicious filenames or patterns
    find . -type f | grep -Ei 'shadow|passwd|key'
    cd ..
done
```

# Summary
This guide provides a modern, comprehensive approach to Docker forensics:

Container Modification Analysis:
Use docker diff, docker cp, and docker exec to pinpoint and extract suspicious changes.

Image Analysis:
Leverage docker inspect, docker history, container-diff, and dive to understand layer modifications and metadata.

Advanced Security Scanning:
Integrate tools like Trivy, Docker Scan, Docker Bench, and Dockle to assess vulnerabilities and compliance.

Memory & Process Forensics:
Dump and analyze process memory and monitor running processes to uncover hidden credentials and malicious behavior.

Modern Binary Analysis:
Use radare2 (via r2pipe) and other forensic libraries to inspect binaries and artifacts.


