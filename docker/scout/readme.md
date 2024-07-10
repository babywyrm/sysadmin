# Docker Scout CLI notes

**1. Analyze local files**
- _Get an at-a-glance vulnerability summary of the source code in the current working directory_

  ```
  docker scout quickview fs://.
  ```

- _View the details of vulnerabilities found in your local source code_

  ```
  docker scout cves --details --only-severity high fs://.
  ```

- _Compare the analysis of source code on your local filesystem with the analysis of a container image_

  ```
  docker scout compare fs://. --to docker/scout-cli:latest --ignore-unchanged
  ```
  
  For example,
  
  ```
  # Compare 2 alpine images
  docker scout compare --to alpine:latest alpine:3.12
  
  # Compare an image to the latest tag
  docker scout compare --to namespace/repo:latest namespace/repo:v1.2.0-pre

  # Ignore base images
  docker scout compare --ignore-base --to namespace/repo:latest namespace/repo:v1.2.0-pre

  # Generate a markdown output
  docker scout compare --format markdown --to namespace/repo:latest namespace/repo:v1.2.0-pre

  # Compare maven packages only and display critical vulnerabilities in them
  docker scout compare --only-package-type maven --only-severity critical --to namespace/repo:latest namespace/repo:v1.2.0-pre
  ```

**2. Compare two images and displays the differences**

```
docker scout compare
```

**3. Display the CVEs identified for any software artifacts in the image**

```
docker scout cves
```

For example,

```
docker scout cves nginx:latest
```

**4. Display a quick overview of an image**
  
```
docker scout quickview
```

For example,

```
docker scout quickview nginx:latest
```

**5. Display all available base image updates and remediation recommendations.**

```
docker scout recommendations
```

For example,

```
docker scout recommendations nginx:latest
```
