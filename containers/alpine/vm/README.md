# Node VM Sandbox Archive

This directory preserves Node sandbox and Podman networking research.

`package.legacy.json` includes old sandbox dependencies, including `vm2`, and is
kept as archive material rather than a maintained runtime. The Dockerfile copies
it to `package.json` inside the image only when intentionally reproducing the
old setup.

Do not use this as a security boundary or deploy it to a shared environment
without redesigning the sandbox.
