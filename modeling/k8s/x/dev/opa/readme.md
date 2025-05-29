# OPA / Gatekeeper Admission Policies / 
 
 ## ( Proposed )

Project-X uses OPA Gatekeeper to enforce admission control on all challenge workloads:

1. Only container images from the designated per-tier registries are admitted  
2. Only images signed with Cosign are admitted  
3. Per-tier resource quotas and max concurrent challenge limits are enforced  

## Directory Layout, Tbh

config/opa/
├── templates/
│   ├── signed-images-template.yaml        # ConstraintTemplate for image whitelist & signature
│   └── resource-limits-template.yaml      # ConstraintTemplate for tier resource limits
└── constraints/
    ├── signed-images.yaml                # Instantiates SignedImagesOnly
    └── resource-limits.yaml              # Instantiates ProjectXResourceLimits


##
##


## Constraint Templates

### templates/signed-images-template.yaml

Defines a `SignedImagesOnly` CRD that checks for:

- `allowedRegistries` (list of image path prefixes)  
- `cosignPublicKey` (public key to verify image signatures)  

At admission time it rejects any Pod whose container image:

- Does not start with one of the allowed registries  
- Lacks a valid Cosign signature  

### templates/resource-limits-template.yaml

Defines a `ProjectXResourceLimits` CRD that enforces per-tier:

- `maxChallenges` (max concurrent Pods per user)  
- `maxCPU` / `maxMemory` (hard resource limits)  

It counts existing Pods labeled with a user’s ID and tier and rejects new ones beyond `maxChallenges`.

## Constraints

### constraints/signed-images.yaml

```yaml
apiVersion: config.gatekeeper.sh/v1alpha1
kind: SignedImagesOnly
metadata:
  name: projectx-signed-images
spec:
  allowedRegistries:
    - "registry-tier1.project-x.local/ctf/tier1"
    - "registry-tier2.project-x.local/ctf/tier2"
    - "registry-tier3.project-x.local/ctf/tier3"
  cosignPublicKey: |
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
    -----END PUBLIC KEY-----
```

### constraints/resource-limits.yaml

```yaml
apiVersion: config.gatekeeper.sh/v1alpha1
kind: ProjectXResourceLimits
metadata:
  name: projectx-tier-limits
spec:
  tierLimits:
    tier-1:
      maxChallenges: 3
      maxCPU: "500m"
      maxMemory: "1Gi"
    tier-2:
      maxChallenges: 5
      maxCPU: "1000m"
      maxMemory: "2Gi"
    tier-3:
      maxChallenges: 10
      maxCPU: "2000m"
      maxMemory: "4Gi"
```

## How It Works, Probably, (Hopefully)

1. **Frontend** obtains a JWT from Ambassador Auth gateway:
   - JWT includes claims: `user_id`, `tier`
2. **Frontend** calls `/api/challenges` on the Challenge Controller with  
   `Authorization: Bearer <JWT>`.
3. **Controller**:
   - Parses the JWT, extracts `user_id` and `tier`
   - Selects the correct image registry prefix (`cfg.ImageRegistryPerTier[tier]`)
   - Creates a `Deployment` with labels:
     - `project-x/user-id: "<user_id>"`
     - `project-x/tier: "<tier>"`
     - `project-x/challenge-id: "<uuid>"`
   - Creates a `Service`, registers a SPIRE entry, and applies Istio CRDs
4. **Kubernetes** invokes Gatekeeper webhooks:
   - **SignedImagesOnly** checks the Deployment’s `spec.containers[].image`
     - must start with one of `allowedRegistries`
     - must have a valid Cosign signature
   - **ProjectXResourceLimits** checks active Pods:
     - counts Pods labeled with the same `user-id` & `tier`
     - rejects if count ≥ `maxChallenges`
5. If both policies pass, the Deployment is admitted and Pods start.  
   Otherwise the API call fails with an admission error.

## Signing & Pushing Images

In your CI/CD pipeline, for each challenge image:

```bash
# 1. Build the image
docker build -t registry-tier2.project-x.local/ctf/tier2/web-challenge:latest .

# 2. Scan for vulnerabilities
trivy image --severity HIGH,CRITICAL registry-tier2.project-x.local/ctf/tier2/web-challenge:latest

# 3. Sign with Cosign
cosign sign --key cosign.key registry-tier2.project-x.local/ctf/tier2/web-challenge:latest

# 4. Push to your private registry
docker push registry-tier2.project-x.local/ctf/tier2/web-challenge:latest
```

Gatekeeper will verify the signature at admission.

## Deploying Gatekeeper Policies

```bash
# 1. Install Gatekeeper once:
helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system

# 2. Apply ConstraintTemplates:
kubectl apply -f config/opa/templates/

# 3. Apply Constraints:
kubectl apply -f config/opa/constraints/
```

## Updating Policies

- **Add a new registry**: edit `constraints/signed-images.yaml → allowedRegistries`, re-apply  
- **Adjust tier limits**: edit `constraints/resource-limits.yaml`, re-apply  
- **Rotate Cosign key**: update `cosignPublicKey` in signed-images constraint, re-apply  

With these admission controls in place, only authorized, signed, tier-approved images ever run in your cluster, and each user cannot exceed their concurrency limits.
