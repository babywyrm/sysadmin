kustomize_vars.md
This was initially posted in an kubernetes-sigs/kustomize issue.

##
#
https://gist.github.com/hermanbanken/3d0f232ffd86236c9f1f198c9452aad9
#
##

We are using Kustomize's vars feature. 
Initially we didn't understand how to use it for our purpose, but it is a 100% fit. One example is our Ingress resource, which looks like this:
```
# file: base/ingress.yaml
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: services
  annotations:
    kubernetes.io/ingress.global-static-ip-name: $(SERVICES_GLOBAL_STATIC_IP_NAME)
    kubernetes.io/ingress.allow-http: "false"
    ingress.gcp.kubernetes.io/pre-shared-cert: $(SERVICES_PRE_SHARED_CERT)
    kubernetes.io/ingress.class: "gce"
spec:
  rules:
  - host: $(HOST_A)
    http:
      paths:
      - backend:
          serviceName: serviceA
          servicePort: 80
  - host: $(HOST_B)
    http:
      paths:
      - backend:
          serviceName: serviceB
          servicePort: 80
  - host: $(HOST_C)
    http:
      paths:
      - backend:
          serviceName: serviceC
          servicePort: 80
```
Then our configMapGenerator / vars looks like this:

```
# file: base/kustomization.yaml
bases:
- ingress.yaml

configMapGenerator:
- name: ops-ingress-properties
  envs: [environment.properties]

vars:
- name: SERVICES_GLOBAL_STATIC_IP_NAME
  objref: { kind: ConfigMap, name: ops-ingress-properties, apiVersion: v1 }
  fieldref: { fieldpath: data.SERVICES_GLOBAL_STATIC_IP_NAME }
- name: SERVICES_PRE_SHARED_CERT
  objref: { kind: ConfigMap, name: ops-ingress-properties, apiVersion: v1 }
  fieldref: { fieldpath: data.SERVICES_PRE_SHARED_CERT }
- name: HOST_A
  objref: { kind: ConfigMap, name: ops-ingress-properties, apiVersion: v1 }
  fieldref: { fieldpath: data.HOST_A }
- name: HOST_B
  objref: { kind: ConfigMap, name: ops-ingress-properties, apiVersion: v1 }
  fieldref: { fieldpath: data.HOST_B }
- name: HOST_C
  objref: { kind: ConfigMap, name: ops-ingress-properties, apiVersion: v1 }
  fieldref: { fieldpath: data.HOST_C }

```

and the properties like this:

```
# file: base/environment.properties

# Ingress annotations
SERVICES_GLOBAL_STATIC_IP_NAME=services
SERVICES_PRE_SHARED_CERT=a-yyyymmdd,b-yyyymmdd,c-yyyymmdd

# Hosts
HOST_A=a.example.org
HOST_B=b.example.org
HOST_C=c.example.org
then in our overlays we redefine the environment.properties file and have this in Kustomization:

# file: overlay/staging/kustomization.yaml
configMapGenerator:
- name: ops-ingress-properties
  envs: [environment.properties]
  behavior: replace # <======= critical
```


which overwrites the values in the base like this:
```
# file: overlay/staging/environment.properties

# Ingress annotations
SERVICES_GLOBAL_STATIC_IP_NAME=services-staging
SERVICES_PRE_SHARED_CERT=a-staging-yyyymmdd,b-staging-yyyymmdd,c-staging-yyyymmdd

# Hosts
HOST_A=a-staging.example.org
HOST_B=b-staging.example.org
HOST_C=c-staging.example.org
```




This works ideal for us! A bit sad that it took us soo long to discover this feature. We really don't want it replaced/removed.

@hermanbanken
Author
hermanbanken commented on Nov 22, 2020
@srknc:
Not sure whether it's scope of this conversation but, following @hermanbanken 's example, it does overwrites values at host section but not the ones under annotations with the error below;
well-defined vars that were never replaced: SERVICES_GLOBAL_STATIC_IP_NAME,SERVICES_PRE_SHARED_CERT

I'm not 100% sure what causes this, but it can be an issue with the version of kustomize. I have

{Version:v3.6.1 GitCommit:a0072a2cf92bf5399565e84c621e1e7c5c1f1094 BuildDate:2020-06-15T20:19:07Z GoOs:darwin GoArch:amd64}
installed.

@jurabek
jurabek commented on Jan 9, 2021
A great example, thanks for sharing

@TrueBrain
TrueBrain commented on Jan 12, 2021 • 
A piece of knowledge that helped me further (credits to @bburky, https://github.com/bburky/kustomize-transformer-environment-variables/blob/master/environment-variables/configuration.yaml):

# file: base/configuration.yaml

varReference:
- path: spec/routes/match
  kind: IngressRoute
- path: spec/loadBalancerIP
  kind: Service
# Add additional entries into `varReference` if you would like substitution to occur anywhere else.

# Default varReference list from Kustomize:
# https://github.com/kubernetes-sigs/kustomize/blob/master/api/konfig/builtinpluginconsts/varreference.go
and an addition for base/kustomization.yaml:

configurations:
- configuration.yaml
That way you can use variables in other paths, just add any you need!

Thank you so much for this gist; people kept telling me to look in text-cases of the go-code .... that was really not helpful :D This is the first place I found that explained how one can use variables .. finally I can abstract my domain-name away, and not copy/paste is 20 times all over the place :) Tnx a lot!

@hermanbanken
Author
hermanbanken commented on Jan 12, 2021
Thanks @TrueBrain 🙏 for your kind words and the addition!

I was surprised by the large list of supported fields: caused my to wonder why they don’t support everything by default... anyway, great to have captured that here. (Not sure about adding it to the general explainer, maybe as a small link to the comment).

@bburky
bburky commented on Jan 12, 2021
Thanks @TrueBrain.

My repo actually demonstrates another useful feature in combination with vars. You can omit values from the .env file to use the current environment variables

I can't find any documentation for this behavior, but it's actually quite useful:
https://github.com/kubernetes-sigs/kustomize/blob/ea5d08bac5afa8921dba3c458f6ef07adf8563e3/api/kv/kv.go#L163-L169

@hermanbanken
Author
hermanbanken commented on Jan 12, 2021 • 
Ah! More goodies 😀 cool. Typical how this is not documented 😅

So

# file: base/environment.properties

# Ingress annotations
SERVICES_GLOBAL_STATIC_IP_NAME=services
SERVICES_PRE_SHARED_CERT=a-yyyymmdd,b-yyyymmdd,c-yyyymmdd

# Hosts
HOST_A=a.example.org
HOST_B=b.example.org
HOST_C
# HOST_C is read from environment
@beatcracker
beatcracker commented on Jan 30, 2021 • 
@hermanbanken , so basically, because one can't directly assign variables in the kustomize, you're using properties file + configMapGenerator to inject custom vars? And this will create unused ops-ingress-properties ConfigMap in the k8s cluster, since it's only needed for kustomize build?

@hermanbanken
Author
hermanbanken commented on Jan 31, 2021
@beatcracker, correct. And indeed that extra ConfigMap gets inserted into k8s.

@beatcracker
beatcracker commented on Jan 31, 2021
@hermanbanken , thanks! I've just recently started to dig in to the kustomize and this was very helpful to understand what can be done with it.

@Shuliyey
Shuliyey commented on May 14, 2021 • 
interesting seems like it's here https://github.com/kubernetes-sigs/kustomize/blob/f61b075d3bd670b7bcd5d58ce13e88a6f25977f2/api/kv/kv.go#L163-L169, but not documented (this is a tricky one to discover)

Ah! More goodies 😀 cool. Typical how this is not documented 😅

So

# file: base/environment.properties

# Ingress annotations
SERVICES_GLOBAL_STATIC_IP_NAME=services
SERVICES_PRE_SHARED_CERT=a-yyyymmdd,b-yyyymmdd,c-yyyymmdd

# Hosts
HOST_A=a.example.org
HOST_B=b.example.org
HOST_C
# HOST_C is read from environment
@bburky
bburky commented on May 16, 2021 • 
By the way, kubernetes-sigs/kustomize#3737 was recently merged (after discussion in kubernetes-sigs/kustomize#3492), which adds a new replacements: field similar to vars:.

It works a bit differently but looks clearer than vars. Not sure if it's in any released version yet or documented.

@hermanbanken
Author
hermanbanken commented on May 16, 2021
Looking at the tests I was afraid for index based replacements. Then I saw:

https://github.com/kubernetes-sigs/kustomize/pull/3737/files#diff-c3d1278453f2a6fb229ec8998df0f109d8605b5e46ba2a84d067083f5a543761R194

  - spec.template.spec.containers.[name=nginx].image
and I was happy 😃

@joebowbeer
joebowbeer commented on Aug 13, 2022
@bburky wrote:

My repo actually demonstrates another useful feature in combination with vars. You can omit values from the .env file to use the current environment variables

I can't find any documentation for this behavior, but it's actually quite useful: https://github.com/kubernetes-sigs/kustomize/blob/ea5d08bac5afa8921dba3c458f6ef07adf8563e3/api/kv/kv.go#L163-L169

This misfeature was finally documented in 2022 but then the documentation was removed eight months later.

@brunzefb
brunzefb commented on Nov 12, 2022 • 
@joebowbeer I just looked at the latest source -- if you leave the values out that it will take the env vars, but give a big fat warning that this will not be supported in future kustomize versions.

@hermanbanken - thanks for providing this solution.
I have a question about all of this. I just tried the technique and it worked just as shown. However, I only need variable replacements and do not require the generated configmap. This shown method also has a lot of moving parts. You must have all of the pieces in the correct positions - it took me a few tries to get this right! Is there no simple mechanism in kustomize that allows variable replacement?  One could keep $(ENV VAR) syntax be used in the base folder yaml, and one would have an environment.properties file in the overlay with ENV=value pairs (exactly as in this sample). The difference would be that kustomize.yaml in the overlay would reference environment.properties without a configmap generator. The base kustomize.yaml would also not have the config map generator. The desired effect is to use the environment variables in the base manifests and have the all instances replaced in all manifests in the base with the values from environment.properties.  Essentially this would just be a glorified search/replace of variables.

Maybe this functionality exists -- if so, please enlighten me.

@joebowbeer
joebowbeer commented on Nov 12, 2022
@brunzefb kustomize is designed to not support this:

https://kubectl.docs.kubernetes.io/faq/kustomize/eschewedfeatures/#build-time-side-effects-from-cli-args-or-env-variables

History of a misfeature: https://rm3l.org/using-system-envvars-with-kustomize/

@brunzefb
brunzefb commented on Nov 12, 2022
@jowbowbeer -- thanks for the eschewedfeatures link, which explains the reasoning. Makes sense. The article says that one of the bad things about unstructured parameterization and I quote "The source yaml gets polluted with $VARs and can no longed be applied as is to the cluster (it must be processed)." On the surface, it looks like the technique is doing that -- of course the base/kustomization.yaml explicity references the configmap with an objectref and fieldref to populate the values from. Overall, the technique presented here is still conceptually fairly difficult to grasp -- and I don't like the fact that I end up with a configmap that I don't need -- its just an artifact used in the env var replacements.

@brunzefb
brunzefb commented on Nov 16, 2022 • 
I have written a blog post that gives an example of all of these techniques. Find it here

@trandersen-ufst
trandersen-ufst commented on Jun 11
I have written a blog post that gives an example of all of these techniques. Find it here

@brunzefb Looks like your blog is down. Do you have a working link?

@brunzefb
brunzefb commented on Jun 12 via email 

https://blog.brunzema.com should be up.
I had some electrical work done, so it was down.  Server now on a UPS.

Best,
F
…
@brunzefb
brunzefb commented on Jun 12 via email 
here is the new server link
https://blog.brunzema.com/2022/11/15/a-kustomize-journey/
…
