# Kustomize plugins

##
#
https://gist.githubusercontent.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897/raw/d22569e9cbb906e2099f57d385ead2266409ea04/README.md
#
##

> The following examples illustrate how Kustomize plugins work.

# Summary

The following examples illustrate how Kustomize plugins work--that is, illustrate [_Kustomize Kubernetes Resource Model (KRM) Functions Specification_](https://github.com/kubernetes-sigs/kustomize/blob/master/cmd/config/docs/api-conventions/functions-spec.md) with the following examples:

1. [Example 1 - exec - Do nothing](#example-1---exec---do-nothing)
1. [Example 2 - exec - Log something](#example-2---exec---log-something)
1. [Example 3 - container - Do nothing](#example-3---container---do-nothing)
1. [Example 4 - container - Reach ✨The Internet✨](#example-4---container---reach-the-internet)


**Jargon note:** Kubernetes Resource Model means _Kubernetes data model_. 
For an explanation about the Kubernetes Resource Model (KRM) jargon term, see 
[_Kubernetes Resource Model (KRM)_](https://github.com/kubernetes/design-proposals-archive/blob/main/architecture/resource-management.md) page.

# Setup

The following examples depend on the `kustomize` standalone command. To install `kustomize` on macOS, run the `brew install kustomize` command. To follow Kustomize plugin graduation--that is, to figure out if plugins are out of Alpha status and merged into `kubectl`, see [_Kustomize Plugin Graduation #2953_](https://github.com/kubernetes/enhancements/issues/2953) issue.

# Example 1 - exec - Do nothing

The following example runs a _do-nothing_ DoNothing Kustomize exec plugin that does nothing (I guess it's not _nothing_, you copy stdin to stdout (it's _cat_)).

1. To experiment, create to a temporary directory--good for quick experiments and aligns with how Kustomize documentation tends to illustrate examples.

   ```
   DEMO=$(mktemp -d)
   ```

1. Create a kustomization.yaml file that reaches the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist--also a kustomization. Also create _do-nothing_ DoNothing Kustomize exec plugin.

   ```
   cat <<'KUSTOMIZATION' >${DEMO}/kustomization.yaml
   resources:
     - https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897
   transformers:
     - |
       kind: DoNothing
       apiVersion: maxhax.net/v1apha1
       metadata:
         name: do-nothing
         annotations:
           config.kubernetes.io/function: |
             exec:
               path: cat
   KUSTOMIZATION
   ```

   **Jargon note:** The term _kustomization_ means: a directory with Kubernetes YAML files and a kustomization.yaml file that bundles and manipulates those Kubernetes YAML files. There is probably a more precise definition; but if you're totally bewildered by that _kustomization_ term, then you can probably do worse than this explanation. For more details, see [_kustomization_](https://kubectl.docs.kubernetes.io/references/kustomize/glossary/#kustomization) Kustomize glossary definition.

1. Run `kustomize` command that runs your _do-nothing_ DoNothing Kustomize exec plugin that doesn't do anything.

   ```
   kustomize build --enable-alpha-plugins --enable-exec $DEMO
   ```
   Your output should look like the following:
   ```
   $ kustomize build --enable-alpha-plugins --enable-exec $DEMO
   apiVersion: v1
   data:
     HELLO: world
   kind: ConfigMap
   metadata:
     name: hello
   ```
   Consider the following:
   1. You just ran your first Kustomize exec plugin--congratulations!
   1. **Observation:** Notice that _do-nothing_ DoNothing Kustomize exec plugin that didn't do much--just passed stdin to stdout. And your command printed the _hello_ ConfigMap in the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist to stdout--expected result.
   1. **Observation:** Notice that to run Kustomize exec plugins, you need those `--enable-alpha-plugins` and `--enable-exec` options. Gotcha: When you run _container_ Kustomize plugins, you don't need that `--enable-exec` option.

# Example 2 - exec - Log something

The following example runs a _log-something_ LogSomething Kustomize exec plugin that logs the input that your _log-something_ plugin gets from Kustomize on stdin to stderr--usual excellent Unix convention--and also copies stdin to stdout (it's _tee_).

1. Create to a temporary directory.

   ```
   DEMO=$(mktemp -d)
   ```

1. Create a log-something.sh script that runs _`tee`_ command.

   ```
   cat <<'SCRIPT' >${DEMO}/log-something.sh && chmod +x ${DEMO}/log-something.sh
   #!/usr/bin/env bash
   # Script log-something.sh print stdin to stderr and stdout--it's tee.
   tee /dev/stderr
   SCRIPT
   ```
   **Gotcha:** Run that log-something.sh script instead of `{"path":"tee","args":["/dev/stderr"]}` because you can only use that path field and you can't pass args to your exec plugin, see https://github.com/kubernetes-sigs/kustomize/blob/878cda7c55aa20903cc3c6d9f85380ccb0b66d5e/kyaml/fn/runtime/runtimeutil/functiontypes.go#L142-L144 code segment.

1. Create a kustomization.yaml file that reaches the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist--also a kustomization. Also create _log-something_ LogSomething Kustomize exec plugin.

   ```
   cat <<'KUSTOMIZATION' >${DEMO}/kustomization.yaml
   resources:
     - https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897
   transformers:
     - |
       kind: LogSomething
       apiVersion: maxhax.net/v1apha1
       metadata:
         name: log-something
         annotations:
           config.kubernetes.io/function: |
             exec:
               path: ./log-something.sh
               # path: tee
               # args: ["/dev/stderr"] # Gotcha: Run that log-something.sh script instead of `{"path":"tee","args":["/dev/stderr"]}` because you can only use that path field and you can't pass args to your exec plugin, see https://github.com/kubernetes-sigs/kustomize/blob/878cda7c55aa20903cc3c6d9f85380ccb0b66d5e/kyaml/fn/runtime/runtimeutil/functiontypes.go#L142-L144 code segment.
   KUSTOMIZATION
   ```

1. Run `kustomize` command that runs your _log-something_ LogSomething Kustomize exec plugin that copies stdin to stderr and stdout.

   ```
   kustomize build --enable-alpha-plugins --enable-exec $DEMO
   ```
   Your output should look like the following:
   ```
   $ kustomize build --enable-alpha-plugins --enable-exec $DEMO
   apiVersion: config.kubernetes.io/v1
   kind: ResourceList
   items:
   - apiVersion: v1
     data:
       HELLO: world
     kind: ConfigMap
     metadata:
       annotations:
         kustomize.config.k8s.io/id: |
           kind: ConfigMap
           name: hello
           version: v1
         config.kubernetes.io/index: '0'
         internal.config.kubernetes.io/index: '0'
         internal.config.kubernetes.io/annotations-migration-resource-id: '0'
         internal.config.kubernetes.io/id: '1'
         config.k8s.io/id: '1'
       name: hello
   functionConfig:
     apiVersion: maxhax.net/v1apha1
     kind: DoNothing
     metadata:
       annotations:
         config.kubernetes.io/function: |
           exec:
             path: ./log-something.sh
             # path: tee
             # args: ["/dev/stderr"] # Gotcha: Run that log-something.sh script instead of `{"path":"tee","args":["/dev/stderr"]}` because you can only use that path field and you can't pass args to your exec plugin, see https://github.com/kubernetes-sigs/kustomize/blob/878cda7c55aa20903cc3c6d9f85380ccb0b66d5e/kyaml/fn/runtime/runtimeutil/functiontypes.go#L142-L144 code segment.
         config.kubernetes.io/local-config: 'true'
       name: do-nothing
   apiVersion: v1
   data:
     HELLO: world
   kind: ConfigMap
   metadata:
     name: hello
   ```
   Consider the following:
   1. You printed a concrete example of the [_Kustomize plugin message schema_](https://github.com/kubernetes-sigs/kustomize/blob/878cda7c55aa20903cc3c6d9f85380ccb0b66d5e/cmd/config/docs/api-conventions/functions-spec.md?plain=1#L74-L77) to stderr--so you can see!
   1. **Observation:** Notice that _log-something_ LogSomething Kustomize exec plugin also still printed the _hello_ ConfigMap in the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist to stdout--expected result.

# Example 3 - container - Do nothing

The following example runs a _do-nothing_ DoNothing Kustomize container plugin that does nothing (I guess it's not _nothing_, you copy stdin to stdout (it's _cat_)). Also runs a _do-nothing_ Docker container from the local _do-nothing:latest_ Docker image--it's a container Kustomize plugin.

1. Create to a temporary directory.

   ```
   DEMO=$(mktemp -d)
   ```

1. Create a _do-nothing:latest_ Docker image.

   ```
   cat <<'DOCKERFILE' | docker build -t do-nothing:latest -f - $DEMO
   FROM debian:stable
   ENTRYPOINT ["/usr/bin/env", "cat"]
   DOCKERFILE
   ```

1. Create a kustomization.yaml file that reaches the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist--also a kustomization. Also create _do-nothing_ DoNothing Kustomize container plugin.

   ```
   cat <<'KUSTOMIZATION' >${DEMO}/kustomization.yaml
   resources:
     - https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897
   transformers:
     - |
       kind: DoNothing
       apiVersion: maxhax.net/v1apha1
       metadata:
         name: do-nothing
         annotations:
           config.kubernetes.io/function: |
             container:
               image: do-nothing:latest
             # exec:
             #   path: cat
   KUSTOMIZATION
   ```

1. Run `kustomize` command that runs your _do-nothing_ DoNothing Kustomize container plugin.

   ```
   kustomize build --enable-alpha-plugins $DEMO
   ```
   Your output should look like the following:
   ```
   $ kustomize build --enable-alpha-plugins $DEMO
   apiVersion: v1
   data:
     HELLO: world
   kind: ConfigMap
   metadata:
     name: hello
   ```
   Consider the following:
   1. You just ran your first Kustomize container plugin--congratulations!
   1. **Observation:** Notice that _do-nothing_ DoNothing Kustomize container plugin that didn't do much--just passed stdin to stdout. And your command printed the _hello_ ConfigMap in the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist to stdout--expected result.
   1. **Observation:** Notice that to run Kustomize container plugins, you need that `--enable-alpha-plugins` option (but not the `--enable-exec` option).

# Example 4 - container - Reach ✨The Internet✨

The following example runs a _hello-world_ HelloWorld Kustomize container plugin that reaches ✨The Internet✨.

1. Create to a temporary directory.

   ```
   DEMO=$(mktemp -d)
   ```

1. Create a _hello-world:latest_ Docker image--reaches ✨The Internet✨ with _`curl`_ command, manipulates YAML with _`yq`_ command.

   ```
   cat <<'DOCKERFILE' | docker build -t hello-world:latest -f - $DEMO
   # syntax=docker/dockerfile:1.3-labs
   FROM mikefarah/yq AS yq
   FROM debian:stable
   COPY --from=yq /usr/bin/yq /usr/local/bin/yq
   RUN apt update && apt install -y curl
   COPY <<'SCRIPT' /hello-world.sh
   #!/usr/bin/env bash
   # Script hello-world.sh reaches ✨The Internet✨ and also manipulates Kubernetes YAML--it's a Kustomize plugin.
   myip=$(curl -sSL https://checkip.amazonaws.com) \
   yq '.items[]
   |= with(select(.kind == "ConfigMap" and .metadata.name == "hello");
   .metadata.annotations.myip = strenv(myip))'
   SCRIPT
   RUN chmod +x /hello-world.sh
   ENTRYPOINT ["/hello-world.sh"]
   DOCKERFILE
   ```

1. Create a kustomization.yaml file that reaches the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist--also a kustomization. Also create _hello-world_ HelloWorld Kustomize container plugin.

   ```
   cat <<'KUSTOMIZATION' >${DEMO}/kustomization.yaml
   resources:
     - https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897
   transformers:
     - |
       kind: DoNothing
       apiVersion: maxhax.net/v1apha1
       metadata:
         name: do-nothing
         annotations:
           config.kubernetes.io/function: |
             container:
               image: hello-world:latest
               network: true
             # container:
             #   image: do-nothing:latest
             # exec:
             #   path: cat
   KUSTOMIZATION
   ```
   **Obsevation:** Notice that to reach the network, you set that `"config.kubernetes.io/function".container.network = true` option.

1. Run `kustomize` command that runs your _hello-world_ HelloWorld Kustomize container plugin.

   ```
   kustomize build --enable-alpha-plugins --network $DEMO
   ```
   Your output should look like the following:
   ```
   $ kustomize build --enable-alpha-plugins --network $DEMO
   apiVersion: v1
   data:
     HELLO: world
   kind: ConfigMap
   metadata:
     annotations:
       myip: 35.247.30.15
     name: hello
   ```
   Consider the following:
   1. **Observation:** Notice that _hello-world_ HelloWorld Kustomize container plugin added that `myip = "YOURIP"` Kubernetes annotation and printed the _hello_ ConfigMap in the https://gist.github.com/mbigras/24b9d8c97a43a81d650c67a0d08f1897 public gist to stdout--expected result.
   1. **Gotcha:** Notice that to reach the network, you set that `"config.kubernetes.io/function".container.network = true` option and you also set the `--network` `kustomize` command option.

# Conclusion

You can run Kustomize exec and container plugins. Kustomize exec plugins run a host command. Kustomize container plugins run a Docker container. Experiment with examples to learn and identify gotchas. After you get the hang of how Kustomize plugins work, then consider the [_Kustomize Kubernetes Resource Model (KRM) Functions Specification_](https://github.com/kubernetes-sigs/kustomize/blob/master/cmd/config/docs/api-conventions/functions-spec.md) to understand the precise Kustomize plugin input/output schema.
