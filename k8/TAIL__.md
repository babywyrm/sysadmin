

# 📘 Kubernetes Log Tailing Cheat Sheet (Power User Edition)

## 🔧 `stern` Commands

| Description                                                     | Command                                     |              |
| --------------------------------------------------------------- | ------------------------------------------- | ------------ |
| Tail logs from pods with name prefix `web-` in `prod` namespace | `stern -n prod 'web-*'`                     |              |
| Tail logs across all namespaces                                 | `stern --all-namespaces '.*'`               |              |
| Tail logs for multiple containers                               | `stern podname -c container1 -c container2` |              |
| Tail logs by label                                              | `stern -l app=nginx`                        |              |
| Tail logs using specific kubeconfig                             | `stern -k ~/.kube/dev-config -n dev '.*'`   |              |
| Filter log output for `error`                                   | \`stern '.\*'                               | grep error\` |
| Disable colored output                                          | `stern --no-color '.*'`                     |              |
| Regex filter pod/container names                                | `stern '^nginx-[a-z0-9]+$'`                 |              |
| Tail JSON logs with jq filtering                                | \`stern '.\*'                               | jq -c\`      |

---

## 🔥 `kail` Commands

| Description                             | Command                  |              |         |
| --------------------------------------- | ------------------------ | ------------ | ------- |
| Tail logs for pods with label `app=web` | `kail -l app=web`        |              |         |
| Tail logs for a specific namespace      | `kail -n prod`           |              |         |
| Tail logs for a specific deployment     | `kail -d web-api`        |              |         |
| Tail logs for a specific pod            | `kail -p web-api-57df5d` |              |         |
| Tail logs from all namespaces           | `kail --ns '.*'`         |              |         |
| Include container name in output        | `kail -c`                |              |         |
| Disable colored output                  | `kail --nocolor`         |              |         |
| Filter logs for errors/warnings         | \`kail -l app=foo        | egrep 'ERROR | WARN'\` |

---

## 🧱 `kubectl logs` Equivalents

| Description                                   | Command                                                          |                                 |
| --------------------------------------------- | ---------------------------------------------------------------- | ------------------------------- |
| Tail logs for a specific pod                  | `kubectl logs podname -f`                                        |                                 |
| Tail logs for a container                     | `kubectl logs podname -c container1 -f`                          |                                 |
| Tail logs with label selector                 | `kubectl logs -l app=nginx -f`                                   |                                 |
| Tail logs across all namespaces (manual loop) | \`kubectl get pods --all-namespaces -o name                      | xargs -I{} kubectl logs -f {}\` |
| Tail logs with grep filtering                 | \`kubectl logs podname                                           | grep error\`                    |
| Specify kubeconfig                            | `kubectl --kubeconfig ~/.kube/dev-config logs -n dev podname -f` |                                 |

---

## ⚙️ Advanced Usage & Tips

* Use **regex filters** with `stern` and `kail` for precise control over pod/container names.
* Combine with **`grep`, `jq`, or `fzf`** for interactive filtering or structured log parsing.
* For **ephemeral pods or CI/CD**: use `kail` for auto-reattachment.
* For **debugging a crashloop**:

  ```bash
  stern -n dev 'crashing-pod' --container crashy --timestamps
  ```

---

## 🚀 Tool Selection Guide

| Use Case                  | Recommended Tool                      |
| ------------------------- | ------------------------------------- |
| Dev/debug single service  | `stern`                               |
| Dynamic/multi-pod tailing | `kail`                                |
| Basic logs from one pod   | `kubectl logs`                        |
| Historical/log search     | Centralized logging (Loki, EFK, etc.) |


