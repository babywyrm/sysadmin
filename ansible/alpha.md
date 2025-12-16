
# Ansible in 2025 — Production-Grade Guide .. (beta edition) ..

This guide assumes:

* **Ansible ≥ 9.x**
* **Python ≥ 3.10**
* SSH key-based auth
* YAML-first, idempotent, linted playbooks
* Inventory, roles, collections, and security baked in

---

## 1. Installation (2025-Safe)

### macOS

```bash
brew install ansible
ansible --version
```

### Linux (pipx preferred)

```bash
pipx install ansible
pipx ensurepath
```

> ✅ **Why pipx?**
> Isolated environments, no system-Python pollution (critical in 2025).

---

## 2. Project Layout (Modern Standard)

```text
setup/
├── ansible.cfg
├── inventory/
│   ├── production/
│   │   ├── hosts.yml
│   │   └── group_vars/
│   │       └── web.yml
│   └── lab/
│       └── hosts.yml
├── playbooks/
│   └── site.yml
├── roles/
│   └── nginx/
│       ├── tasks/
│       │   └── main.yml
│       ├── handlers/
│       │   └── main.yml
│       ├── templates/
│       │   └── nginx.conf.j2
│       ├── defaults/
│       │   └── main.yml
│       └── meta/
│           └── main.yml
├── collections/
├── requirements.yml
└── vault/
    └── secrets.yml
```

This is **table-stakes** in 2025.

---

## 3. ansible.cfg (Critical)

```ini
[defaults]
inventory = inventory
roles_path = roles
collections_paths = collections
host_key_checking = False
retry_files_enabled = False
interpreter_python = auto_silent
stdout_callback = yaml
bin_ansible_callbacks = True

[ssh_connection]
pipelining = True
```

---

## 4. Inventory (YAML, Not INI)

### `inventory/lab/hosts.yml`

```yaml
all:
  children:
    web:
      hosts:
        127.0.0.1:
        192.168.0.1:
    db:
      hosts:
        192.168.0.2:
```

---

## 5. Group Variables (Environment-Aware)

### `inventory/lab/group_vars/web.yml`

```yaml
nginx_package: nginx
nginx_port: 80
```

---

## 6. Secrets (Ansible Vault)

```bash
ansible-vault create vault/secrets.yml
```

```yaml
vault_nginx_basic_auth_password: supersecret
```

Use it safely:

```yaml
vars_files:
  - vault/secrets.yml
```

---

## 7. Roles (The Only Acceptable Way)

### `roles/nginx/tasks/main.yml`

```yaml
- name: Install nginx
  ansible.builtin.package:
    name: "{{ nginx_package }}"
    state: present

- name: Deploy nginx config
  ansible.builtin.template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
    mode: "0644"
  notify: restart nginx

- name: Ensure nginx running
  ansible.builtin.service:
    name: nginx
    state: started
    enabled: true
```

---

### `roles/nginx/handlers/main.yml`

```yaml
- name: restart nginx
  ansible.builtin.service:
    name: nginx
    state: restarted
```

---

## 8. Templates (Jinja2)

### `roles/nginx/templates/nginx.conf.j2`

```nginx
server {
    listen {{ nginx_port }};
    location / {
        return 200 "Hello from {{ inventory_hostname }}\n";
    }
}
```

---

## 9. Playbook (site.yml)

```yaml
- name: Configure web servers
  hosts: web
  become: true
  gather_facts: true

  roles:
    - nginx
```

---

## 10. Execution (Safe Defaults)

```bash
ansible-playbook \
  -i inventory/lab/hosts.yml \
  playbooks/site.yml \
  --check \
  --diff
```

Then deploy for real:

```bash
ansible-playbook -i inventory/lab/hosts.yml playbooks/site.yml
```

---

## 11. Collections (2025 Reality)

### `requirements.yml`

```yaml
collections:
  - name: ansible.posix
  - name: community.general
  - name: community.crypto
```

Install:

```bash
ansible-galaxy collection install -r requirements.yml
```

---

## 12. Security Hardening (Modern)

### SSH

```yaml
ansible_user: deploy
ansible_ssh_private_key_file: ~/.ssh/id_ed25519
ansible_ssh_common_args: "-o StrictHostKeyChecking=no"
```

### Avoid shell when possible

❌ Bad:

```yaml
shell: echo hello > /tmp/abc.txt
```

✅ Good:

```yaml
copy:
  content: "hello\n"
  dest: /tmp/abc.txt
  mode: "0644"
```

---

## 13. Idempotency Rules (Non-Negotiable)

| Rule                          | Reason             |
| ----------------------------- | ------------------ |
| No `shell` unless unavoidable | Breaks idempotency |
| Always use handlers           | Avoid restarts     |
| Variables > hardcoded         | Reusability        |
| `--check` must pass           | CI/CD safety       |

---

## 14. CI/CD Integration (2025 Standard)

### ansible-lint

```bash
pipx install ansible-lint
ansible-lint
```

### GitHub Actions (Example)

```yaml
- name: Lint Ansible
  run: ansible-lint
```

---

## 15. Ansible vs Terraform vs Kubernetes (Reality)

| Tool      | Purpose         |
| --------- | --------------- |
| Ansible   | OS & app config |
| Terraform | Infrastructure  |
| Helm      | Kubernetes apps |
| ArgoCD    | GitOps          |

**Ansible still wins** for:

* Bare metal
* VM hardening
* Day-2 ops
* Incident response
* CTF infra setup 😉

---

##
##
