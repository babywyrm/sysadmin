include:
  - nginx.epel

install_nginx:
  pkg.installed:
    - name: nginx
  service.running:
    - name: nginx
    - enable: true
