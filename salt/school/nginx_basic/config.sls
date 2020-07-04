nginx_configuration:
  file.managed:
    - name: /etc/nginx/nginx.conf
    - source: salt://nginx/config/nginx.conf
    - require:
      - pkg: nginx
