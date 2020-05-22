  
{% from "wordpress/map.jinja" import map with context %}
# This downloads and installs WP-Cli
/usr/local/bin/wp:
  file.managed:
    - source: {{ salt['pillar.get']('wordpress:cli:source') }}
    - source_hash: {{ salt['pillar.get']('wordpress:cli:hash') }}
    - user: {{ map.www_user }}
    - group: {{ map.www_group }}
    - mode: 740
