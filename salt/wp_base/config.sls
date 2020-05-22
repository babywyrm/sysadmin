{% from "wordpress/map.jinja" import map with context %}
{% from "wordpress/cli-allow-root.sls" import allowroot with context %}
{% for name, site in pillar['wordpress']['sites'].items() %}
{% if 'dbhost' in site %}
{% set dbhost = site.dbhost %}
{% else %}
{% set dbhost = 'localhost' %}
{% endif %}
# This command tells wp-cli to create our wp-config.php, DB info needs to be the same as above
configure-{{ name }}:
 cmd.run:
  - name: '/usr/local/bin/wp core config {{ allowroot }} --dbhost={{ dbhost }} --dbname={{ site.database }} --dbuser={{ site.dbuser }} --dbpass={{ site.dbpass }}'
  - cwd: {{ map.docroot }}/{{ name }}
  - runas: {{ map.www_user }}
  - unless: test -f {{ map.docroot }}/{{ name }}/wp-config.php
{% endfor %}
