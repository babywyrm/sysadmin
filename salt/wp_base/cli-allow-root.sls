  
{% if salt['pillar.get']('wordpress:cli:allowroot') == True %}
{% set allowroot = "--allow-root" %}
{% else %}
{% set allowroot = "" %}
{% endif %}
