nginx_restart:
  module.wait:
    - name: service.restart
    - m_name: nginx
    - onchanges:
      - nginx_configuration
