```

server {
  ...
  
  add_header Content-Security-Policy "default-src 'none'";
  add_header X-Content-Security-Policy "default-src 'none'";
  add_header X-WebKit-CSP "default-src 'none'";

  add_header "Access-Control-Allow-Headers" "X-Requested-With";
  
  if ( $http_origin ~* (https?://(.+\.)?(domain1|domain2|domain3)\.(?:me|co|com)$) ) {
    set $cors "$http_origin";
  }
  
  add_header "Access-Control-Allow-Origin" "$cors";
  
  ...
}

```

###
###

