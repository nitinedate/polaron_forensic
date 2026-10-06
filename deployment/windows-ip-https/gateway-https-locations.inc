location ^~ /.well-known/acme-challenge/ {
    root /var/www/certbot;
    default_type text/plain;
    try_files $uri =404;
}

location = /health {
    set $api_upstream http://host.docker.internal:8082;
    include /etc/nginx/conf.d/gateway-proxy.inc;
}

location /api/acquisition/ {
    set $api_upstream $hdr_upstream;
    include /etc/nginx/conf.d/gateway-proxy.inc;
}

location /api/vuln/ { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scanners { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scanner-agent/ { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scan-jobs { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/scan-policies { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/assets { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }
location /api/remediation-tasks { set $api_upstream http://host.docker.internal:8082; include /etc/nginx/conf.d/gateway-proxy.inc; }

location /api/ {
    set $api_upstream $hdr_upstream;
    include /etc/nginx/conf.d/gateway-proxy.inc;
}

location /assets/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    try_files $uri =404;
}

location / {
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    expires -1;
    try_files $uri $uri/ /index.html;
}
