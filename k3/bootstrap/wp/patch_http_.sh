#!/bin/bash
set -e

echo "==== WordPress Fix Script ===="

# Get server's external IP
NODE_IP=$(hostname -I | awk '{print $1}')

# Get WordPress NodePort
WP_PORT=$(kubectl get svc -n wordpress wordpress -o jsonpath="{.spec.ports[0].nodePort}")

echo "Your WordPress should be accessible at: http://$NODE_IP:$WP_PORT"
echo "Testing connection to WordPress..."

# Test the connection
if curl -s --max-time 5 "http://$NODE_IP:$WP_PORT" | grep -q "WordPress"; then
    echo "✅ WordPress is now accessible!"
else
    echo "⚠️ Still having issues. Let's check WordPress container logs:"
    WP_POD=$(kubectl get pods -n wordpress -l app.kubernetes.io/name=wordpress -o jsonpath='{.items[0].metadata.name}')
    kubectl logs -n wordpress $WP_POD --tail=50
    
    echo ""
    echo "Let's create an Ingress rule to expose WordPress through Traefik:"
    
    # Create an ingress resource
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wordpress-ingress
  namespace: wordpress
spec:
  rules:
  - host: wordpress.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: wordpress
            port:
              number: 80
EOF

    echo ""
    echo "Ingress created. Add this to your host machine's /etc/hosts file:"
    echo "$NODE_IP  wordpress.local"
    echo "Then access WordPress at: http://wordpress.local"
    
    # Alternative solution using port-forward
    echo ""
    echo "Alternative solution - let's set up a port-forward to access directly:"
    echo "Running: kubectl port-forward -n wordpress svc/wordpress 8080:80 --address 0.0.0.0 &"
    kubectl port-forward -n wordpress svc/wordpress 8080:80 --address 0.0.0.0 &
    echo "✅ WordPress should now be accessible at: http://$NODE_IP:8080"
fi

# Get WordPress credentials
echo ""
echo "WordPress admin credentials:"
WP_USERNAME="admin"
WP_PASSWORD=$(kubectl get secret -n wordpress wordpress -o jsonpath="{.data.wordpress-password}" | base64 --decode)
echo "Username: $WP_USERNAME"
echo "Password: $WP_PASSWORD"
echo ""
echo "==============================="
