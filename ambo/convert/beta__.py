import yaml
import json
import argparse
import logging
import os,sys,re
from typing import Dict, List, Any, Union, Optional, Tuple
from dataclasses import dataclass

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("nginx-to-ambassador")

@dataclass
class ConversionContext:
    """Context object to track the conversion process and metadata"""
    source_file: str
    namespace: str
    dry_run: bool
    validation_errors: List[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        self.validation_errors = []
        self.warnings = []
    
    def add_error(self, error: str):
        """Add validation error"""
        self.validation_errors.append(error)
        logger.error(f"Validation error: {error}")
    
    def add_warning(self, warning: str):
        """Add warning"""
        self.warnings.append(warning)
        logger.warning(warning)
    
    def has_errors(self) -> bool:
        """Check if there are validation errors"""
        return len(self.validation_errors) > 0


class NginxToAmbassadorConverter:
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.annotation_mappings = self._initialize_annotation_mappings()
    
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load custom configuration from file if provided"""
        default_config = {
            "default_namespace": "default",
            "preserve_comments": True,
            "strict_validation": False,
            "mapping_defaults": {
                "timeout_ms": 3000,
                "connect_timeout_ms": 1000,
                "retry_policy": {
                    "retry_on": "5xx",
                    "num_retries": 1
                }
            }
        }
        
        if not config_file:
            return default_config
        
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                return {**default_config, **user_config}
        except Exception as e:
            logger.warning(f"Failed to load config file {config_file}: {e}")
            logger.warning("Using default configuration")
            return default_config
    
    def _initialize_annotation_mappings(self) -> Dict:
        """Define mappings from nginx-ingress annotations to Ambassador configurations"""
        return {
            # Basic settings
            "nginx.ingress.kubernetes.io/rewrite-target": self._handle_rewrite_target,
            "nginx.ingress.kubernetes.io/ssl-redirect": self._handle_ssl_redirect,
            "nginx.ingress.kubernetes.io/force-ssl-redirect": self._handle_force_ssl_redirect,
            
            # Authentication
            "nginx.ingress.kubernetes.io/auth-type": self._handle_auth_type,
            "nginx.ingress.kubernetes.io/auth-url": self._handle_auth_url,
            "nginx.ingress.kubernetes.io/auth-realm": self._handle_auth_realm,
            
            # Rate limiting
            "nginx.ingress.kubernetes.io/limit-connections": self._handle_limit_connections,
            "nginx.ingress.kubernetes.io/limit-rps": self._handle_limit_rps,
            
            # Timeout and retries
            "nginx.ingress.kubernetes.io/proxy-connect-timeout": self._handle_connect_timeout,
            "nginx.ingress.kubernetes.io/proxy-read-timeout": self._handle_read_timeout,
            "nginx.ingress.kubernetes.io/proxy-send-timeout": self._handle_send_timeout,
            "nginx.ingress.kubernetes.io/proxy-next-upstream": self._handle_next_upstream,
            "nginx.ingress.kubernetes.io/proxy-next-upstream-tries": self._handle_next_upstream_tries,
            
            # CORS
            "nginx.ingress.kubernetes.io/enable-cors": self._handle_enable_cors,
            "nginx.ingress.kubernetes.io/cors-allow-methods": self._handle_cors_allow_methods,
            "nginx.ingress.kubernetes.io/cors-allow-headers": self._handle_cors_allow_headers,
            "nginx.ingress.kubernetes.io/cors-allow-origin": self._handle_cors_allow_origin,
            
            # Others
            "kubernetes.io/ingress.class": self._handle_ingress_class,
        }
    
    def convert(self, input_files: List[str], dry_run: bool = False, 
                namespace: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        Convert nginx-ingress configs to Ambassador resources
        
        Args:
            input_files: List of nginx-ingress YAML files
            dry_run: If True, validate but don't output files
            namespace: Target namespace for generated resources
            
        Returns:
            Dictionary mapping output filenames to resources
        """
        if not namespace:
            namespace = self.config["default_namespace"]
        
        all_resources = {}
        
        for input_file in input_files:
            try:
                logger.info(f"Processing file: {input_file}")
                documents = self._load_yaml_documents(input_file)
                
                for doc in documents:
                    if not doc:
                        continue
                    
                    kind = doc.get("kind", "")
                    
                    # Handle different resource types
                    if kind.lower() == "ingress":
                        context = ConversionContext(
                            source_file=input_file,
                            namespace=doc.get("metadata", {}).get("namespace", namespace),
                            dry_run=dry_run
                        )
                        
                        resources = self._convert_ingress(doc, context)
                        
                        # Generate output filenames based on ingress name
                        ingress_name = doc.get("metadata", {}).get("name", "unknown")
                        output_file = f"{ingress_name}-ambassador.yaml"
                        
                        if context.has_errors() and self.config["strict_validation"]:
                            logger.error(f"Conversion failed for {ingress_name} due to validation errors")
                            continue
                        
                        all_resources[output_file] = resources
                    else:
                        logger.debug(f"Skipping non-Ingress resource of kind: {kind}")
            
            except Exception as e:
                logger.error(f"Error processing file {input_file}: {e}")
                continue
        
        return all_resources
    
    def _load_yaml_documents(self, file_path: str) -> List[Dict]:
        """Load multiple YAML documents from a file"""
        try:
            with open(file_path, 'r') as f:
                return list(yaml.safe_load_all(f))
        except Exception as e:
            logger.error(f"Failed to load YAML file {file_path}: {e}")
            raise
    
    def _convert_ingress(self, ingress: Dict, context: ConversionContext) -> List[Dict]:
        """Convert a single Ingress resource to Ambassador resources"""
        ambassador_resources = []
        
        # Extract metadata
        metadata = ingress.get("metadata", {})
        name = metadata.get("name", "unknown")
        annotations = metadata.get("annotations", {})
        ingress_namespace = metadata.get("namespace", context.namespace)
        
        # Base labels for all generated resources
        common_labels = {
            "app.kubernetes.io/managed-by": "nginx-to-ambassador-converter",
            "original-ingress-name": name,
        }
        if "labels" in metadata:
            common_labels.update(metadata["labels"])
        
        # Process TLS configurations
        tls_contexts = self._process_tls_config(ingress.get("spec", {}).get("tls", []), 
                                              name, ingress_namespace, common_labels)
        ambassador_resources.extend(tls_contexts)
        
        # Process global annotations that apply to all rules
        global_config = self._process_annotations(annotations, name)
        
        # Process rules
        rules = ingress.get("spec", {}).get("rules", [])
        if not rules:
            context.add_warning(f"Ingress {name} has no rules defined")
        
        # Special case: default backend (no rules)
        default_backend = ingress.get("spec", {}).get("defaultBackend")
        if default_backend:
            default_mapping = self._create_default_backend_mapping(
                default_backend, name, ingress_namespace, common_labels, global_config
            )
            ambassador_resources.append(default_mapping)
        
        # Process each rule
        for i, rule in enumerate(rules):
            rule_resources = self._process_rule(
                rule, name, i, ingress_namespace, common_labels, global_config, context
            )
            ambassador_resources.extend(rule_resources)
        
        # Add any additional resources required by annotations
        if global_config.get("requires_auth_service"):
            auth_service = self._create_auth_service(
                annotations, name, ingress_namespace, common_labels
            )
            if auth_service:
                ambassador_resources.append(auth_service)
        
        if global_config.get("requires_rate_limit"):
            rate_limit = self._create_rate_limit(
                annotations, name, ingress_namespace, common_labels
            )
            if rate_limit:
                ambassador_resources.append(rate_limit)
        
        return ambassador_resources
    
    def _process_rule(self, rule: Dict, ingress_name: str, rule_index: int, 
                     namespace: str, labels: Dict, global_config: Dict,
                     context: ConversionContext) -> List[Dict]:
        """Process a single ingress rule, creating appropriate Ambassador resources"""
        resources = []
        
        host = rule.get("host")
        
        # Create a Host resource if a hostname is specified
        if host:
            host_resource = {
                "apiVersion": "getambassador.io/v3alpha1",
                "kind": "Host",
                "metadata": {
                    "name": f"{ingress_name}-host-{rule_index}",
                    "namespace": namespace,
                    "labels": labels,
                },
                "spec": {
                    "hostname": host,
                    "acmeProvider": {
                        "authority": "none"  # Default to no ACME, can be overridden by annotations
                    }
                }
            }
            
            # Apply TLS settings if present in global config
            if global_config.get("tls_enabled"):
                host_resource["spec"]["tlsSecret"] = {
                    "name": global_config.get("tls_secret_name", f"{ingress_name}-tls")
                }
            
            resources.append(host_resource)
        
        # Process HTTP paths
        http_paths = rule.get("http", {}).get("paths", [])
        for path_index, path in enumerate(http_paths):
            path_resource = self._process_path(
                path, ingress_name, rule_index, path_index, host, 
                namespace, labels, global_config, context
            )
            if path_resource:
                resources.append(path_resource)
        
        return resources
    
    def _process_path(self, path: Dict, ingress_name: str, rule_index: int, 
                     path_index: int, host: Optional[str], namespace: str, 
                     labels: Dict, global_config: Dict,
                     context: ConversionContext) -> Optional[Dict]:
        """Convert an Ingress path to an Ambassador Mapping"""
        path_type = path.get("pathType", "Prefix")
        path_value = path.get("path", "/")
        backend = path.get("backend", {})
        
        if not backend:
            context.add_warning(f"Path {path_value} has no backend defined")
            return None
        
        # Extract backend service details
        service_name = None
        service_port = None
        
        # Handle both old and new Ingress API versions
        if "serviceName" in backend:  # v1beta1
            service_name = backend.get("serviceName")
            service_port = backend.get("servicePort")
        elif "service" in backend:  # v1
            service_name = backend.get("service", {}).get("name")
            service_port = backend.get("service", {}).get("port", {}).get("number")
            # Handle string port names
            if not service_port and "name" in backend.get("service", {}).get("port", {}):
                port_name = backend.get("service", {}).get("port", {}).get("name")
                service_port = port_name
                context.add_warning(f"Using named port '{port_name}' for service {service_name}. "
                                   "Ambassador might require port numbers.")
        
        if not service_name or not service_port:
            context.add_error(f"Invalid backend specification for path {path_value}")
            return None
        
        # Create mapping resource
        mapping_name = f"{ingress_name}-mapping-{rule_index}-{path_index}"
        mapping = {
            "apiVersion": "getambassador.io/v3alpha1",
            "kind": "Mapping",
            "metadata": {
                "name": mapping_name,
                "namespace": namespace,
                "labels": labels.copy(),
            },
            "spec": {
                "prefix": path_value,
                "service": f"{service_name}.{namespace}:{service_port}",
            }
        }
        
        # Add host if specified
        if host:
            mapping["spec"]["host"] = host
        
        # Apply pathType
        if path_type == "Exact":
            mapping["spec"]["prefix_exact"] = True
        elif path_type == "Prefix":
            # This is the default in Ambassador
            pass
        else:
            context.add_warning(f"Unsupported pathType {path_type} for path {path_value}, "
                               "using Prefix matching")
        
        # Apply rewrite rules from global config
        if "rewrite" in global_config:
            mapping["spec"]["rewrite"] = global_config["rewrite"]
        
        # Apply timeout settings
        if "timeout_ms" in global_config:
            mapping["spec"]["timeout_ms"] = global_config["timeout_ms"]
        else:
            mapping["spec"]["timeout_ms"] = self.config["mapping_defaults"]["timeout_ms"]
        
        if "connect_timeout_ms" in global_config:
            mapping["spec"]["connect_timeout_ms"] = global_config["connect_timeout_ms"]
        else:
            mapping["spec"]["connect_timeout_ms"] = self.config["mapping_defaults"]["connect_timeout_ms"]
        
        # Apply retry policy
        if "retry_policy" in global_config:
            mapping["spec"]["retry_policy"] = global_config["retry_policy"]
        elif self.config["mapping_defaults"]["retry_policy"]:
            mapping["spec"]["retry_policy"] = self.config["mapping_defaults"]["retry_policy"]
        
        # Apply CORS settings
        if "cors" in global_config:
            mapping["spec"]["cors"] = global_config["cors"]
        
        # Apply circuit breaking
        if "circuit_breaker" in global_config:
            mapping["spec"]["circuit_breakers"] = global_config["circuit_breaker"]
        
        # Apply authentication
        if "auth_service" in global_config:
            mapping["spec"]["bypass_auth"] = False  # Ensure auth is applied to this mapping
        
        return mapping
    
    def _process_annotations(self, annotations: Dict, name: str) -> Dict:
        """Process nginx-ingress annotations and convert to Ambassador configuration"""
        config = {}
        
        for annotation, value in annotations.items():
            handler = self.annotation_mappings.get(annotation)
            if handler:
                handler(annotation, value, config)
            else:
                # Try generic handling for common annotation prefixes
                if annotation.startswith("nginx.ingress.kubernetes.io/"):
                    logger.debug(f"Unhandled nginx annotation: {annotation}")
        
        return config
    
    def _process_tls_config(self, tls_configs: List[Dict], name: str, 
                           namespace: str, labels: Dict) -> List[Dict]:
        """Process TLS configurations and create Ambassador TLSContext resources"""
        tls_contexts = []
        
        for i, tls in enumerate(tls_configs):
            secret_name = tls.get("secretName")
            hosts = tls.get("hosts", [])
            
            if not secret_name:
                logger.warning(f"TLS config {i} in Ingress {name} has no secretName")
                continue
            
            context_name = f"{name}-tls-context-{i}"
            tls_context = {
                "apiVersion": "getambassador.io/v3alpha1",
                "kind": "TLSContext",
                "metadata": {
                    "name": context_name,
                    "namespace": namespace,
                    "labels": labels.copy(),
                },
                "spec": {
                    "secret": secret_name,
                    "hosts": hosts
                }
            }
            
            tls_contexts.append(tls_context)
        
        return tls_contexts
    
    def _create_default_backend_mapping(self, backend: Dict, ingress_name: str, 
                                      namespace: str, labels: Dict, 
                                      global_config: Dict) -> Dict:
        """Create a Mapping for the default backend of an Ingress"""
        service_name = None
        service_port = None
        
        # Handle both old and new Ingress API versions
        if "serviceName" in backend:  # v1beta1
            service_name = backend.get("serviceName")
            service_port = backend.get("servicePort")
        elif "service" in backend:  # v1
            service_name = backend.get("service", {}).get("name")
            service_port = backend.get("service", {}).get("port", {}).get("number")
            if not service_port and "name" in backend.get("service", {}).get("port", {}):
                service_port = backend.get("service", {}).get("port", {}).get("name")
        
        mapping = {
            "apiVersion": "getambassador.io/v3alpha1",
            "kind": "Mapping",
            "metadata": {
                "name": f"{ingress_name}-default-backend",
                "namespace": namespace,
                "labels": labels.copy(),
            },
            "spec": {
                "prefix": "/",  # Default backend matches everything
                "service": f"{service_name}.{namespace}:{service_port}",
            }
        }
        
        # Apply timeout settings
        if "timeout_ms" in global_config:
            mapping["spec"]["timeout_ms"] = global_config["timeout_ms"]
        
        if "connect_timeout_ms" in global_config:
            mapping["spec"]["connect_timeout_ms"] = global_config["connect_timeout_ms"]
        
        return mapping
    
    def _create_auth_service(self, annotations: Dict, ingress_name: str, 
                            namespace: str, labels: Dict) -> Optional[Dict]:
        """Create an AuthService resource based on auth annotations"""
        auth_url = annotations.get("nginx.ingress.kubernetes.io/auth-url")
        if not auth_url:
            return None
        
        # Parse the auth URL to extract service information
        # Expected format: https://hostname/path or http://service.namespace/path
        auth_service_name = "auth-service"
        auth_service_namespace = namespace
        auth_service_port = 80
        
        try:
            # Very simple parsing, would need to be enhanced for production
            if "://" in auth_url:
                protocol, rest = auth_url.split("://", 1)
                if "/" in rest:
                    service_host, path = rest.split("/", 1)
                    path = "/" + path
                else:
                    service_host, path = rest, "/"
                
                # Try to parse service.namespace format
                if "." in service_host:
                    auth_service_name, auth_service_namespace = service_host.split(".", 1)
                else:
                    auth_service_name = service_host
                
                # Check for port specification
                if ":" in auth_service_name:
                    auth_service_name, port_str = auth_service_name.split(":", 1)
                    auth_service_port = int(port_str)
        except Exception as e:
            logger.warning(f"Failed to parse auth URL {auth_url}: {e}")
            # Use defaults
        
        auth_service = {
            "apiVersion": "getambassador.io/v3alpha1",
            "kind": "AuthService",
            "metadata": {
                "name": f"{ingress_name}-auth",
                "namespace": namespace,
                "labels": labels.copy(),
            },
            "spec": {
                "auth_service": f"{auth_service_name}.{auth_service_namespace}:{auth_service_port}",
                "proto": "http",  # Default to HTTP, would need to be adjusted based on annotation
                "path_prefix": "/",  # May need adjustment based on parsed path
                "timeout_ms": 5000
            }
        }
        
        # Add auth headers if specified
        auth_headers = annotations.get("nginx.ingress.kubernetes.io/auth-response-headers")
        if auth_headers:
            auth_service["spec"]["allowed_request_headers"] = auth_headers.split(",")
        
        return auth_service
    
    def _create_rate_limit(self, annotations: Dict, ingress_name: str, 
                         namespace: str, labels: Dict) -> Optional[Dict]:
        """Create a RateLimit resource based on rate limiting annotations"""
        rps = annotations.get("nginx.ingress.kubernetes.io/limit-rps")
        if not rps:
            return None
        
        try:
            rps_val = int(rps)
        except ValueError:
            logger.warning(f"Invalid RPS value: {rps}")
            return None
        
        rate_limit = {
            "apiVersion": "getambassador.io/v3alpha1",
            "kind": "RateLimit",
            "metadata": {
                "name": f"{ingress_name}-rate-limit",
                "namespace": namespace,
                "labels": labels.copy(),
            },
            "spec": {
                "domain": ingress_name,
                "limits": [{
                    "pattern": [{
                        "generic_key": {
                            "value": "default"
                        }
                    }],
                    "rate": rps_val,
                    "unit": "second"
                }]
            }
        }
        
        return rate_limit
    
    # Annotation handler methods
    def _handle_rewrite_target(self, annotation: str, value: str, config: Dict):
        config["rewrite"] = value
    
    def _handle_ssl_redirect(self, annotation: str, value: str, config: Dict):
        if value.lower() in ("true", "yes", "1"):
            config["tls_enabled"] = True
    
    def _handle_force_ssl_redirect(self, annotation: str, value: str, config: Dict):
        if value.lower() in ("true", "yes", "1"):
            config["tls_enabled"] = True
    
    def _handle_auth_type(self, annotation: str, value: str, config: Dict):
        config["auth_type"] = value
        config["requires_auth_service"] = True
    
    def _handle_auth_url(self, annotation: str, value: str, config: Dict):
        config["auth_url"] = value
        config["requires_auth_service"] = True
    
    def _handle_auth_realm(self, annotation: str, value: str, config: Dict):
        config["auth_realm"] = value
    
    def _handle_limit_connections(self, annotation: str, value: str, config: Dict):
        try:
            config["circuit_breaker"] = config.get("circuit_breaker", {})
            config["circuit_breaker"]["max_connections"] = int(value)
        except ValueError:
            logger.warning(f"Invalid connection limit value: {value}")
    
    def _handle_limit_rps(self, annotation: str, value: str, config: Dict):
        try:
            config["requires_rate_limit"] = True
            config["rate_limit_rps"] = int(value)
        except ValueError:
            logger.warning(f"Invalid RPS limit value: {value}")
    
    def _handle_connect_timeout(self, annotation: str, value: str, config: Dict):
        try:
            # Convert from nginx seconds to Ambassador milliseconds
            timeout_seconds = float(value)
            config["connect_timeout_ms"] = int(timeout_seconds * 1000)
        except ValueError:
            logger.warning(f"Invalid connect timeout value: {value}")
    
    def _handle_read_timeout(self, annotation: str, value: str, config: Dict):
        try:
            # Convert from nginx seconds to Ambassador milliseconds
            timeout_seconds = float(value)
            config["timeout_ms"] = int(timeout_seconds * 1000)
        except ValueError:
            logger.warning(f"Invalid read timeout value: {value}")
    
    def _handle_send_timeout(self, annotation: str, value: str, config: Dict):
        # In nginx this controls how long sending to client can take
        # Ambassador doesn't have a direct equivalent, so we'll log it
        logger.info(f"nginx send timeout {value}s has no direct Ambassador equivalent")
    
    def _handle_next_upstream(self, annotation: str, value: str, config: Dict):
        # Map nginx next-upstream to Ambassador retry_policy
        retry_values = value.split()
        retry_on = []
        
        mapping = {
            "error": "connect-failure",
            "timeout": "connect-failure",
            "invalid_header": "5xx",
            "http_500": "5xx", 
            "http_502": "5xx",
            "http_503": "5xx",
            "http_504": "5xx",
            "http_403": "5xx",  # Not exact but closest equivalent
            "http_404": "5xx",  # Not exact but closest equivalent
            "http_429": "retriable-4xx"
        }
        
        for nginx_val in retry_values:
            ambassador_val = mapping.get(nginx_val)
            if ambassador_val and ambassador_val not in retry_on:
                retry_on.append(ambassador_val)
        
        if retry_on:
            config["retry_policy"] = config.get("retry_policy", {})
            config["retry_policy"]["retry_on"] = " ".join(retry_on)
    
    def _handle_next_upstream_tries(self, annotation: str, value: str, config: Dict):
        try:
            num_retries = int(value)
            config["retry_policy"] = config.get("retry_policy", {})
            config["retry_policy"]["num_retries"] = num_retries
        except ValueError:
            logger.warning(f"Invalid retry count value: {value}")
    
    def _handle_enable_cors(self, annotation: str, value: str, config: Dict):
        if value.lower() in ("true", "yes", "1"):
            config["cors"] = config.get("cors", {})
            config["cors"]["origins"] = "*"
            config["cors"]["methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            config["cors"]["headers"] = "*"
    
    def _handle_cors_allow_methods(self, annotation: str, value: str, config: Dict):
        config["cors"] = config.get("cors", {})
        config["cors"]["methods"] = value
    
    def _handle_cors_allow_headers(self, annotation: str, value: str, config: Dict):
        config["cors"] = config.get("cors", {})
        config["cors"]["headers"] = value
    
    def _handle_cors_allow_origin(self, annotation: str, value: str, config: Dict):
        config["cors"] = config.get("cors", {})
        config["cors"]["origins"] = value
    
    def _handle_ingress_class(self, annotation: str, value: str, config: Dict):
        # We only care if it's explicitly set to something other than "nginx"
        if value != "nginx":
            logger.warning(f"Ingress class is '{value}', not 'nginx'. This might not be intended for nginx-ingress.")


def main():
    parser = argparse.ArgumentParser(
        description="Convert nginx-ingress to Ambassador API resources"
    )
    parser.add_argument(
        "--input", "-i", nargs="+", required=True, 
        help="Input nginx-ingress YAML files"
    )
    parser.add_argument(
        "--output-dir", "-o", required=False, default="./ambassador-output",
        help="Output directory for Ambassador resources"
    )
    parser.add_argument(
        "--namespace", "-n", required=False,
        help="Target Kubernetes namespace for resources"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate and print resources without writing files"
    )
    parser.add_argument(
        "--config", "-c", required=False,
        help="Configuration file for converter settings"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    converter = NginxToAmbassadorConverter(args.config)
    resources = converter.convert(args.input, args.dry_run, args.namespace)
    
    if args.dry_run:
        logger.info("Dry run mode - not writing files")
        for filename, file_resources in resources.items():
            print(f"\n--- {filename} ---")
            yaml_content = yaml.dump_all(file_resources)
            print(yaml_content)
        return
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Write files
    for filename, file_resources in resources.items():
        output_path = os.path.join(args.output_dir, filename)
        with open(output_path, "w") as f:
            yaml.dump_all(file_resources, f)
        logger.info(f"Wrote {len(file_resources)} resources to {output_path}")


if __name__ == "__main__":
    main()

