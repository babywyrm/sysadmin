from kubernetes import client, config
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime
import time

class K8sDashboard:
    def __init__(self):
        config.load_kube_config()
        self.v1 = client.CoreV1Api()
        self.metrics = client.CustomObjectsApi()
        self.console = Console()
    
    def parse_quantity(self, quantity_str, unit_type='cpu'):
        """Convert K8s quantity strings to numbers"""
        if not quantity_str:
            return 0
        
        qty = str(quantity_str)
        
        if unit_type == 'cpu':
            # CPU: "100m" = 0.1 cores, "1" = 1 core
            if 'm' in qty:
                return int(qty.replace('m', ''))
            elif 'n' in qty:
                return int(qty.replace('n', '')) / 1_000_000
            return int(float(qty) * 1000)
        else:
            # Memory: Ki, Mi, Gi
            units = {
                'Ki': 1024, 'Mi': 1024**2, 'Gi': 1024**3, 
                'Ti': 1024**4, 'K': 1000, 'M': 1000**2, 
                'G': 1000**3
            }
            for unit, multiplier in units.items():
                if unit in qty:
                    val = float(qty.replace(unit, ''))
                    return int(val * multiplier / (1024**2))  # Convert to Mi
            # Assume bytes if no unit
            return int(float(qty) / (1024**2))
    
    def get_pod_metrics(self):
        """Fetch actual resource usage from metrics-server"""
        try:
            metrics = self.metrics.list_cluster_custom_object(
                group="metrics.k8s.io",
                version="v1beta1",
                plural="pods"
            )
            
            usage_map = {}
            for item in metrics['items']:
                key = f"{item['metadata']['namespace']}/"
                key += f"{item['metadata']['name']}"
                
                total_cpu = 0
                total_mem = 0
                for container in item['containers']:
                    total_cpu += self.parse_quantity(
                        container['usage'].get('cpu', '0'), 'cpu'
                    )
                    total_mem += self.parse_quantity(
                        container['usage'].get('memory', '0'), 'memory'
                    )
                
                usage_map[key] = {
                    'cpu': total_cpu,
                    'memory': total_mem
                }
            
            return usage_map
        except Exception:
            return {}
    
    def get_all_pods_with_resources(self):
        """Get all pods with their resource configuration and usage"""
        pods = self.v1.list_pod_for_all_namespaces()
        usage_map = self.get_pod_metrics()
        
        pod_data = []
        for pod in pods.items:
            # Calculate total requests and limits
            cpu_req = 0
            cpu_lim = 0
            mem_req = 0
            mem_lim = 0
            
            for container in pod.spec.containers:
                if container.resources.requests:
                    cpu_req += self.parse_quantity(
                        container.resources.requests.get('cpu', '0'), 'cpu'
                    )
                    mem_req += self.parse_quantity(
                        container.resources.requests.get('memory', '0'),
                        'memory'
                    )
                
                if container.resources.limits:
                    cpu_lim += self.parse_quantity(
                        container.resources.limits.get('cpu', '0'), 'cpu'
                    )
                    mem_lim += self.parse_quantity(
                        container.resources.limits.get('memory', '0'),
                        'memory'
                    )
            
            # Get actual usage
            pod_key = f"{pod.metadata.namespace}/{pod.metadata.name}"
            usage = usage_map.get(pod_key, {'cpu': 0, 'memory': 0})
            
            # Get restart count
            restarts = 0
            if pod.status.container_statuses:
                restarts = sum(
                    cs.restart_count for cs in pod.status.container_statuses
                )
            
            pod_data.append({
                'namespace': pod.metadata.namespace,
                'name': pod.metadata.name,
                'status': pod.status.phase,
                'restarts': restarts,
                'node': pod.spec.node_name or 'N/A',
                'cpu_req': cpu_req,
                'cpu_lim': cpu_lim,
                'cpu_use': usage['cpu'],
                'mem_req': mem_req,
                'mem_lim': mem_lim,
                'mem_use': usage['memory']
            })
        
        return pod_data
    
    def create_resource_table(self, sort_by='cpu_use'):
        """Create comprehensive resource table"""
        pods = self.get_all_pods_with_resources()
        
        # Sort by specified metric
        pods_sorted = sorted(
            pods, 
            key=lambda x: x.get(sort_by, 0), 
            reverse=True
        )
        
        table = Table(
            title="Pod Resources (Top 15)", 
            show_lines=True,
            title_style="bold cyan"
        )
        
        # Add columns
        table.add_column("Namespace", style="cyan", width=12)
        table.add_column("Pod", style="magenta", width=25)
        table.add_column("Status", style="green", width=10)
        table.add_column("Restarts", justify="right", style="yellow", width=8)
        table.add_column("CPU Use", justify="right", style="red", width=8)
        table.add_column("CPU Req", justify="right", style="blue", width=8)
        table.add_column("CPU Lim", justify="right", style="blue", width=8)
        table.add_column("Mem Use", justify="right", style="red", width=8)
        table.add_column("Mem Req", justify="right", style="blue", width=8)
        table.add_column("Mem Lim", justify="right", style="blue", width=8)
        
        # Add rows (top 15)
        for pod in pods_sorted[:15]:
            # Color code status
            if pod['status'] == 'Running':
                status_text = "[green]Running[/green]"
            elif pod['status'] in ['Pending', 'ContainerCreating']:
                status_text = "[yellow]" + pod['status'] + "[/yellow]"
            else:
                status_text = "[red]" + pod['status'] + "[/red]"
            
            # Format CPU (millicores)
            cpu_use = f"{pod['cpu_use']}m" if pod['cpu_use'] > 0 else "-"
            cpu_req = f"{pod['cpu_req']}m" if pod['cpu_req'] > 0 else "-"
            cpu_lim = f"{pod['cpu_lim']}m" if pod['cpu_lim'] > 0 else "-"
            
            # Format Memory (Mi)
            mem_use = f"{pod['mem_use']}Mi" if pod['mem_use'] > 0 else "-"
            mem_req = f"{pod['mem_req']}Mi" if pod['mem_req'] > 0 else "-"
            mem_lim = f"{pod['mem_lim']}Mi" if pod['mem_lim'] > 0 else "-"
            
            # Highlight high restarts
            restart_text = str(pod['restarts'])
            if pod['restarts'] > 3:
                restart_text = f"[bold red]{pod['restarts']}[/bold red]"
            
            table.add_row(
                pod['namespace'][:12],
                pod['name'][:25],
                status_text,
                restart_text,
                cpu_use,
                cpu_req,
                cpu_lim,
                mem_use,
                mem_req,
                mem_lim
            )
        
        return table
    
    def create_problem_pods_table(self):
        """Show only pods with issues"""
        pods = self.get_all_pods_with_resources()
        
        # Filter for problems
        problem_pods = [
            p for p in pods 
            if p['status'] not in ['Running', 'Succeeded'] 
            or p['restarts'] > 2
            or p['mem_lim'] > 0 and p['mem_use'] > p['mem_lim'] * 0.9
        ]
        
        if not problem_pods:
            return None
        
        table = Table(
            title="Problem Pods", 
            show_lines=True,
            title_style="bold red"
        )
        
        table.add_column("Namespace", style="cyan")
        table.add_column("Pod", style="magenta")
        table.add_column("Issue", style="red")
        table.add_column("Restarts", justify="right", style="yellow")
        table.add_column("CPU Use/Lim", justify="right", style="blue")
        table.add_column("Mem Use/Lim", justify="right", style="blue")
        
        for pod in problem_pods[:10]:
            # Determine issue
            issues = []
            if pod['status'] not in ['Running', 'Succeeded']:
                issues.append(pod['status'])
            if pod['restarts'] > 2:
                issues.append(f"Restarts:{pod['restarts']}")
            if pod['mem_lim'] > 0 and pod['mem_use'] > pod['mem_lim'] * 0.9:
                issues.append("MemPressure")
            
            issue_text = ", ".join(issues)
            
            cpu_text = f"{pod['cpu_use']}m/{pod['cpu_lim']}m" if pod[
                'cpu_lim'
            ] > 0 else f"{pod['cpu_use']}m/-"
            
            mem_text = f"{pod['mem_use']}Mi/{pod['mem_lim']}Mi" if pod[
                'mem_lim'
            ] > 0 else f"{pod['mem_use']}Mi/-"
            
            table.add_row(
                pod['namespace'],
                pod['name'],
                issue_text,
                str(pod['restarts']),
                cpu_text,
                mem_text
            )
        
        return table
    
    def get_cluster_summary(self):
        """Get cluster-level statistics"""
        pods = self.get_all_pods_with_resources()
        nodes = self.v1.list_node()
        
        total_cpu_req = sum(p['cpu_req'] for p in pods)
        total_cpu_lim = sum(p['cpu_lim'] for p in pods)
        total_cpu_use = sum(p['cpu_use'] for p in pods)
        
        total_mem_req = sum(p['mem_req'] for p in pods)
        total_mem_lim = sum(p['mem_lim'] for p in pods)
        total_mem_use = sum(p['mem_use'] for p in pods)
        
        running = sum(1 for p in pods if p['status'] == 'Running')
        problem = sum(
            1 for p in pods 
            if p['status'] not in ['Running', 'Succeeded']
        )
        
        return {
            'nodes': len(nodes.items),
            'total_pods': len(pods),
            'running_pods': running,
            'problem_pods': problem,
            'cpu_req': total_cpu_req,
            'cpu_lim': total_cpu_lim,
            'cpu_use': total_cpu_use,
            'mem_req': total_mem_req,
            'mem_lim': total_mem_lim,
            'mem_use': total_mem_use
        }
    
    def create_summary_table(self):
        """Create cluster summary"""
        summary = self.get_cluster_summary()
        
        table = Table(
            title="Cluster Summary", 
            show_header=False,
            title_style="bold green"
        )
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Nodes", str(summary['nodes']))
        table.add_row("Total Pods", str(summary['total_pods']))
        table.add_row(
            "Running Pods", 
            f"[green]{summary['running_pods']}[/green]"
        )
        
        if summary['problem_pods'] > 0:
            table.add_row(
                "Problem Pods", 
                f"[bold red]{summary['problem_pods']}[/bold red]"
            )
        
        table.add_row("", "")
        table.add_row(
            "CPU Requested", 
            f"{summary['cpu_req']/1000:.2f} cores"
        )
        table.add_row(
            "CPU Limited", 
            f"{summary['cpu_lim']/1000:.2f} cores"
        )
        table.add_row(
            "CPU Used", 
            f"[bold]{summary['cpu_use']/1000:.2f}[/bold] cores"
        )
        
        table.add_row("", "")
        table.add_row(
            "Mem Requested", 
            f"{summary['mem_req']:.0f} Mi"
        )
        table.add_row(
            "Mem Limited", 
            f"{summary['mem_lim']:.0f} Mi"
        )
        table.add_row(
            "Mem Used", 
            f"[bold]{summary['mem_use']:.0f}[/bold] Mi"
        )
        
        return table
    
    def display_dashboard(self):
        """Display the complete dashboard"""
        self.console.clear()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.console.print(
            Panel(
                "[bold cyan]Kubernetes Resource Dashboard[/bold cyan]\n"
                f"[dim]{timestamp}[/dim]",
                style="bold blue"
            )
        )
        
        # Summary
        self.console.print(self.create_summary_table())
        self.console.print()
        
        # Problem pods (if any)
        problem_table = self.create_problem_pods_table()
        if problem_table:
            self.console.print(problem_table)
            self.console.print()
        
        # Top resource consumers
        self.console.print(self.create_resource_table(sort_by='cpu_use'))
        self.console.print()
        
        self.console.print(
            "[dim]Press Ctrl+C to exit | "
            "Refreshing every 5 seconds[/dim]"
        )
    
    def watch(self, interval=5):
        """Live updating dashboard"""
        try:
            while True:
                self.display_dashboard()
                time.sleep(interval)
        except KeyboardInterrupt:
            self.console.print("\n[red]Dashboard stopped[/red]")

if __name__ == "__main__":
    import sys
    
    dashboard = K8sDashboard()
    
    # Allow custom refresh interval
    interval = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    
    dashboard.watch(interval=interval)
