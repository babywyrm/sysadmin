from kubernetes import client, config
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime
import time
import sys
import argparse

class K8sDashboard:
    def __init__(self):
        config.load_kube_config()
        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.metrics = client.CustomObjectsApi()
        self.console = Console()
    
    def parse_quantity(self, quantity_str, unit_type='cpu'):
        """Convert K8s quantity strings to numbers"""
        if not quantity_str:
            return 0
        
        qty = str(quantity_str)
        
        if unit_type == 'cpu':
            if 'm' in qty:
                return int(qty.replace('m', ''))
            elif 'n' in qty:
                return int(qty.replace('n', '')) / 1_000_000
            return int(float(qty) * 1000)
        else:
            units = {
                'Ki': 1024, 'Mi': 1024**2, 'Gi': 1024**3, 
                'Ti': 1024**4, 'K': 1000, 'M': 1000**2, 
                'G': 1000**3
            }
            for unit, multiplier in units.items():
                if unit in qty:
                    val = float(qty.replace(unit, ''))
                    return int(val * multiplier / (1024**2))
            return int(float(qty) / (1024**2))
    
    def get_pod_controller_info(self, pod):
        """
        Determine the originating controller and its name.
        Returns tuple: (controller_type, controller_name)
        """
        if not pod.metadata.owner_references:
            return ("Standalone", "-")
        
        owner = pod.metadata.owner_references[0]
        owner_kind = owner.kind
        owner_name = owner.name
        
        # If owned by ReplicaSet, try to find the parent Deployment
        if owner_kind == 'ReplicaSet':
            try:
                rs = self.apps_v1.read_namespaced_replica_set(
                    owner_name, 
                    pod.metadata.namespace
                )
                if rs.metadata.owner_references:
                    parent = rs.metadata.owner_references[0]
                    if parent.kind == 'Deployment':
                        return ('Deployment', parent.name)
            except Exception:
                pass
            return ('ReplicaSet', owner_name)
        
        # Handle other controller types
        controller_map = {
            'StatefulSet': 'StatefulSet',
            'DaemonSet': 'DaemonSet',
            'Job': 'Job',
            'CronJob': 'CronJob',
            'ReplicationController': 'RC'
        }
        
        controller_type = controller_map.get(owner_kind, owner_kind)
        
        return (controller_type, owner_name)
    
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
    
    def get_all_pods_with_resources(self, namespace=None, 
                                    controller_type=None):
        """Get all pods with their resource configuration and usage"""
        if namespace:
            pods = self.v1.list_namespaced_pod(namespace)
        else:
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
            
            # Get controller info
            ctrl_type, ctrl_name = self.get_pod_controller_info(pod)
            
            # Filter by controller type if specified
            if controller_type and ctrl_type.lower() != controller_type.lower():
                continue
            
            pod_data.append({
                'namespace': pod.metadata.namespace,
                'name': pod.metadata.name,
                'controller_type': ctrl_type,
                'controller_name': ctrl_name,
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
    
    def create_resource_table(self, sort_by='cpu_use', limit=15, 
                              namespace=None, controller_type=None):
        """Create comprehensive resource table"""
        pods = self.get_all_pods_with_resources(
            namespace=namespace, 
            controller_type=controller_type
        )
        
        pods_sorted = sorted(
            pods, 
            key=lambda x: x.get(sort_by, 0), 
            reverse=True
        )
        
        title = f"Pod Resources (Top {limit})"
        if namespace:
            title += f" - Namespace: {namespace}"
        if controller_type:
            title += f" - Type: {controller_type}"
        
        table = Table(
            title=title, 
            show_lines=True,
            title_style="bold cyan"
        )
        
        # Add columns
        table.add_column("Namespace", style="cyan", width=12)
        table.add_column("Pod", style="magenta", width=22)
        table.add_column("Controller", style="blue", width=18)
        table.add_column("Type", style="yellow", width=8)
        table.add_column("Status", style="green", width=8)
        table.add_column("↻", justify="right", style="yellow", width=3)
        table.add_column("CPU↑", justify="right", style="red", width=6)
        table.add_column("C-Req", justify="right", style="blue", width=6)
        table.add_column("C-Lim", justify="right", style="blue", width=6)
        table.add_column("Mem↑", justify="right", style="red", width=6)
        table.add_column("M-Req", justify="right", style="blue", width=6)
        table.add_column("M-Lim", justify="right", style="blue", width=6)
        
        for pod in pods_sorted[:limit]:
            # Color code status
            if pod['status'] == 'Running':
                status_text = "[green]Run[/green]"
            elif pod['status'] in ['Pending', 'ContainerCreating']:
                status_text = "[yellow]Pend[/yellow]"
            else:
                status_text = "[red]" + pod['status'][:4] + "[/red]"
            
            # Color code controller type
            ctrl_colors = {
                'Deployment': 'green',
                'StatefulSet': 'magenta',
                'DaemonSet': 'yellow',
                'Job': 'cyan',
                'CronJob': 'blue',
                'Standalone': 'dim'
            }
            ctrl_color = ctrl_colors.get(pod['controller_type'], 'white')
            ctrl_type_text = f"[{ctrl_color}]{pod['controller_type'][:8]}"
            ctrl_type_text += f"[/{ctrl_color}]"
            
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
            
            # Truncate controller name
            ctrl_name = pod['controller_name'][:18]
            
            table.add_row(
                pod['namespace'][:12],
                pod['name'][:22],
                ctrl_name,
                ctrl_type_text,
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
    
    def create_controller_summary_table(self):
        """Summarize resources by controller type"""
        pods = self.get_all_pods_with_resources()
        
        # Group by controller type
        controller_stats = {}
        for pod in pods:
            ctrl_type = pod['controller_type']
            if ctrl_type not in controller_stats:
                controller_stats[ctrl_type] = {
                    'count': 0,
                    'running': 0,
                    'cpu_use': 0,
                    'mem_use': 0,
                    'restarts': 0
                }
            
            stats = controller_stats[ctrl_type]
            stats['count'] += 1
            if pod['status'] == 'Running':
                stats['running'] += 1
            stats['cpu_use'] += pod['cpu_use']
            stats['mem_use'] += pod['mem_use']
            stats['restarts'] += pod['restarts']
        
        table = Table(
            title="Resources by Controller Type",
            show_lines=True,
            title_style="bold green"
        )
        
        table.add_column("Controller Type", style="cyan")
        table.add_column("Pods", justify="right", style="blue")
        table.add_column("Running", justify="right", style="green")
        table.add_column("Total CPU", justify="right", style="yellow")
        table.add_column("Total Mem", justify="right", style="magenta")
        table.add_column("Restarts", justify="right", style="red")
        
        # Sort by CPU usage
        sorted_controllers = sorted(
            controller_stats.items(),
            key=lambda x: x[1]['cpu_use'],
            reverse=True
        )
        
        for ctrl_type, stats in sorted_controllers:
            table.add_row(
                ctrl_type,
                str(stats['count']),
                str(stats['running']),
                f"{stats['cpu_use']}m",
                f"{stats['mem_use']}Mi",
                str(stats['restarts'])
            )
        
        return table
    
    def create_problem_pods_table(self):
        """Show only pods with issues"""
        pods = self.get_all_pods_with_resources()
        
        problem_pods = [
            p for p in pods 
            if p['status'] not in ['Running', 'Succeeded'] 
            or p['restarts'] > 2
            or (p['mem_lim'] > 0 and p['mem_use'] > p['mem_lim'] * 0.9)
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
        table.add_column("Controller", style="blue")
        table.add_column("Issue", style="red")
        table.add_column("Restarts", justify="right", style="yellow")
        table.add_column("CPU Use/Lim", justify="right", style="blue")
        table.add_column("Mem Use/Lim", justify="right", style="blue")
        
        for pod in problem_pods[:10]:
            issues = []
            if pod['status'] not in ['Running', 'Succeeded']:
                issues.append(pod['status'])
            if pod['restarts'] > 2:
                issues.append(f"↻{pod['restarts']}")
            if pod['mem_lim'] > 0 and pod['mem_use'] > pod['mem_lim'] * 0.9:
                issues.append("MemPress")
            
            issue_text = ", ".join(issues)
            
            cpu_text = f"{pod['cpu_use']}m"
            if pod['cpu_lim'] > 0:
                cpu_text += f"/{pod['cpu_lim']}m"
            
            mem_text = f"{pod['mem_use']}Mi"
            if pod['mem_lim'] > 0:
                mem_text += f"/{pod['mem_lim']}Mi"
            
            ctrl_display = f"{pod['controller_type']}/"
            ctrl_display += f"{pod['controller_name'][:12]}"
            
            table.add_row(
                pod['namespace'],
                pod['name'][:22],
                ctrl_display[:18],
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
    
    def display_dashboard(self, sort_by='cpu_use', limit=15, 
                         show_summary=True, show_controller_summary=True,
                         show_problems=True, namespace=None, 
                         controller_type=None):
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
        
        # Cluster Summary
        if show_summary:
            self.console.print(self.create_summary_table())
            self.console.print()
        
        # Controller type breakdown
        if show_controller_summary:
            self.console.print(self.create_controller_summary_table())
            self.console.print()
        
        # Problem pods (if any)
        if show_problems:
            problem_table = self.create_problem_pods_table()
            if problem_table:
                self.console.print(problem_table)
                self.console.print()
        
        # Top resource consumers
        self.console.print(
            self.create_resource_table(
                sort_by=sort_by, 
                limit=limit,
                namespace=namespace,
                controller_type=controller_type
            )
        )
        self.console.print()
        
        self.console.print(
            "[dim]Press Ctrl+C to exit | "
            f"Sorting by: {sort_by}[/dim]"
        )
    
    def watch(self, interval=5, **kwargs):
        """Live updating dashboard"""
        try:
            while True:
                self.display_dashboard(**kwargs)
                time.sleep(interval)
        except KeyboardInterrupt:
            self.console.print("\n[red]Dashboard stopped[/red]")
    
    def display_once(self, **kwargs):
        """Display dashboard once and exit"""
        self.display_dashboard(**kwargs)

def print_help():
    """Print detailed help information"""
    console = Console()
    
    console.print(
        Panel(
            "[bold cyan]Kubernetes Resource Dashboard - Help[/bold cyan]",
            style="bold blue"
        )
    )
    
    help_text = """
[bold yellow]USAGE:[/bold yellow]
  python3 top.py [OPTIONS]

[bold yellow]OPTIONS:[/bold yellow]
  -h, --help              Show this help message
  -i, --interval N        Refresh interval in seconds (default: 5)
  -s, --sort-by FIELD     Sort by: cpu_use, mem_use, cpu_req, mem_req, 
                          cpu_lim, mem_lim, restarts (default: cpu_use)
  -l, --limit N           Show top N pods (default: 15)
  -n, --namespace NS      Filter by namespace
  -t, --type TYPE         Filter by controller type: deployment, 
                          statefulset, daemonset, job, cronjob, standalone
  --once                  Display once and exit (no live updates)
  --no-summary            Hide cluster summary
  --no-controller         Hide controller type summary
  --no-problems           Hide problem pods section

[bold yellow]EXAMPLES:[/bold yellow]

  [cyan]# Basic usage (live dashboard, refresh every 5 seconds)[/cyan]
  python3 top.py

  [cyan]# Refresh every 10 seconds[/cyan]
  python3 top.py -i 10

  [cyan]# Sort by memory usage[/cyan]
  python3 top.py --sort-by mem_use

  [cyan]# Show only top 5 pods[/cyan]
  python3 top.py --limit 5

  [cyan]# Filter by namespace[/cyan]
  python3 top.py --namespace kube-system

  [cyan]# Show only DaemonSet pods[/cyan]
  python3 top.py --type daemonset

  [cyan]# Show only Deployment pods in wordpress namespace[/cyan]
  python3 top.py -n wordpress -t deployment

  [cyan]# Display once without live updates[/cyan]
  python3 top.py --once

  [cyan]# Sort by restart count, show top 20[/cyan]
  python3 top.py --sort-by restarts --limit 20

  [cyan]# Minimal view (just pod table)[/cyan]
  python3 top.py --no-summary --no-controller --no-problems

[bold yellow]COLUMN LEGEND:[/bold yellow]
  ↻        - Restart count
  CPU↑     - Current CPU usage (millicores)
  C-Req    - CPU requested (millicores)
  C-Lim    - CPU limit (millicores)
  Mem↑     - Current memory usage (Mi)
  M-Req    - Memory requested (Mi)
  M-Lim    - Memory limit (Mi)

[bold yellow]CONTROLLER TYPES:[/bold yellow]
  [green]Deployment[/green]   - Pods from Deployments
  [magenta]StatefulSet[/magenta] - Pods from StatefulSets
  [yellow]DaemonSet[/yellow]   - Pods from DaemonSets
  [cyan]Job[/cyan]         - Pods from Jobs
  [blue]CronJob[/blue]     - Pods from CronJobs
  [dim]Standalone[/dim]   - Manually created pods

[bold yellow]TIPS:[/bold yellow]
  • Requires metrics-server to be installed in the cluster
  • Red highlighting indicates high restart counts (>3)
  • Problem pods section shows non-Running or high-restart pods
  • Use --once for scripting or CI/CD pipelines
  • Press Ctrl+C to exit live mode
"""
    
    console.print(help_text)

def main():
    parser = argparse.ArgumentParser(
        description='Kubernetes Resource Dashboard',
        add_help=False
    )
    
    parser.add_argument(
        '-h', '--help', 
        action='store_true',
        help='Show help message'
    )
    parser.add_argument(
        '-i', '--interval', 
        type=int, 
        default=5,
        help='Refresh interval in seconds (default: 5)'
    )
    parser.add_argument(
        '-s', '--sort-by', 
        default='cpu_use',
        choices=['cpu_use', 'mem_use', 'cpu_req', 'mem_req', 
                 'cpu_lim', 'mem_lim', 'restarts'],
        help='Sort by field (default: cpu_use)'
    )
    parser.add_argument(
        '-l', '--limit', 
        type=int, 
        default=15,
        help='Show top N pods (default: 15)'
    )
    parser.add_argument(
        '-n', '--namespace',
        help='Filter by namespace'
    )
    parser.add_argument(
        '-t', '--type',
        help='Filter by controller type'
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='Display once and exit (no live updates)'
    )
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Hide cluster summary'
    )
    parser.add_argument(
        '--no-controller',
        action='store_true',
        help='Hide controller type summary'
    )
    parser.add_argument(
        '--no-problems',
        action='store_true',
        help='Hide problem pods section'
    )
    
    args = parser.parse_args()
    
    # Show help
    if args.help:
        print_help()
        sys.exit(0)
    
    # Create dashboard
    dashboard = K8sDashboard()
    
    # Prepare kwargs
    kwargs = {
        'sort_by': args.sort_by,
        'limit': args.limit,
        'show_summary': not args.no_summary,
        'show_controller_summary': not args.no_controller,
        'show_problems': not args.no_problems,
        'namespace': args.namespace,
        'controller_type': args.type
    }
    
    # Display
    if args.once:
        dashboard.display_once(**kwargs)
    else:
        dashboard.watch(interval=args.interval, **kwargs)

if __name__ == "__main__":
    main()
