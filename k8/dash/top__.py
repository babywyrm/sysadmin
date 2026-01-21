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
        self.apps_v1 = client.AppsV1Api()
        self.console = Console()
    
    def get_cluster_info(self):
        """Get basic cluster information"""
        nodes = self.v1.list_node()
        namespaces = self.v1.list_namespace()
        pods = self.v1.list_pod_for_all_namespaces()
        
        return {
            'nodes': len(nodes.items),
            'namespaces': len(namespaces.items),
            'total_pods': len(pods.items),
            'running_pods': sum(
                1 for p in pods.items if p.status.phase == 'Running'
            )
        }
    
    def get_unhealthy_pods(self):
        """Find pods that are not Running or Succeeded"""
        pods = self.v1.list_pod_for_all_namespaces()
        unhealthy = []
        
        for pod in pods.items:
            if pod.status.phase not in ['Running', 'Succeeded']:
                restart_count = 0
                if pod.status.container_statuses:
                    restart_count = sum(
                        cs.restart_count 
                        for cs in pod.status.container_statuses
                    )
                
                unhealthy.append({
                    'namespace': pod.metadata.namespace,
                    'name': pod.metadata.name,
                    'status': pod.status.phase,
                    'restarts': restart_count,
                    'node': pod.spec.node_name or 'N/A'
                })
        
        return unhealthy
    
    def get_high_restart_pods(self, threshold=3):
        """Find pods with high restart counts"""
        pods = self.v1.list_pod_for_all_namespaces()
        high_restarts = []
        
        for pod in pods.items:
            if pod.status.container_statuses:
                for container in pod.status.container_statuses:
                    if container.restart_count > threshold:
                        reason = 'Unknown'
                        if container.last_state.terminated:
                            reason = container.last_state.terminated.reason
                        
                        high_restarts.append({
                            'namespace': pod.metadata.namespace,
                            'name': pod.metadata.name,
                            'container': container.name,
                            'restarts': container.restart_count,
                            'reason': reason
                        })
        
        return sorted(
            high_restarts, 
            key=lambda x: x['restarts'], 
            reverse=True
        )
    
    def get_recent_events(self, limit=10):
        """Get recent cluster events"""
        events = self.v1.list_event_for_all_namespaces()
        
        sorted_events = sorted(
            events.items,
            key=lambda x: x.last_timestamp or datetime.min,
            reverse=True
        )
        
        recent = []
        for event in sorted_events[:limit]:
            msg = event.message
            if len(msg) > 50:
                msg = msg[:50] + '...'
            
            recent.append({
                'namespace': event.metadata.namespace,
                'object': f"{event.involved_object.kind}/"
                         f"{event.involved_object.name}",
                'reason': event.reason,
                'message': msg,
                'type': event.type
            })
        
        return recent
    
    def get_node_status(self):
        """Get node health information"""
        nodes = self.v1.list_node()
        node_info = []
        
        for node in nodes.items:
            conditions = {}
            for c in node.status.conditions:
                conditions[c.type] = c.status
            
            node_info.append({
                'name': node.metadata.name,
                'status': conditions.get('Ready', 'Unknown'),
                'cpu': node.status.capacity.get('cpu', 'N/A'),
                'memory': node.status.capacity.get('memory', 'N/A'),
                'pods': node.status.capacity.get('pods', 'N/A')
            })
        
        return node_info
    
    def create_cluster_overview(self):
        """Create cluster overview table"""
        info = self.get_cluster_info()
        
        table = Table(title="Cluster Overview", show_header=False)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Nodes", str(info['nodes']))
        table.add_row("Namespaces", str(info['namespaces']))
        table.add_row("Total Pods", str(info['total_pods']))
        table.add_row("Running Pods", str(info['running_pods']))
        
        return table
    
    def create_unhealthy_table(self):
        """Create unhealthy pods table"""
        unhealthy = self.get_unhealthy_pods()
        
        table = Table(title="Unhealthy Pods", show_lines=True)
        table.add_column("Namespace", style="cyan")
        table.add_column("Pod", style="magenta")
        table.add_column("Status", style="red")
        table.add_column("Restarts", justify="right", style="yellow")
        table.add_column("Node", style="blue")
        
        if unhealthy:
            for pod in unhealthy[:10]:
                table.add_row(
                    pod['namespace'],
                    pod['name'],
                    pod['status'],
                    str(pod['restarts']),
                    pod['node']
                )
        else:
            table.add_row("", "All pods healthy", "", "", "")
        
        return table
    
    def create_restart_table(self):
        """Create high restart pods table"""
        restarts = self.get_high_restart_pods()
        
        table = Table(title="High Restart Pods", show_lines=True)
        table.add_column("Namespace", style="cyan")
        table.add_column("Pod", style="magenta")
        table.add_column("Container", style="blue")
        table.add_column("Restarts", justify="right", style="red")
        table.add_column("Last Reason", style="yellow")
        
        if restarts:
            for pod in restarts[:10]:
                table.add_row(
                    pod['namespace'],
                    pod['name'],
                    pod['container'],
                    str(pod['restarts']),
                    pod['reason']
                )
        else:
            table.add_row("", "No high restart pods", "", "", "")
        
        return table
    
    def create_events_table(self):
        """Create recent events table"""
        events = self.get_recent_events()
        
        table = Table(title="Recent Events", show_lines=True)
        table.add_column("Namespace", style="cyan")
        table.add_column("Object", style="magenta")
        table.add_column("Reason", style="yellow")
        table.add_column("Message", style="white")
        table.add_column("Type", style="green")
        
        for event in events:
            type_color = "red" if event['type'] == 'Warning' else "green"
            type_text = f"[{type_color}]{event['type']}[/{type_color}]"
            
            table.add_row(
                event['namespace'],
                event['object'],
                event['reason'],
                event['message'],
                type_text
            )
        
        return table
    
    def create_node_table(self):
        """Create node status table"""
        nodes = self.get_node_status()
        
        table = Table(title="Node Status", show_lines=True)
        table.add_column("Node Name", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("CPU", justify="right", style="yellow")
        table.add_column("Memory", justify="right", style="magenta")
        table.add_column("Max Pods", justify="right", style="blue")
        
        for node in nodes:
            if node['status'] == 'True':
                status_text = "[green]Ready[/green]"
            else:
                status_text = "[red]NotReady[/red]"
            
            table.add_row(
                node['name'],
                status_text,
                node['cpu'],
                node['memory'],
                node['pods']
            )
        
        return table
    
    def display_full_dashboard(self):
        """Display the complete dashboard"""
        self.console.clear()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.console.print(
            Panel(
                "[bold cyan]Kubernetes Cluster Dashboard[/bold cyan]\n"
                f"[dim]{timestamp}[/dim]",
                style="bold blue"
            )
        )
        
        self.console.print(self.create_cluster_overview())
        self.console.print()
        
        self.console.print(self.create_node_table())
        self.console.print()
        
        self.console.print(self.create_unhealthy_table())
        self.console.print()
        
        self.console.print(self.create_restart_table())
        self.console.print()
        
        self.console.print(self.create_events_table())
    
    def watch_dashboard(self, interval=5):
        """Live updating dashboard"""
        try:
            while True:
                self.display_full_dashboard()
                time.sleep(interval)
        except KeyboardInterrupt:
            self.console.print("\n[red]Dashboard stopped[/red]")

if __name__ == "__main__":
    dashboard = K8sDashboard()
    dashboard.watch_dashboard(interval=5)
