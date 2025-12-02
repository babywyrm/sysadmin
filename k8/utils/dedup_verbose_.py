#!/usr/bin/env python3
"""
Kubernetes Pod Deduplication & Container Image Analysis Tool ..beta..

A comprehensive analysis tool for Kubernetes clusters to identify pod
distribution patterns, workload deduplication opportunities, and container
image usage statistics.
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import csv


@dataclass
class PodInfo:
    """Represents a Kubernetes pod with normalized metadata."""
    name: str
    namespace: str
    normalized_name: str
    image: str
    container_count: int
    labels: Dict[str, str] = field(default_factory=dict)
    node: str = ""
    phase: str = ""


@dataclass
class WorkloadStats:
    """Statistics for a normalized workload."""
    name: str
    namespace: str
    replica_count: int
    images: Set[str] = field(default_factory=set)
    pods: List[str] = field(default_factory=list)


@dataclass
class ImageStats:
    """Statistics for a container image."""
    image: str
    workload_count: int
    pod_count: int
    workloads: Set[str] = field(default_factory=set)


@dataclass
class AnalysisReport:
    """Complete analysis report structure."""
    timestamp: str
    namespace: Optional[str]
    total_pods: int
    unique_workloads: int
    deduplication_ratio: float
    unique_images: int
    total_namespaces: int
    shared_images: List[ImageStats]
    multi_replica_workloads: List[WorkloadStats]
    pattern_matches: Dict[str, int] = field(default_factory=dict)


class KubernetesAnalyzer:
    """Main analyzer class for Kubernetes cluster analysis."""
    
    # Regex patterns for normalization
    REPLICA_HASH_PATTERN = re.compile(r'-[a-z0-9]{8,10}(-[a-z0-9]{5})?$')
    NUMBERED_SUFFIX_PATTERN = re.compile(r'-\d+-[a-z]+$')
    WORKER_PATTERN = re.compile(
        r'-(taskmanager|worker|job)(-\d+)?(-\d+)?$'
    )
    ORDINAL_PATTERN = re.compile(r'-\d+$')
    VERSION_PATTERN = re.compile(r'-\d+-\d+$')
    
    def __init__(
        self,
        kubectl_cmd: str = "kubectl",
        namespace: Optional[str] = None,
        top_n: int = 30,
        replica_threshold: int = 1,
        timeout: int = 60
    ):
        """
        Initialize the analyzer.
        
        Args:
            kubectl_cmd: kubectl command to use
            namespace: Optional namespace to scope analysis
            top_n: Number of top results to show
            replica_threshold: Minimum replica count for reporting
            timeout: Timeout for kubectl commands in seconds
        """
        self.kubectl_cmd = self._validate_kubectl_cmd(kubectl_cmd)
        self.namespace = namespace
        self.top_n = top_n
        self.replica_threshold = replica_threshold
        self.timeout = timeout
        self.pods_data: Dict = {}
    
    @staticmethod
    def _validate_kubectl_cmd(kubectl_cmd: str) -> List[str]:
        """
        Validate and parse kubectl command safely.
        
        Args:
            kubectl_cmd: kubectl command string
            
        Returns:
            List of command parts
            
        Raises:
            ValueError: If command contains suspicious characters
        """
        # Security: Only allow alphanumeric, spaces, hyphens, and slashes
        if not re.match(r'^[a-zA-Z0-9\s\-/]+$', kubectl_cmd):
            raise ValueError(
                "Invalid kubectl command: contains unsafe characters"
            )
        
        return kubectl_cmd.split()
    
    def normalize_workload_name(self, pod_name: str) -> str:
        """
        Normalize pod name to workload name by removing transient identifiers.
        
        Args:
            pod_name: Original pod name
            
        Returns:
            Normalized workload name
        """
        name = pod_name
        
        # Remove ReplicaSet/Deployment hash suffixes
        name = self.REPLICA_HASH_PATTERN.sub('', name)
        
        # Normalize numbered suffixes with common patterns
        name = self.NUMBERED_SUFFIX_PATTERN.sub('', name)
        
        # Remove job/worker suffixes
        name = self.WORKER_PATTERN.sub('', name)
        
        # Remove StatefulSet ordinals (preserve version patterns)
        if not self.VERSION_PATTERN.search(name):
            name = self.ORDINAL_PATTERN.sub('', name)
        
        return name
    
    def fetch_pods_data(self) -> Dict:
        """
        Fetch pod data from Kubernetes cluster.
        
        Returns:
            JSON data of pods
            
        Raises:
            subprocess.CalledProcessError: If kubectl command fails
            json.JSONDecodeError: If response is not valid JSON
        """
        cmd = [*self.kubectl_cmd, "get", "pods", "-o", "json"]
        
        if self.namespace:
            cmd.extend(["-n", self.namespace])
        else:
            cmd.append("-A")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=True
            )
            self.pods_data = json.loads(result.stdout)
            return self.pods_data
            
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"kubectl command timed out after {self.timeout}s"
            ) from e
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"kubectl command failed: {e.stderr}"
            ) from e
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Invalid JSON response from kubectl: {e}"
            ) from e
    
    def parse_pods(self) -> List[PodInfo]:
        """
        Parse raw pod data into structured PodInfo objects.
        
        Returns:
            List of PodInfo objects
        """
        pods: List[PodInfo] = []
        
        for item in self.pods_data.get("items", []):
            metadata = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})
            
            name = metadata.get("name", "")
            namespace = metadata.get("namespace", "")
            
            containers = spec.get("containers", [])
            image = containers[0].get("image", "") if containers else ""
            
            pod = PodInfo(
                name=name,
                namespace=namespace,
                normalized_name=self.normalize_workload_name(name),
                image=image,
                container_count=len(containers),
                labels=metadata.get("labels", {}),
                node=spec.get("nodeName", ""),
                phase=status.get("phase", "")
            )
            pods.append(pod)
        
        return pods
    
    def analyze_deduplication(
        self, pods: List[PodInfo]
    ) -> Tuple[int, int, float]:
        """
        Analyze pod deduplication statistics.
        
        Args:
            pods: List of PodInfo objects
            
        Returns:
            Tuple of (total_pods, unique_workloads, ratio)
        """
        total_pods = len(pods)
        
        unique_workloads = len({
            f"{p.namespace}/{p.normalized_name}" for p in pods
        })
        
        ratio = total_pods / unique_workloads if unique_workloads > 0 else 0
        
        return total_pods, unique_workloads, ratio
    
    def analyze_shared_images(self, pods: List[PodInfo]) -> List[ImageStats]:
        """
        Analyze which images are shared across multiple workloads.
        
        Args:
            pods: List of PodInfo objects
            
        Returns:
            List of ImageStats sorted by workload count
        """
        # Map: image -> set of workloads
        image_workloads: Dict[str, Set[str]] = defaultdict(set)
        image_pod_count: Dict[str, int] = defaultdict(int)
        
        for pod in pods:
            workload_key = f"{pod.namespace}/{pod.normalized_name}"
            image_workloads[pod.image].add(workload_key)
            image_pod_count[pod.image] += 1
        
        stats = [
            ImageStats(
                image=image,
                workload_count=len(workloads),
                pod_count=image_pod_count[image],
                workloads=workloads
            )
            for image, workloads in image_workloads.items()
        ]
        
        return sorted(stats, key=lambda x: x.workload_count, reverse=True)
    
    def analyze_replicas(self, pods: List[PodInfo]) -> List[WorkloadStats]:
        """
        Analyze workloads with multiple replicas.
        
        Args:
            pods: List of PodInfo objects
            
        Returns:
            List of WorkloadStats sorted by replica count
        """
        workloads: Dict[str, WorkloadStats] = {}
        
        for pod in pods:
            key = f"{pod.namespace}/{pod.normalized_name}"
            
            if key not in workloads:
                workloads[key] = WorkloadStats(
                    name=pod.normalized_name,
                    namespace=pod.namespace,
                    replica_count=0,
                    images=set(),
                    pods=[]
                )
            
            workloads[key].replica_count += 1
            workloads[key].images.add(pod.image)
            workloads[key].pods.append(pod.name)
        
        filtered = [
            w for w in workloads.values()
            if w.replica_count > self.replica_threshold
        ]
        
        return sorted(filtered, key=lambda x: x.replica_count, reverse=True)
    
    def analyze_patterns(
        self, pods: List[PodInfo], patterns: List[str]
    ) -> Dict[str, int]:
        """
        Analyze workloads matching specific image patterns.
        
        Args:
            pods: List of PodInfo objects
            patterns: List of patterns to search for
            
        Returns:
            Dictionary mapping pattern to unique workload count
        """
        results: Dict[str, int] = {}
        
        for pattern in patterns:
            workloads = {
                f"{p.namespace}/{p.normalized_name}"
                for p in pods
                if pattern.lower() in p.image.lower()
            }
            results[pattern] = len(workloads)
        
        return results
    
    def generate_report(
        self, pods: List[PodInfo], patterns: Optional[List[str]] = None
    ) -> AnalysisReport:
        """
        Generate complete analysis report.
        
        Args:
            pods: List of PodInfo objects
            patterns: Optional image patterns to analyze
            
        Returns:
            Complete AnalysisReport object
        """
        total_pods, unique_workloads, ratio = self.analyze_deduplication(pods)
        shared_images = self.analyze_shared_images(pods)
        multi_replica = self.analyze_replicas(pods)
        
        pattern_matches = {}
        if patterns:
            pattern_matches = self.analyze_patterns(pods, patterns)
        
        unique_images = len({p.image for p in pods})
        total_namespaces = len({p.namespace for p in pods})
        
        return AnalysisReport(
            timestamp=datetime.now().isoformat(),
            namespace=self.namespace,
            total_pods=total_pods,
            unique_workloads=unique_workloads,
            deduplication_ratio=ratio,
            unique_images=unique_images,
            total_namespaces=total_namespaces,
            shared_images=shared_images[:self.top_n],
            multi_replica_workloads=multi_replica[:20],
            pattern_matches=pattern_matches
        )


class ReportFormatter:
    """Formats analysis reports in various output formats."""
    
    @staticmethod
    def print_header(namespace: Optional[str] = None):
        """Print report header."""
        print("=" * 80)
        print("KUBERNETES POD DEDUPLICATION & IMAGE ANALYSIS REPORT")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if namespace:
            print(f"Namespace: {namespace}")
        else:
            print("Scope: All Namespaces")
        print("=" * 80)
        print()
    
    @staticmethod
    def print_section(title: str):
        """Print section divider."""
        print("━" * 80)
        print(title)
        print("━" * 80)
    
    def format_console(self, report: AnalysisReport, verbose: bool = False):
        """
        Format report for console output.
        
        Args:
            report: AnalysisReport to format
            verbose: Whether to show detailed information
        """
        self.print_header(report.namespace)
        
        # Section 1: Deduplication Analysis
        self.print_section("1. DEDUPLICATION ANALYSIS")
        print(f"Total Pods: {report.total_pods}")
        print(f"Unique Workloads (normalized): {report.unique_workloads}")
        print(f"Deduplication Ratio: {report.deduplication_ratio:.2f}x "
              f"(avg pods per workload)")
        print()
        
        # Section 2: Shared Images
        self.print_section(f"2. SHARED CONTAINER IMAGES (Top {len(report.shared_images)})")
        print("Format: [workload_count] [pod_count] [image_name]")
        print()
        
        for stat in report.shared_images:
            print(f"{stat.workload_count:4d} {stat.pod_count:4d}  "
                  f"{stat.image}")
            
            if verbose and stat.workloads:
                for workload in sorted(stat.workloads)[:5]:
                    print(f"      └─ {workload}")
                if len(stat.workloads) > 5:
                    print(f"      └─ ... and {len(stat.workloads) - 5} more")
        print()
        
        # Section 3: Multi-Replica Workloads
        self.print_section("3. MULTI-REPLICA WORKLOADS")
        print("Format: [replicas] [namespace/workload]")
        print()
        
        for workload in report.multi_replica_workloads:
            print(f"{workload.replica_count:4d}  "
                  f"{workload.namespace}/{workload.name}")
            
            if verbose:
                for img in workload.images:
                    print(f"      └─ {img}")
        print()
        
        # Section 4: Pattern Analysis
        if report.pattern_matches:
            self.print_section("4. PATTERN-BASED IMAGE ANALYSIS")
            for pattern, count in report.pattern_matches.items():
                if count > 0:
                    print(f"Pattern '{pattern}': {count} unique workloads")
            print()
        
        # Section 5: Summary Statistics
        self.print_section("5. SUMMARY STATISTICS")
        print(f"Namespaces: {report.total_namespaces}")
        print(f"Unique Images: {report.unique_images}")
        print(f"Avg Pods/Workload: "
              f"{report.total_pods / report.unique_workloads:.2f}")
        print()
        
        print("=" * 80)
        print("REPORT COMPLETE")
        print("=" * 80)
    
    @staticmethod
    def export_json(report: AnalysisReport, output_file: Path):
        """
        Export report as JSON.
        
        Args:
            report: AnalysisReport to export
            output_file: Path to output file
        """
        data = {
            "timestamp": report.timestamp,
            "namespace": report.namespace,
            "summary": {
                "total_pods": report.total_pods,
                "unique_workloads": report.unique_workloads,
                "deduplication_ratio": report.deduplication_ratio,
                "unique_images": report.unique_images,
                "total_namespaces": report.total_namespaces
            },
            "shared_images": [
                {
                    "image": stat.image,
                    "workload_count": stat.workload_count,
                    "pod_count": stat.pod_count,
                    "workloads": list(stat.workloads)
                }
                for stat in report.shared_images
            ],
            "multi_replica_workloads": [
                {
                    "name": w.name,
                    "namespace": w.namespace,
                    "replica_count": w.replica_count,
                    "images": list(w.images),
                    "pods": w.pods
                }
                for w in report.multi_replica_workloads
            ],
            "pattern_matches": report.pattern_matches
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[INFO] Report exported to {output_file}")
    
    @staticmethod
    def export_csv(report: AnalysisReport, output_file: Path):
        """
        Export shared images as CSV.
        
        Args:
            report: AnalysisReport to export
            output_file: Path to output file
        """
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Image', 'Workload Count', 'Pod Count', 'Workloads'
            ])
            
            for stat in report.shared_images:
                writer.writerow([
                    stat.image,
                    stat.workload_count,
                    stat.pod_count,
                    '; '.join(sorted(stat.workloads))
                ])
        
        print(f"[INFO] CSV exported to {output_file}")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Kubernetes Pod Deduplication & Container Image Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze entire cluster
  %(prog)s

  # Analyze specific namespace
  %(prog)s -n production

  # Use with custom kubectl command
  %(prog)s -k "tsh kubectl" -n staging

  # Search for specific image patterns
  %(prog)s -p nginx,redis,postgres -t 50

  # Export results
  %(prog)s -n prod --json report.json --csv images.csv

  # Verbose output with workload details
  %(prog)s -n staging -v

Environment Variables:
  KUBECTL_CMD    Override kubectl command (default: kubectl)
  K8S_TIMEOUT    kubectl command timeout in seconds (default: 60)
        """
    )
    
    parser.add_argument(
        "-n", "--namespace",
        help="Limit analysis to specific namespace"
    )
    
    parser.add_argument(
        "-k", "--kubectl",
        default="kubectl",
        help="kubectl command to use (default: kubectl)"
    )
    
    parser.add_argument(
        "-t", "--top",
        type=int,
        default=30,
        help="Show top N results (default: 30)"
    )
    
    parser.add_argument(
        "-r", "--replicas",
        type=int,
        default=1,
        help="Min replicas to show (default: 1)"
    )
    
    parser.add_argument(
        "-p", "--patterns",
        help="Comma-separated image patterns to analyze"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information"
    )
    
    parser.add_argument(
        "--json",
        type=Path,
        metavar="FILE",
        help="Export report as JSON"
    )
    
    parser.add_argument(
        "--csv",
        type=Path,
        metavar="FILE",
        help="Export shared images as CSV"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="kubectl command timeout in seconds (default: 60)"
    )
    
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    try:
        # Initialize analyzer
        analyzer = KubernetesAnalyzer(
            kubectl_cmd=args.kubectl,
            namespace=args.namespace,
            top_n=args.top,
            replica_threshold=args.replicas,
            timeout=args.timeout
        )
        
        # Fetch data
        print("[INFO] Fetching pod data from cluster...")
        analyzer.fetch_pods_data()
        
        # Parse pods
        pods = analyzer.parse_pods()
        
        if not pods:
            print("[WARNING] No pods found")
            return
        
        # Parse patterns
        patterns = None
        if args.patterns:
            patterns = [p.strip() for p in args.patterns.split(',')]
        
        # Generate report
        print("[INFO] Analyzing data...")
        report = analyzer.generate_report(pods, patterns)
        
        # Format and display
        formatter = ReportFormatter()
        formatter.format_console(report, verbose=args.verbose)
        
        # Export if requested
        if args.json:
            formatter.export_json(report, args.json)
        
        if args.csv:
            formatter.export_csv(report, args.csv)
        
    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
