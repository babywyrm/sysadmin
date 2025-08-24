"""
Modern Kubernetes exec example using Busybox container, (..testing mode..)
Demonstrates both simple command execution and interactive sessions.
"""

import logging
import time
from typing import Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KubernetesExecDemo:
    def __init__(self, namespace: str = "default"):
        self.namespace = namespace
        self.pod_name = "busybox-test"
        self.core_v1 = client.CoreV1Api()

    def ensure_pod_exists(self) -> None:
        """Create pod if it doesn't exist and wait for it to be ready."""
        try:
            pod = self.core_v1.read_namespaced_pod(
                name=self.pod_name, namespace=self.namespace
            )
            logger.info(f"Pod {self.pod_name} already exists")
            return
        except ApiException as e:
            if e.status != 404:
                logger.error(f"Unexpected error checking pod: {e}")
                raise

        logger.info(f"Creating pod {self.pod_name}...")
        pod_spec = client.V1Pod(
            api_version="v1",
            kind="Pod",
            metadata=client.V1ObjectMeta(name=self.pod_name),
            spec=client.V1PodSpec(
                containers=[
                    client.V1Container(
                        name="sleep",
                        image="busybox:latest",
                        args=[
                            "/bin/sh",
                            "-c",
                            "while true; do date; sleep 5; done"
                        ]
                    )
                ],
                restart_policy="Never"
            )
        )

        self.core_v1.create_namespaced_pod(
            body=pod_spec, namespace=self.namespace
        )

        # Wait for pod to be ready
        self._wait_for_pod_ready()
        logger.info("Pod created and ready")

    def _wait_for_pod_ready(self, timeout: int = 60) -> None:
        """Wait for pod to be in Running state."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                pod = self.core_v1.read_namespaced_pod(
                    name=self.pod_name, namespace=self.namespace
                )
                if pod.status.phase == "Running":
                    return
                elif pod.status.phase == "Failed":
                    raise RuntimeError(f"Pod {self.pod_name} failed to start")
                
                logger.info(f"Pod status: {pod.status.phase}, waiting...")
                time.sleep(2)
            except ApiException as e:
                logger.error(f"Error checking pod status: {e}")
                raise

        raise TimeoutError(f"Pod {self.pod_name} did not become ready within {timeout}s")

    def execute_simple_command(self) -> None:
        """Execute a simple command and capture output."""
        logger.info("Executing simple command...")
        
        command = [
            '/bin/sh',
            '-c',
            'echo "This goes to stdout"; echo "This goes to stderr" >&2; echo "Exit code: $?"'
        ]

        try:
            response = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                self.pod_name,
                self.namespace,
                command=command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False
            )
            logger.info(f"Command output: {response}")
        except ApiException as e:
            logger.error(f"Error executing command: {e}")
            raise

    def execute_interactive_session(self) -> None:
        """Execute commands in an interactive session."""
        logger.info("Starting interactive session...")
        
        try:
            exec_stream = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                self.pod_name,
                self.namespace,
                command=['/bin/sh'],
                stderr=True,
                stdin=True,
                stdout=True,
                tty=False,
                _preload_content=False
            )

            commands = [
                "echo 'Hello from interactive session'",
                "whoami",
                "date",
                "pwd",
                "ls -la /tmp"
            ]

            # Execute commands interactively
            for cmd in commands:
                logger.info(f"Executing: {cmd}")
                exec_stream.write_stdin(f"{cmd}\n")
                time.sleep(0.5)  # Give command time to execute
                
                # Read any available output
                if exec_stream.peek_stdout():
                    stdout = exec_stream.read_stdout()
                    logger.info(f"STDOUT: {stdout.strip()}")
                
                if exec_stream.peek_stderr():
                    stderr = exec_stream.read_stderr()
                    logger.info(f"STDERR: {stderr.strip()}")

            # Final cleanup
            exec_stream.write_stdin("exit\n")
            exec_stream.close()
            
        except ApiException as e:
            logger.error(f"Error in interactive session: {e}")
            raise

    def cleanup(self) -> None:
        """Clean up created resources."""
        try:
            self.core_v1.delete_namespaced_pod(
                name=self.pod_name, 
                namespace=self.namespace,
                body=client.V1DeleteOptions()
            )
            logger.info(f"Pod {self.pod_name} deleted")
        except ApiException as e:
            if e.status != 404:
                logger.error(f"Error deleting pod: {e}")


def main():
    """Main execution function."""
    # Load kubernetes config
    try:
        config.load_incluster_config()  # For running inside cluster
        logger.info("Loaded in-cluster config")
    except config.ConfigException:
        config.load_kube_config()  # For running outside cluster
        logger.info("Loaded kube config")

    demo = KubernetesExecDemo()
    
    try:
        # Ensure pod exists and is ready
        demo.ensure_pod_exists()
        
        # Demonstrate simple command execution
        demo.execute_simple_command()
        
        # Demonstrate interactive session
        demo.execute_interactive_session()
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise
    finally:
        # Cleanup (optional - comment out if you want to keep the pod)
        # demo.cleanup()
        pass


if __name__ == '__main__':
    main()
