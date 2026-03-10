"""
Modern Kubernetes exec example using a Busybox container.
Demonstrates both simple command execution and interactive sessions.
"""

import logging
import time
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BUSYBOX_IMAGE = "busybox:1.36"


class KubernetesExecDemo:
    def __init__(
        self,
        core_v1: client.CoreV1Api,
        namespace: str = "default",
        pod_name: str = "busybox-exec-demo",
    ):
        self.namespace = namespace
        self.pod_name = pod_name
        self.core_v1 = core_v1

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "KubernetesExecDemo":
        return self

    def __exit__(self, *_) -> None:
        self.cleanup()

    # ------------------------------------------------------------------
    # Pod lifecycle
    # ------------------------------------------------------------------

    def ensure_pod_exists(self) -> None:
        """Create the pod if it doesn't exist, then wait until it is Running."""
        try:
            self.core_v1.read_namespaced_pod(
                name=self.pod_name, namespace=self.namespace
            )
            logger.info("Pod %s already exists", self.pod_name)
            return
        except ApiException as e:
            if e.status != 404:
                logger.error("Unexpected error checking pod: %s", e)
                raise

        logger.info("Creating pod %s ...", self.pod_name)
        pod_spec = client.V1Pod(
            api_version="v1",
            kind="Pod",
            metadata=client.V1ObjectMeta(name=self.pod_name),
            spec=client.V1PodSpec(
                containers=[
                    client.V1Container(
                        name="sleep",
                        image=BUSYBOX_IMAGE,
                        args=[
                            "/bin/sh",
                            "-c",
                            "while true; do date; sleep 5; done",
                        ],
                    )
                ],
                restart_policy="Never",
            ),
        )

        self.core_v1.create_namespaced_pod(
            body=pod_spec, namespace=self.namespace
        )
        self._wait_for_pod_ready()
        logger.info("Pod %s is ready", self.pod_name)

    def _wait_for_pod_ready(self, timeout: int = 60) -> None:
        """Poll until the pod reaches Running state or the timeout expires."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pod = self.core_v1.read_namespaced_pod(
                    name=self.pod_name, namespace=self.namespace
                )
                phase = pod.status.phase
                if phase == "Running":
                    return
                if phase == "Failed":
                    raise RuntimeError(
                        f"Pod {self.pod_name} entered Failed state"
                    )
                logger.info("Pod phase: %s — waiting...", phase)
                time.sleep(2)
            except ApiException as e:
                logger.error("Error polling pod status: %s", e)
                raise

        raise TimeoutError(
            f"Pod {self.pod_name} did not become Ready within {timeout}s"
        )

    def cleanup(self) -> None:
        """Delete the pod, ignoring 404 (already gone)."""
        try:
            self.core_v1.delete_namespaced_pod(
                name=self.pod_name,
                namespace=self.namespace,
                body=client.V1DeleteOptions(grace_period_seconds=0),
            )
            logger.info("Pod %s deleted", self.pod_name)
        except ApiException as e:
            if e.status != 404:
                logger.error("Error deleting pod: %s", e)

    # ------------------------------------------------------------------
    # Exec helpers
    # ------------------------------------------------------------------

    def execute_simple_command(self) -> None:
        """Run a one-shot command and log stdout/stderr separately."""
        logger.info("Executing simple command...")
        command = [
            "/bin/sh",
            "-c",
            (
                'echo "This goes to stdout"; '
                'echo "This goes to stderr" >&2'
            ),
        ]

        try:
            exec_stream = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                self.pod_name,
                self.namespace,
                command=command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
                _preload_content=False,  # needed to read stdout/stderr separately
            )

            stdout_buf: list[str] = []
            stderr_buf: list[str] = []

            while exec_stream.is_open():
                exec_stream.update(timeout=5)
                if exec_stream.peek_stdout():
                    stdout_buf.append(exec_stream.read_stdout())
                if exec_stream.peek_stderr():
                    stderr_buf.append(exec_stream.read_stderr())

            exec_stream.close()

            if stdout_buf:
                logger.info("STDOUT: %s", "".join(stdout_buf).strip())
            if stderr_buf:
                logger.info("STDERR: %s", "".join(stderr_buf).strip())

        except ApiException as e:
            logger.error("Error executing command: %s", e)
            raise

    def execute_interactive_session(self) -> None:
        """Send a sequence of commands over a persistent shell session."""
        logger.info("Starting interactive session...")

        commands = [
            "echo 'Hello from interactive session'",
            "whoami",
            "date",
            "pwd",
            "ls -la /tmp",
        ]

        try:
            exec_stream = stream(
                self.core_v1.connect_get_namespaced_pod_exec,
                self.pod_name,
                self.namespace,
                command=["/bin/sh"],
                stderr=True,
                stdin=True,
                stdout=True,
                tty=False,
                _preload_content=False,
            )

            for cmd in commands:
                logger.info("Executing: %s", cmd)
                # Use a sentinel so we know exactly when output is done.
                sentinel = f"__DONE_{cmd.split()[0].upper()}__"
                exec_stream.write_stdin(f"{cmd}; echo {sentinel}\n")
                self._read_until_sentinel(exec_stream, sentinel)

            exec_stream.write_stdin("exit\n")
            exec_stream.close()

        except ApiException as e:
            logger.error("Error in interactive session: %s", e)
            raise

    def _read_until_sentinel(
        self, exec_stream, sentinel: str, timeout: float = 10.0
    ) -> None:
        """Drain output lines until the sentinel marker is seen."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            exec_stream.update(timeout=1)
            if exec_stream.peek_stdout():
                chunk = exec_stream.read_stdout()
                for line in chunk.splitlines():
                    if sentinel in line:
                        return
                    if line.strip():
                        logger.info("STDOUT: %s", line)
            if exec_stream.peek_stderr():
                chunk = exec_stream.read_stderr()
                for line in chunk.splitlines():
                    if line.strip():
                        logger.info("STDERR: %s", line)

        logger.warning("Timed out waiting for sentinel: %s", sentinel)


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------


def _load_kube_config() -> None:
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster config")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kube config")


def main() -> None:
    _load_kube_config()

    # Pass the API client in — config must be loaded first.
    with KubernetesExecDemo(core_v1=client.CoreV1Api()) as demo:
        demo.ensure_pod_exists()
        demo.execute_simple_command()
        demo.execute_interactive_session()
        # cleanup() is called automatically on __exit__


if __name__ == "__main__":
    main()
