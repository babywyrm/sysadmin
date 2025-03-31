/**
 * Security Manager - A complex example demonstrating namespace UID 0 vulnerabilities
 * Compile: gcc -o security_manager security_manager.c -lcap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <sys/capability.h>
#include <errno.h>

#define CONFIG_PATH "/etc/security_manager.conf"
#define LOG_FILE "/var/log/security_manager.log"
#define MAX_CMD_LEN 1024

// Function prototypes
int check_admin_privileges(void);
int validate_environment(void);
void log_activity(const char *action, int success);
void run_security_check(void);
void update_system(void);
void generate_report(void);
void execute_command(const char *cmd);
int drop_privileges(void);
int restore_privileges(void);

// Global variables
uid_t original_uid;
gid_t original_gid;
int privilege_dropped = 0;

int main(int argc, char *argv[]) {
    int choice = 0;
    
    // Store original UID/GID
    original_uid = getuid();
    original_gid = getgid();
    
    printf("Security Manager v2.1.3\n");
    printf("========================\n");
    
    // Initial root check
    if (check_admin_privileges() != 0) {
        printf("Error: Administrative privileges required.\n");
        return 1;
    }
    
    // Environment validation
    if (validate_environment() != 0) {
        printf("Error: Invalid environment configuration.\n");
        return 1;
    }
    
    printf("Security operations menu:\n");
    printf("1. Run security audit\n");
    printf("2. Update security components\n");
    printf("3. Generate security report\n");
    printf("4. Exit\n");
    printf("Select an operation: ");
    
    if (scanf("%d", &choice) != 1) {
        printf("Invalid input.\n");
        return 1;
    }
    
    // Clear input buffer
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    // Process menu selection
    switch (choice) {
        case 1:
            log_activity("security_audit", 1);
            run_security_check();
            break;
        case 2:
            log_activity("system_update", 1);
            update_system();
            break;
        case 3:
            log_activity("report_generation", 1);
            generate_report();
            break;
        case 4:
            printf("Exiting security manager.\n");
            break;
        default:
            printf("Invalid option selected.\n");
            break;
    }
    
    return 0;
}

/**
 * Check if the user has administrative privileges.
 * Returns 0 if user has admin privileges, non-zero otherwise.
 */
int check_admin_privileges(void) {
    // Check if running as root (UID 0)
    if (getuid() != 0) {
        return 1;
    }
    
    // Additional security check - verify real and effective UIDs
    if (getuid() != geteuid()) {
        printf("Warning: Real and effective UIDs do not match.\n");
        // Continue anyway - this is a vulnerability
    }
    
    printf("[+] Administrative privileges confirmed\n");
    return 0;
}

/**
 * Validate the execution environment for security purposes.
 * Returns 0 if environment is valid, non-zero otherwise.
 */
int validate_environment(void) {
    struct stat st;
    const char *security_level;
    FILE *config;
    
    // Check if config file exists and is readable
    if (stat(CONFIG_PATH, &st) != 0) {
        printf("Warning: Configuration file not found. Using defaults.\n");
        // Continue anyway - this is a vulnerability
    }
    
    // Check environment variable for security level
    security_level = getenv("SECURITY_LEVEL");
    if (!security_level) {
        printf("Warning: SECURITY_LEVEL not set. Using 'standard'.\n");
        // Continue anyway - this is a vulnerability
    } else {
        printf("[+] Security level: %s\n", security_level);
    }
    
    // Check for custom security script (vulnerable to PATH manipulation)
    if (security_level && strcmp(security_level, "high") == 0) {
        printf("[+] Running enhanced security validation...\n");
        system("security_validator");  // Vulnerable to PATH manipulation
    }
    
    printf("[+] Environment validation completed\n");
    return 0;
}

/**
 * Log activity to the security log file.
 */
void log_activity(const char *action, int success) {
    FILE *log_file;
    time_t now;
    char timestamp[64];
    
    // Get current time
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Try to open log file
    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        // Try to create log directory and file in /tmp if main log fails
        // This is a vulnerability - creates files in world-writable location
        char tmp_log[100];
        snprintf(tmp_log, sizeof(tmp_log), "/tmp/security_manager_%d.log", getuid());
        log_file = fopen(tmp_log, "a");
        if (!log_file) {
            perror("Error opening log file");
            return;
        }
    }
    
    // Write log entry
    fprintf(log_file, "[%s] User ID: %d, Action: %s, Success: %d\n",
            timestamp, getuid(), action, success);
    
    fclose(log_file);
}

/**
 * Run a security check on the system.
 */
void run_security_check(void) {
    // Another UID check - redundant but shows layered checks
    if (getuid() != 0) {
        printf("Error: Root privileges required for security check.\n");
        return;
    }
    
    printf("Running comprehensive security check...\n");
    
    // Drop privileges temporarily for safer execution
    if (drop_privileges() != 0) {
        printf("Warning: Failed to drop privileges. Continuing anyway.\n");
        // Continue anyway - another vulnerability
    }
    
    // Multiple vulnerable system calls using relative paths
    system("find_vulnerable_packages");  // Vulnerable to PATH manipulation
    system("verify_system_integrity");   // Vulnerable to PATH manipulation
    
    // Try to restore privileges
    if (privilege_dropped) {
        if (restore_privileges() != 0) {
            printf("Error: Failed to restore privileges.\n");
            exit(1);
        }
    }
    
    printf("Security check completed.\n");
}

/**
 * Update system security components.
 */
void update_system(void) {
    char command[MAX_CMD_LEN];
    char component[100];
    
    // Another UID check
    if (getuid() != 0) {
        printf("Error: Root privileges required for system update.\n");
        return;
    }
    
    printf("Enter security component to update: ");
    if (fgets(component, sizeof(component), stdin) == NULL) {
        printf("Error reading input.\n");
        return;
    }
    
    // Remove newline character
    component[strcspn(component, "\n")] = '\0';
    
    // Attempt to sanitize input - but imperfectly
    if (strchr(component, ';') || strchr(component, '|') || strchr(component, '&')) {
        printf("Invalid component name.\n");
        return;
    }
    
    // Command injection vulnerability - incomplete sanitization
    snprintf(command, sizeof(command), "update_security_component %s", component);
    printf("Executing: %s\n", command);
    
    // Execute command
    execute_command(command);
    
    printf("Update completed.\n");
}

/**
 * Generate a security report.
 */
void generate_report(void) {
    char report_path[256];
    char *custom_path;
    
    // Check if we have a custom report path from environment
    custom_path = getenv("REPORT_PATH");
    if (custom_path) {
        // Path traversal vulnerability - no validation of custom_path
        strncpy(report_path, custom_path, sizeof(report_path) - 1);
        report_path[sizeof(report_path) - 1] = '\0';
    } else {
        strcpy(report_path, "/tmp/security_report.txt");
    }
    
    printf("Generating security report to: %s\n", report_path);
    
    // Run report generation commands
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "generate_security_report > %s", report_path);
    execute_command(cmd);
    
    printf("Report generated successfully.\n");
}

/**
 * Execute a command with proper privilege handling.
 */
void execute_command(const char *cmd) {
    printf("Executing command: %s\n", cmd);
    
    // Check for custom executor in environment
    char *executor = getenv("COMMAND_EXECUTOR");
    if (executor) {
        // Vulnerability - blindly using environment variable
        char full_cmd[MAX_CMD_LEN + 256];
        snprintf(full_cmd, sizeof(full_cmd), "%s \"%s\"", executor, cmd);
        system(full_cmd);
    } else {
        // Direct system call - still vulnerable to PATH manipulation
        system(cmd);
    }
}

/**
 * Drop privileges temporarily for safer execution.
 * Returns 0 on success, non-zero on failure.
 */
int drop_privileges(void) {
    struct passwd *pw;
    
    // Only attempt to drop privileges if we're root
    if (getuid() != 0) {
        return 0;  // Nothing to do
    }
    
    // Get nobody user info
    pw = getpwnam("nobody");
    if (!pw) {
        perror("Error getting nobody user info");
        return 1;
    }
    
    // Drop privileges to nobody
    if (setgid(pw->pw_gid) != 0) {
        perror("Error dropping group privileges");
        return 1;
    }
    
    if (setuid(pw->pw_uid) != 0) {
        perror("Error dropping user privileges");
        return 1;
    }
    
    privilege_dropped = 1;
    printf("[+] Privileges dropped to nobody for safer execution\n");
    return 0;
}

/**
 * Attempt to restore privileges (this should fail in normal circumstances,
 * but might work in a namespace with SETUID capability).
 * Returns 0 on success, non-zero on failure.
 */
int restore_privileges(void) {
    // Attempt to restore original GID
    if (setgid(original_gid) != 0) {
        perror("Failed to restore GID");
        return 1;
    }
    
    // Attempt to restore original UID
    if (setuid(original_uid) != 0) {
        perror("Failed to restore UID");
        return 1;
    }
    
    printf("[+] Original privileges restored\n");
    privilege_dropped = 0;
    return 0;
}
