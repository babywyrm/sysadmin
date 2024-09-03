//
package main
//

import (
        "context"
        "log"
        "os"
        "path/filepath"

        "github.com/hanwen/go-fuse/v2/fs"
        "github.com/hanwen/go-fuse/v2/fuse"
)

type SecurityTestFS struct {
        fs.Inode
}

func (f *SecurityTestFS) OnAdd(ctx context.Context, mountPoint string) {
        log.Println("Filesystem mounted, running security tests...")
        runSecurityTests(mountPoint)
}

// RunSecurityTests performs a set of security tests on the mounted filesystem.
func runSecurityTests(mountPoint string) {
        log.Println("Running security tests...")

        testFileCreation(mountPoint)

        log.Println("Security tests completed.")
}

// Test file creation and access permissions
func testFileCreation(mountPoint string) {
        log.Println("Testing file creation and permissions...")

        // Use the mount point directory to create a test file
        filePath := filepath.Join(mountPoint, "testfile")

        // Create a file
        f, err := os.Create(filePath)
        if err != nil {
                log.Fatalf("Failed to create file: %v", err)
        }
        f.Close()

        // Set permissions to read-only
        err = os.Chmod(filePath, 0444)
        if err != nil {
                log.Fatalf("Failed to set file permissions: %v", err)
        }

        // Attempt to write to the file, should fail
        f, err = os.OpenFile(filePath, os.O_WRONLY, 0666)
        if err != nil {
                log.Println("Permission check passed: Cannot write to read-only file.")
        } else {
                log.Println("Permission check failed: Able to write to read-only file.")
                f.Close()
        }

        // Clean up
        err = os.Remove(filePath)
        if err != nil {
                log.Fatalf("Failed to remove test file: %v", err)
        }
}

func main() {
        root := &SecurityTestFS{}

        // Define the mount point for the FUSE filesystem
        mountPoint := "mountpoint"
        opts := &fs.Options{
                MountOptions: fuse.MountOptions{
                        AllowOther: true, // Allow non-root users to access the mount point
                },
        }

        // Mount the FUSE filesystem
        server, err := fs.Mount(mountPoint, root, opts)
        if err != nil {
                log.Fatalf("Mount failed: %v\n", err)
        }

        // Call security tests after mounting
        root.OnAdd(context.Background(), mountPoint)

        log.Printf("Filesystem mounted at %s. Press Ctrl+C to unmount.\n", mountPoint)

        // Wait for the server to finish (no value returned)
        server.Wait()
}
