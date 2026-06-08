# Security Check Helper

This directory contains a small Go host-security helper and related shell notes.

Dependency pins are kept reasonably current, but the directory is not currently
a clean single-package Go module: `core.go` and `osinfo.go` use different
package names. Split or reorganize the package before treating it as a buildable
tool.
