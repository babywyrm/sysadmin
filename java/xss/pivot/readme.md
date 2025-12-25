# blind-browser-enum

A **methodology-focused toolkit** for studying semi-blind internal service
enumeration via browser-based pivots (e.g. stored XSS).

##
##

## What This Is

- A human-in-the-loop research aid
- A way to structure blind browser enumeration
- A declarative, stage-based workflow
- Designed for modern internal service architectures
  (Kubernetes, service meshes, internal APIs)

---

## What This Is NOT

- Not a scanner
- Not an exploit framework
- Not copy-paste usable against any target
- Not specific to any HTB box

---

## Core Ideas Demonstrated

- Blind / semi-blind feedback loops
- Browser-based internal pivots
- Trust-boundary collapse at the browser layer
- Incremental enumeration via diagnostics
- Header-based identity assumptions

---

## Non-Weaponization Notice

This repository **intentionally omits**:

- Real hostnames
- Real ports
- Real endpoint paths
- Real headers
- Real payload mutations

All identifiers are symbolic placeholders.

Successful use of these techniques **requires**:
- Manual enumeration
- Architectural reasoning
- Target-specific discovery

---

## Intended Audience

- Security researchers
- Red teamers, Red v Blue teamers
- People studying modern web + Kubernetes trust failures

---
