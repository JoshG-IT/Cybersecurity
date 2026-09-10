# Azure Portal Training Guide

## Purpose

The Azure Portal is the graphical interface for Azure administration.

I do not consider the portal a beginner-only tool.

It is useful for discovering unfamiliar services, understanding relationships, and validating CLI findings.

## Best Used For

- Learning an unfamiliar Azure service
- Understanding resource relationships visually
- Viewing complex configuration screens
- Quickly validating CLI findings
- Discovering property names
- Finding settings not easily exposed through CLI wrappers

## Investigation Strategy

Use the portal intentionally.

```text
Portal discovery
      |
      v
Understand object/property
      |
      v
Find CLI/API equivalent
      |
      v
Repeat through command line
```

## Avoid

Do not rely entirely on clicking through the portal without understanding:

- Object IDs
- Resource IDs
- RBAC scope
- APIs
- Resource providers
- Underlying Azure objects

## Goal

Use the portal as another investigation interface rather than as a replacement for understanding Azure.
