# Google Cloud Interface Training Guide

Google Cloud administration and security investigation can be performed through multiple interfaces.

No single interface exposes every capability.

These guides document how I am learning to select the appropriate interface based on what I am investigating, querying, or analyzing.

## Interface Map

| Interface | Best For | Main Skill Developed |
|---|---|---|
| gcloud CLI | Google Cloud resources | Resource investigation |
| Google Cloud APIs | Direct service interaction | API investigation |
| Cloud Logging | Logs and audit events | Security analysis |
| Cloud Asset Inventory | Resource and IAM inventory at scale | Cloud reconnaissance |
| Google Cloud Console | Visual exploration and validation | Architecture awareness |

---

## The Three Questions

When approaching a task, determine:

### 1. What am I interacting with?

Examples:

- Google Cloud organization
- folder
- project
- IAM principal
- IAM role
- IAM policy binding
- service account
- Compute Engine instance
- VPC
- Cloud Storage bucket
- audit log
- security event
- Google Cloud resource

### 2. Which interface is best suited to it?

Examples:

```text
Google Cloud resource
→ gcloud CLI

Direct service or API data
→ Google Cloud APIs

Audit logs or security events
→ Cloud Logging

Large resource or IAM inventory
→ Cloud Asset Inventory

Visual exploration or validation
→ Google Cloud Console
```

### 3. What service/API is underneath the interface?

Examples:

```text
gcloud CLI
→ Google Cloud service APIs

Google Cloud APIs
→ Individual Google Cloud services

Cloud Logging
→ Cloud Logging API

Cloud Asset Inventory
→ Cloud Asset Inventory API

Google Cloud Console
→ Google Cloud service APIs
```

Understanding the underlying service is more important than memorizing the interface.

---

## Google Cloud Resource Hierarchy

A key part of investigating Google Cloud is understanding where a resource exists.

```text
Organization
    ↓
Folder
    ↓
Project
    ↓
Resource
```

IAM policies can be applied at different levels of this hierarchy and inherited by resources below them.

During an investigation, I should identify both the resource and its scope.

---

## Learning Priority

My current priority:

```text
1. gcloud CLI
2. Google Cloud APIs
3. Cloud Logging
4. Cloud Asset Inventory
5. Google Cloud Console
```

This is a personal learning priority rather than a requirement of the Mad Hat investigations.

The Google Cloud Console remains useful throughout the learning process. I use the investigations as opportunities to practice CLI, API, logging, and inventory-based approaches when appropriate.

The goal is to understand when each interface is useful and how the different interfaces relate to the underlying Google Cloud services.
