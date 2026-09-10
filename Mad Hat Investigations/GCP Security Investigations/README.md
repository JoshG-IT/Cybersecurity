# GCP Security Investigations

Hands-on Google Cloud security investigations completed through the Mad Hat.

**Status:** ⏳ Pending

Investigation cases will be added as the training track becomes available and hands-on investigations are completed.

[← Back to Mad Hat Investigations](../)

# GCP Security Investigations

Hands-on Google Cloud security investigations completed through Mad Hat in live training environments.

Each case represents a hands-on investigation focused on a major Google Cloud security domain.

> Training environment only. Completed investigations demonstrate hands-on analysis and are not presented as production customer incidents.

## Investigation Index

| Case | Investigation | Security Focus | Status |
|---|---|---|:---:|
| **MHI-GCP-001** | Coming Soon | Google Cloud security investigation | ⏳ Pending |

---

## Investigation Interfaces

I use these Google Cloud investigations as an opportunity to become more familiar with the different interfaces available for investigating Google Cloud environments.

My primary learning focus is **gcloud CLI**, while Google Cloud APIs, Cloud Logging, Cloud Asset Inventory, and the Google Cloud Console are used when they are relevant to the investigation.

The goal is not to force every investigation through every interface. Instead, I use each case to learn which interface is best suited to the resource, identity, configuration, log source, or activity being investigated.

| Interface | Best For | Guide |
|---|---|---|
| gcloud CLI | Google Cloud resources, IAM, networking, storage, configuration, and reconnaissance | [gcloud CLI](Guides/gcloud-cli.md) |
| Google Cloud APIs | Direct interaction with Google Cloud services and deeper service investigation | [Google Cloud APIs](Guides/google-cloud-api.md) |
| Cloud Logging | Audit logs, telemetry, security events, and event investigation | [Cloud Logging](Guides/cloud-logging.md) |
| Cloud Asset Inventory | Large-scale resource and IAM discovery across Google Cloud environments | [Cloud Asset Inventory](Guides/cloud-asset-inventory.md) |
| Google Cloud Console | Visual exploration, validation, and tasks better suited to a graphical interface | [Google Cloud Console](Guides/google-cloud-console.md) |

See the complete [Google Cloud Interface Training Guide](Guides/).

---

## Interface Selection

```text
What am I investigating?
        |
        +-- Google Cloud resource, IAM, configuration, or network
        |       |
        |       --> gcloud CLI
        |
        +-- Direct service data or capability not easily exposed
        |   through another interface
        |       |
        |       --> Google Cloud APIs
        |
        +-- Logs, audit events, telemetry, or security activity
        |       |
        |       --> Cloud Logging
        |
        +-- Large-scale resource or IAM inventory
        |       |
        |       --> Cloud Asset Inventory
        |
        +-- Visual exploration, validation, or a task
                better suited to a graphical interface
                |
                --> Google Cloud Console
```

---

## Personal Learning Priority

```text
gcloud CLI
    ↓
Google Cloud APIs
    ↓
Cloud Logging
    ↓
Cloud Asset Inventory
    ↓
Google Cloud Console
```

This reflects my personal learning approach rather than a requirement of the Mad Hat investigations.

The Google Cloud Console remains an important administrative and investigative interface. I use these investigations as opportunities to practice command-line, API, logging, and inventory-based methods when appropriate.

---

## Investigation Approach

Whenever practical:

1. Understand the investigation objective.
2. Identify the organization, folder, project, service, resource, identity, or data source involved.
3. Determine which interface is appropriate for the task.
4. Inspect the available information before heavily filtering it.
5. Understand the resource hierarchy, IAM relationships, project scope, and resource identifiers.
6. Filter or query the information needed for the investigation.
7. Correlate findings with logs or additional evidence when appropriate.
8. Document the commands, evidence, findings, and conclusions.

> **Learning Goal:** Understand the underlying Google Cloud services and learn when each interface is useful rather than simply memorizing individual commands.
