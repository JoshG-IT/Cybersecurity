# AWS Security Investigations

Hands-on AWS security investigations completed through the Mad Hat.

**Status:** ⏳ Pending

Investigation cases will be added as the training track becomes available and hands-on investigations are completed.

[← Back to Mad Hat Investigations](../)

---

## Investigation Interfaces

I use these AWS investigations as an opportunity to become more familiar with the different interfaces available for investigating Amazon Web Services environments.

My primary learning focus is **AWS CLI**, while AWS Tools for PowerShell, AWS APIs, CloudWatch Logs Insights, AWS Resource Explorer, and the AWS Management Console are used when they are relevant to the investigation.

The goal is not to force every investigation through every interface. Instead, I use each case to learn which interface is best suited to the resource, identity, configuration, log source, or activity being investigated.

| Interface | Best For | Guide |
|---|---|---|
| AWS CLI | AWS resources, IAM, networking, storage, configuration, and reconnaissance | [AWS CLI](Guides/aws-cli.md) |
| AWS Tools for PowerShell | Scripting, automation, loops, and reusable investigation workflows | [AWS Tools for PowerShell](Guides/aws-tools-for-powershell.md) |
| AWS APIs | Direct interaction with AWS service APIs and deeper service investigation | [AWS APIs](Guides/aws-api.md) |
| CloudWatch Logs Insights | Logs, telemetry, CloudTrail data, event investigation, and security analysis | [CloudWatch Logs Insights](Guides/cloudwatch-logs-insights.md) |
| AWS Resource Explorer | Large-scale resource discovery, inventory, and cross-region reconnaissance | [AWS Resource Explorer](Guides/aws-resource-explorer.md) |
| AWS Management Console | Visual exploration, validation, and tasks better suited to a graphical interface | [AWS Management Console](Guides/aws-management-console.md) |

See the complete [AWS Interface Training Guide](Guides/).

---

## Interface Selection

```text
What am I investigating?
        |
        +-- AWS resource, IAM, configuration, tag, or network
        |       |
        |       --> AWS CLI
        |
        +-- Repeated task, scripting, or automation
        |       |
        |       --> AWS Tools for PowerShell
        |
        +-- Direct service data or capability not easily exposed
        |   through another interface
        |       |
        |       --> AWS APIs
        |
        +-- Logs, events, telemetry, or security activity
        |       |
        |       --> CloudWatch Logs Insights
        |
        +-- Large-scale or cross-region resource discovery
        |       |
        |       --> AWS Resource Explorer
        |
        +-- Visual exploration, validation, or a task
                better suited to a graphical interface
                |
                --> AWS Management Console
```

---

## Personal Learning Priority

```text
AWS CLI
    ↓
AWS Tools for PowerShell
    ↓
AWS APIs
    ↓
CloudWatch Logs Insights
    ↓
AWS Resource Explorer
    ↓
AWS Management Console
```

This reflects my personal learning approach rather than a requirement of the Mad Hat investigations.

The AWS Management Console remains an important administrative and investigative interface. I use these investigations as opportunities to practice command-line, scripting, API, query-based, and resource-discovery methods when appropriate.

---

## Investigation Approach

Whenever practical:

1. Understand the investigation objective.
2. Identify the AWS account, region, service, resource, identity, or data source involved.
3. Determine which interface is appropriate for the task.
4. Inspect the available information before heavily filtering it.
5. Understand the resource structure, ARN, permissions, region, and relationships.
6. Filter or query the information needed for the investigation.
7. Correlate findings with logs or additional evidence when appropriate.
8. Document the commands, evidence, findings, and conclusions.

> **Learning Goal:** Understand the underlying AWS services and learn when each interface is useful rather than simply memorizing individual commands.
