# AWS Interface Training Guide

AWS administration and security investigation can be performed through multiple interfaces.

No single interface exposes every capability.

These guides document how I am learning to select the appropriate interface based on what I am investigating, querying, or analyzing.

## Interface Map

| Interface | Best For | Main Skill Developed |
|---|---|---|
| AWS CLI | AWS resources and configuration | Resource investigation |
| AWS Tools for PowerShell | Automation and administration | Scripting |
| AWS APIs | Direct service interaction | API investigation |
| CloudWatch Logs Insights | Logs and telemetry | Security analysis |
| AWS Resource Explorer | Resource inventory at scale | Cloud reconnaissance |
| AWS Management Console | Visual exploration and validation | Architecture awareness |

---

## The Three Questions

When approaching a task, determine:

### 1. What am I interacting with?

Examples:

- AWS account
- IAM user
- IAM role
- IAM policy
- EC2 instance
- VPC
- security group
- S3 bucket
- CloudTrail event
- CloudWatch log
- AWS resource

### 2. Which interface is best suited to it?

Examples:

```text
AWS resource
→ AWS CLI

Repeated investigation task
→ AWS Tools for PowerShell

Direct AWS service interaction
→ AWS APIs

Logs and security events
→ CloudWatch Logs Insights

Large resource inventory
→ AWS Resource Explorer

Visual exploration or validation
→ AWS Management Console
```

### 3. What service/API is underneath the interface?

Examples:

```text
AWS CLI
→ AWS service APIs

AWS Tools for PowerShell
→ AWS service APIs

AWS APIs
→ Individual AWS services

CloudWatch Logs Insights
→ Amazon CloudWatch Logs

AWS Resource Explorer
→ AWS Resource Explorer service

AWS Management Console
→ AWS service APIs
```

Understanding the underlying AWS service is more important than memorizing the interface.

---

## AWS Scope and Resource Awareness

A key part of investigating AWS is understanding where a resource exists and how it is identified.

```text
AWS Organization
    ↓
AWS Account
    ↓
Region
    ↓
Service
    ↓
Resource
```

Not every AWS service is regional, so during an investigation I should determine whether the resource is:

```text
Global
or
Regional
```

Resources are often identified using an:

```text
ARN
Amazon Resource Name
```

During an investigation, I should identify the account, region, service, resource, and ARN when applicable.

---

## Identity and Access Awareness

AWS IAM permissions are based on relationships between:

```text
Principal
    ↓
Policy
    ↓
Action
    ↓
Resource
    ↓
Condition
```

During an investigation, I should determine:

- which principal is involved
- what policy applies
- which actions are allowed or denied
- which resource is in scope
- whether conditions affect access

---

## Learning Priority

My current priority:

```text
1. AWS CLI
2. AWS Tools for PowerShell
3. AWS APIs
4. CloudWatch Logs Insights
5. AWS Resource Explorer
6. AWS Management Console
```

This is a personal learning priority rather than a requirement of the Mad Hat investigations.

The AWS Management Console remains useful throughout the learning process. I use the investigations as opportunities to practice command-line, scripting, API, log-query, and resource-discovery approaches when appropriate.

The goal is to understand when each interface is useful and how the different interfaces relate to the underlying AWS services.
