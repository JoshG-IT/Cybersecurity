# KQL Training Guide

## Purpose

Kusto Query Language is used to investigate telemetry.

Azure CLI is good for asking:

```text
What exists?
```

KQL is good for asking:

```text
What happened?
```

## Common Security Uses

- Microsoft Sentinel
- Log Analytics
- Azure Monitor
- Defender investigations
- Authentication activity
- Network activity
- Security alerts
- Event correlation

## Core Query Pattern

```kusto
TableName
| where Condition
| project Column1, Column2
| sort by TimeGenerated desc
```

## Operators to Learn First

```text
where
project
extend
summarize
count
distinct
sort
top
join
union
let
```

## Investigation Questions

Use KQL to answer questions such as:

- Who signed in?
- From where?
- When?
- Which IP address?
- What resource was accessed?
- Which account generated the most failures?
- What changed before an incident?
- Which events occurred around the same time?

## Learning Path

```text
Select table
      |
      v
Filter records
      |
      v
Select useful columns
      |
      v
Sort by time
      |
      v
Aggregate
      |
      v
Correlate multiple sources
```

## Important Distinction

KQL generally queries telemetry and indexed data.

It is not a replacement for Azure CLI resource management.
