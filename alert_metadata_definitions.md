# Azure DevOps Advanced Security Alert Metadata Definitions

This document defines the metadata associated with Azure DevOps Advanced Security alerts that will be collected and analyzed by our agent.

## Core Alert Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| alertId | integer (int64) | Unique identifier for the alert within Azure DevOps organization |
| alertType | enum | Type of the alert (e.g., secret, code, dependency) |
| confidence | enum | Confidence level of the alert |
| severity | enum | Severity of the alert (e.g., critical, high, medium, low) |
| state | enum | Current state of the alert |
| firstSeenDate | date-time | First time the service detected this issue |
| lastSeenDate | date-time | Last time the service detected this issue |
| fixedDate | date-time | Time when the issue was fixed (if applicable) |
| introducedDate | date-time | First time the vulnerability was introduced |
| gitRef | string | Reference to a git object (e.g., branch) |

## Location Information

| Field | Type | Description |
|-------|------|-------------|
| logicalLocations | array | Logical locations for the alert (e.g., components) |
| physicalLocations | object | Location in source control where the issue was found |

## Additional Information

| Field | Type | Description |
|-------|------|-------------|
| dismissal | object | Information about alert dismissal (if dismissed) |
| rule | object | The analysis rule that caused the alert |
| tool | object | Analysis tool that generated the security alert |
| additionalProperties | object | Additional properties specific to the alert |

## Filter Criteria Fields
These fields can be used for filtering and analysis:

| Field | Description |
|-------|-------------|
| dependencyName | Name of the dependency (for dependency alerts) |
| licenseName | License for the dependency (for dependency alerts) |
| pipelineName | Pipeline where the alert was detected |
| phaseName | Pipeline phase where the alert was detected |
| ruleId | ID of the rule that triggered the alert |
| ruleName | Name of the rule that triggered the alert |
| toolName | Name of the tool that detected the alert |

## Analysis Capabilities
The agent will enable analysis based on these metadata fields, including:

1. Trending analysis based on firstSeenDate, lastSeenDate, and fixedDate
2. Severity and confidence-based prioritization
3. Filtering by alert types, rules, and tools
4. Grouping by logical and physical locations
5. Tracking alert lifecycle through state changes
6. Dependency and license analysis for dependency alerts
