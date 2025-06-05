# Azure DevOps Security Alert Agent - User Guide

## Overview

This agent collects Advanced Security alert data from Azure DevOps and enables analysis using metadata associated with each alert. The agent provides comprehensive capabilities for collecting, storing, and analyzing security alerts to help you identify and address security issues in your Azure DevOps repositories.

## Features

- **Alert Collection**: Retrieve Advanced Security alerts from Azure DevOps repositories
- **Metadata Extraction**: Extract and store rich metadata from alerts
- **Flexible Storage**: Store alerts in a structured database for efficient querying
- **Advanced Analysis**: Analyze alerts based on various metadata dimensions
- **Reporting**: Generate reports on alert trends, distributions, and patterns

## Installation

1. Clone this repository to your local machine
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Configure the agent (see Configuration section)
4. Run the agent to collect alerts

## Configuration

Copy the `config/config.yaml.template` file to `config/config.yaml` and update it with your Azure DevOps details:

```yaml
organization: "your-organization"
project: "your-project"
repositories:
  - "repo1"
  - "repo2"

auth:
  auth_type: "pat"  # Options: "pat" or "oauth"
  pat: "your-personal-access-token"
  # OAuth settings (only needed if auth_type is "oauth")
  # client_id: "your-client-id"
  # client_secret: "your-client-secret"
  # tenant_id: "your-tenant-id"

database:
  path: "data/alerts.db"

# Optional settings for alert collection
collection:
  # Filter criteria for alerts
  criteria:
    # severity: ["critical", "high"]
    # state: ["active"]
    # alert_type: "code"
  # Maximum number of alerts to collect per repository
  limit: 1000
```

### Authentication

The agent supports two authentication methods:

1. **Personal Access Token (PAT)**: Generate a PAT in Azure DevOps with the `vso.advsec` scope
2. **OAuth 2.0**: Register an application in Azure AD and configure OAuth settings

## Usage

### Collecting Alerts

To collect alerts from Azure DevOps, run:

```
python main.py --config config/config.yaml
```

This will:
1. Connect to Azure DevOps using the configured authentication
2. Retrieve alerts from the specified repositories
3. Store the alerts in the database

### Analyzing Alerts

To analyze collected alerts, run:

```
python analyze.py --config config/config.yaml
```

This will generate reports on:
- Alert counts by severity
- Alert counts by state
- Alert counts by type
- Alert trends over time
- Top repositories by alert count
- Top rules triggering alerts
- Alerts by file path

Reports are saved to the `reports` directory in JSON format.

## Analysis Capabilities

The agent provides the following analysis capabilities:

### Filtering

Filter alerts by:
- Severity (critical, high, medium, low)
- State (active, dismissed, fixed)
- Alert type (code, secret, dependency)
- Repository
- Time range

### Grouping

Group alerts by:
- Repository
- Severity
- State
- Alert type
- Rule
- File path

### Trending

Analyze alert trends over time:
- Daily, weekly, or monthly intervals
- First seen date
- Fixed date

## Architecture

The agent consists of the following components:

1. **Authentication Module**: Handles OAuth 2.0 and PAT authentication
2. **API Client**: Manages REST API calls to Azure DevOps
3. **Data Models**: Represents alerts and associated metadata
4. **Storage Layer**: Stores alerts in a SQLite database
5. **Analysis Module**: Provides querying and analysis capabilities

## Troubleshooting

### Common Issues

1. **Authentication Errors**:
   - Verify that your PAT or OAuth credentials are correct
   - Ensure the PAT has the `vso.advsec` scope

2. **No Alerts Found**:
   - Verify that Advanced Security is enabled for your repositories
   - Check that the repositories exist and are accessible

3. **Database Errors**:
   - Ensure the database directory is writable
   - Check for disk space issues

### Logging

The agent logs information to the console. For more detailed logging, modify the logging configuration in `main.py` and `analyze.py`.

## Extending the Agent

The agent is designed to be extensible. You can:

1. Add new analysis capabilities in `src/analysis/query.py`
2. Implement additional data enrichment in `src/enrichment/`
3. Create custom reporting tools using the stored data

## License

This project is licensed under the MIT License - see the LICENSE file for details.
