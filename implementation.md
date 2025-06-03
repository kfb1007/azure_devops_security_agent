# Azure DevOps Security Alert Agent - Implementation

This directory contains the implementation of the agent for collecting and analyzing Advanced Security alert data from Azure DevOps.

## Project Structure

```
azure_devops_security_agent/
├── src/
│   ├── __init__.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── oauth.py
│   │   └── pat.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── client.py
│   │   └── models.py
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py
│   │   └── schema.py
│   ├── enrichment/
│   │   ├── __init__.py
│   │   └── metadata.py
│   ├── analysis/
│   │   ├── __init__.py
│   │   └── query.py
│   └── utils/
│       ├── __init__.py
│       ├── config.py
│       └── logging.py
├── config/
│   └── config.yaml.template
├── requirements.txt
└── main.py
```

## Setup Instructions

1. Clone this repository
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `config/config.yaml.template` to `config/config.yaml` and update with your settings
4. Run the agent: `python main.py`

## Configuration

The agent requires the following configuration:

- Azure DevOps organization and project details
- Authentication credentials (OAuth client ID/secret or PAT)
- Database connection information
- Logging settings

## Usage

The agent can be used in the following ways:

1. **One-time collection**: Collect alerts and store them for analysis
2. **Scheduled collection**: Run periodically to keep alert data updated
3. **Continuous monitoring**: Run as a service to monitor alerts in real-time

## Analysis Capabilities

The agent provides the following analysis capabilities:

- Filter alerts by metadata (severity, type, state, etc.)
- Group alerts by various dimensions
- Track alert trends over time
- Identify patterns and correlations
