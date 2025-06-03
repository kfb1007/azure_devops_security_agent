"""
Database storage for Azure DevOps Advanced Security alerts.
"""

import sqlite3
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from ..api.models import Alert, AlertType, Confidence, Severity, AlertState

logger = logging.getLogger(__name__)


class ComplexEncoder(json.JSONEncoder):
    """JSON encoder that handles complex objects like dataclasses and enums."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        # Handle dataclasses by converting to dict
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        # Handle enums
        if isinstance(obj, (AlertType, Confidence, Severity, AlertState)):
            return obj.value
        # Let the base class handle anything else
        return super().default(obj)


class AlertDatabase:
    """
    Database for storing and retrieving Azure DevOps Advanced Security alerts.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the database connection.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._ensure_db_exists()
        self._create_tables()
    
    def _ensure_db_exists(self):
        """Ensure the database directory exists."""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def _create_tables(self):
        """Create the necessary database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create alerts table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                alert_id INTEGER NOT NULL,
                organization TEXT NOT NULL,
                project TEXT NOT NULL,
                repository TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                confidence TEXT NOT NULL,
                severity TEXT NOT NULL,
                state TEXT NOT NULL,
                first_seen_date TEXT NOT NULL,
                last_seen_date TEXT NOT NULL,
                git_ref TEXT NOT NULL,
                introduced_date TEXT,
                fixed_date TEXT,
                rule_id TEXT,
                rule_name TEXT,
                tool_name TEXT,
                dismissal_type TEXT,
                dismissal_comment TEXT,
                dismissal_by TEXT,
                dismissal_at TEXT,
                additional_properties TEXT,
                raw_data TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(organization, project, repository, alert_id)
            )
            ''')
            
            # Create locations table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS physical_locations (
                id INTEGER PRIMARY KEY,
                alert_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                start_line INTEGER,
                end_line INTEGER,
                start_column INTEGER,
                end_column INTEGER,
                FOREIGN KEY (alert_id) REFERENCES alerts (id)
            )
            ''')
            
            # Create logical locations table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS logical_locations (
                id INTEGER PRIMARY KEY,
                alert_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                kind TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts (id)
            )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_org_proj_repo ON alerts (organization, project, repository)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts (alert_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts (state)')
            
            conn.commit()
    
    def store_alert(self, alert: Alert, organization: str, project: str, repository: str) -> int:
        """
        Store an alert in the database.
        
        Args:
            alert: The alert to store
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Repository name or ID
            
        Returns:
            int: Database ID of the stored alert
        """
        now = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if alert already exists
            cursor.execute(
                'SELECT id FROM alerts WHERE organization = ? AND project = ? AND repository = ? AND alert_id = ?',
                (organization, project, repository, alert.alert_id)
            )
            result = cursor.fetchone()
            
            # Convert alert to JSON-serializable format using custom encoder
            alert_json = json.dumps(alert, cls=ComplexEncoder)
            
            if result:
                # Update existing alert
                alert_db_id = result[0]
                cursor.execute('''
                UPDATE alerts SET
                    alert_type = ?,
                    confidence = ?,
                    severity = ?,
                    state = ?,
                    first_seen_date = ?,
                    last_seen_date = ?,
                    git_ref = ?,
                    introduced_date = ?,
                    fixed_date = ?,
                    rule_id = ?,
                    rule_name = ?,
                    tool_name = ?,
                    dismissal_type = ?,
                    dismissal_comment = ?,
                    dismissal_by = ?,
                    dismissal_at = ?,
                    additional_properties = ?,
                    raw_data = ?,
                    updated_at = ?
                WHERE id = ?
                ''', (
                    alert.alert_type.value,
                    alert.confidence.value,
                    alert.severity.value,
                    alert.state.value,
                    alert.first_seen_date.isoformat(),
                    alert.last_seen_date.isoformat(),
                    alert.git_ref,
                    alert.introduced_date.isoformat() if alert.introduced_date else None,
                    alert.fixed_date.isoformat() if alert.fixed_date else None,
                    alert.rule.id if alert.rule else None,
                    alert.rule.name if alert.rule else None,
                    alert.tool.name if alert.tool else None,
                    alert.dismissal.type if alert.dismissal else None,
                    alert.dismissal.comment if alert.dismissal else None,
                    alert.dismissal.dismissed_by if alert.dismissal else None,
                    alert.dismissal.dismissed_at.isoformat() if alert.dismissal and alert.dismissal.dismissed_at else None,
                    json.dumps(alert.additional_properties, cls=ComplexEncoder) if alert.additional_properties else None,
                    alert_json,
                    now,
                    alert_db_id
                ))
                
                # Delete existing locations
                cursor.execute('DELETE FROM physical_locations WHERE alert_id = ?', (alert_db_id,))
                cursor.execute('DELETE FROM logical_locations WHERE alert_id = ?', (alert_db_id,))
            else:
                # Insert new alert
                cursor.execute('''
                INSERT INTO alerts (
                    alert_id, organization, project, repository,
                    alert_type, confidence, severity, state,
                    first_seen_date, last_seen_date, git_ref,
                    introduced_date, fixed_date,
                    rule_id, rule_name, tool_name,
                    dismissal_type, dismissal_comment, dismissal_by, dismissal_at,
                    additional_properties, raw_data,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert.alert_id, organization, project, repository,
                    alert.alert_type.value, alert.confidence.value, alert.severity.value, alert.state.value,
                    alert.first_seen_date.isoformat(), alert.last_seen_date.isoformat(), alert.git_ref,
                    alert.introduced_date.isoformat() if alert.introduced_date else None,
                    alert.fixed_date.isoformat() if alert.fixed_date else None,
                    alert.rule.id if alert.rule else None,
                    alert.rule.name if alert.rule else None,
                    alert.tool.name if alert.tool else None,
                    alert.dismissal.type if alert.dismissal else None,
                    alert.dismissal.comment if alert.dismissal else None,
                    alert.dismissal.dismissed_by if alert.dismissal else None,
                    alert.dismissal.dismissed_at.isoformat() if alert.dismissal and alert.dismissal.dismissed_at else None,
                    json.dumps(alert.additional_properties, cls=ComplexEncoder) if alert.additional_properties else None,
                    alert_json,
                    now, now
                ))
                alert_db_id = cursor.lastrowid
            
            # Insert physical locations
            for location in alert.physical_locations:
                cursor.execute('''
                INSERT INTO physical_locations (
                    alert_id, file_path, start_line, end_line, start_column, end_column
                ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    alert_db_id,
                    location.file_path,
                    location.start_line,
                    location.end_line,
                    location.start_column,
                    location.end_column
                ))
            
            # Insert logical locations
            for location in alert.logical_locations:
                cursor.execute('''
                INSERT INTO logical_locations (
                    alert_id, name, kind
                ) VALUES (?, ?, ?)
                ''', (
                    alert_db_id,
                    location.name,
                    location.kind
                ))
            
            conn.commit()
            return alert_db_id
    
    def get_alerts(self, organization: str, project: str, repository: Optional[str] = None, 
                  severity: Optional[List[str]] = None, state: Optional[List[str]] = None,
                  alert_type: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """
        Get alerts from the database with optional filtering.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Optional repository name or ID
            severity: Optional list of severities to filter by
            state: Optional list of states to filter by
            alert_type: Optional alert type to filter by
            limit: Maximum number of alerts to return
            
        Returns:
            List[Dict]: List of alert dictionaries
        """
        query = '''
        SELECT id, alert_id, organization, project, repository,
               alert_type, confidence, severity, state,
               first_seen_date, last_seen_date, git_ref,
               introduced_date, fixed_date,
               rule_id, rule_name, tool_name,
               dismissal_type, dismissal_comment, dismissal_by, dismissal_at,
               additional_properties, raw_data,
               created_at, updated_at
        FROM alerts
        WHERE organization = ? AND project = ?
        '''
        params = [organization, project]
        
        if repository:
            query += ' AND repository = ?'
            params.append(repository)
        
        if severity:
            placeholders = ', '.join(['?'] * len(severity))
            query += f' AND severity IN ({placeholders})'
            params.extend(severity)
        
        if state:
            placeholders = ', '.join(['?'] * len(state))
            query += f' AND state IN ({placeholders})'
            params.extend(state)
        
        if alert_type:
            query += ' AND alert_type = ?'
            params.append(alert_type)
        
        query += ' ORDER BY last_seen_date DESC LIMIT ?'
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            alerts = []
            for row in cursor.fetchall():
                alert_dict = dict(row)
                
                # Get physical locations
                cursor.execute(
                    'SELECT file_path, start_line, end_line, start_column, end_column FROM physical_locations WHERE alert_id = ?',
                    (row['id'],)
                )
                alert_dict['physical_locations'] = [dict(loc) for loc in cursor.fetchall()]
                
                # Get logical locations
                cursor.execute(
                    'SELECT name, kind FROM logical_locations WHERE alert_id = ?',
                    (row['id'],)
                )
                alert_dict['logical_locations'] = [dict(loc) for loc in cursor.fetchall()]
                
                alerts.append(alert_dict)
            
            return alerts
