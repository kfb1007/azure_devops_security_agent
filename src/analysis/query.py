"""
Analysis module for Azure DevOps Advanced Security alerts.
"""

import logging
import sqlite3
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


class AlertAnalyzer:
    """
    Analyzer for Azure DevOps Advanced Security alerts.
    
    This class provides analysis capabilities for alerts stored in the database,
    including filtering, grouping, and trend analysis.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the analyzer with a database connection.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
    
    def get_alert_counts_by_severity(self, organization: str, project: str, 
                                    repository: Optional[str] = None,
                                    days: int = 30) -> Dict[str, int]:
        """
        Get alert counts grouped by severity.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Optional repository name or ID
            days: Number of days to look back
            
        Returns:
            Dict[str, int]: Counts of alerts by severity
        """
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        query = '''
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE organization = ? AND project = ? AND last_seen_date >= ?
        '''
        params = [organization, project, cutoff_date]
        
        if repository:
            query += ' AND repository = ?'
            params.append(repository)
        
        query += ''' GROUP BY severity ORDER BY CASE severity 
                  WHEN "critical" THEN 1 
                  WHEN "high" THEN 2 
                  WHEN "medium" THEN 3 
                  WHEN "low" THEN 4 
                  ELSE 5 END'''
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            return {row['severity']: row['count'] for row in cursor.fetchall()}
    
    def get_alert_counts_by_state(self, organization: str, project: str,
                                 repository: Optional[str] = None) -> Dict[str, int]:
        """
        Get alert counts grouped by state.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Optional repository name or ID
            
        Returns:
            Dict[str, int]: Counts of alerts by state
        """
        query = '''
        SELECT state, COUNT(*) as count
        FROM alerts
        WHERE organization = ? AND project = ?
        '''
        params = [organization, project]
        
        if repository:
            query += ' AND repository = ?'
            params.append(repository)
        
        query += ' GROUP BY state'
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            return {row['state']: row['count'] for row in cursor.fetchall()}
    
    def get_alert_counts_by_type(self, organization: str, project: str,
                               repository: Optional[str] = None) -> Dict[str, int]:
        """
        Get alert counts grouped by alert type.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Optional repository name or ID
            
        Returns:
            Dict[str, int]: Counts of alerts by type
        """
        query = '''
        SELECT alert_type, COUNT(*) as count
        FROM alerts
        WHERE organization = ? AND project = ?
        '''
        params = [organization, project]
        
        if repository:
            query += ' AND repository = ?'
            params.append(repository)
        
        query += ' GROUP BY alert_type'
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            return {row['alert_type']: row['count'] for row in cursor.fetchall()}
    
    def get_alert_trend(self, organization: str, project: str,
                      repository: Optional[str] = None,
                      days: int = 30,
                      interval: str = 'day') -> List[Dict]:
        """
        Get alert trend over time.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Optional repository name or ID
            days: Number of days to look back
            interval: Time interval for grouping ('day', 'week', 'month')
            
        Returns:
            List[Dict]: Alert counts over time
        """
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        # SQLite date format
        if interval == 'day':
            date_format = '%Y-%m-%d'
        elif interval == 'week':
            date_format = '%Y-%W'
        elif interval == 'month':
            date_format = '%Y-%m'
        else:
            date_format = '%Y-%m-%d'
        
        query = f'''
        SELECT 
            strftime('{date_format}', first_seen_date) as period,
            COUNT(*) as count
        FROM alerts
        WHERE organization = ? AND project = ? AND first_seen_date >= ?
        '''
        params = [organization, project, cutoff_date]
        
        if repository:
            query += ' AND repository = ?'
            params.append(repository)
        
        query += f' GROUP BY strftime(\'{date_format}\', first_seen_date) ORDER BY period'
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_top_repositories_by_alerts(self, organization: str, project: str,
                                     severity: Optional[List[str]] = None,
                                     limit: int = 10) -> List[Dict]:
        """
        Get top repositories by alert count.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            severity: Optional list of severities to filter by
            limit: Maximum number of repositories to return
            
        Returns:
            List[Dict]: Repositories with alert counts
        """
        query = '''
        SELECT repository, COUNT(*) as count
        FROM alerts
        WHERE organization = ? AND project = ?
        '''
        params = [organization, project]
        
        if severity:
            placeholders = ', '.join(['?'] * len(severity))
            query += f' AND severity IN ({placeholders})'
            params.extend(severity)
        
        query += ' GROUP BY repository ORDER BY count DESC LIMIT ?'
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_top_rules(self, organization: str, project: str,
                    repository: Optional[str] = None,
                    limit: int = 10) -> List[Dict]:
        """
        Get top rules by alert count.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Optional repository name or ID
            limit: Maximum number of rules to return
            
        Returns:
            List[Dict]: Rules with alert counts
        """
        query = '''
        SELECT rule_id, rule_name, COUNT(*) as count
        FROM alerts
        WHERE organization = ? AND project = ? AND rule_id IS NOT NULL
        '''
        params = [organization, project]
        
        if repository:
            query += ' AND repository = ?'
            params.append(repository)
        
        query += ' GROUP BY rule_id, rule_name ORDER BY count DESC LIMIT ?'
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_alerts_by_file_path(self, organization: str, project: str,
                              repository: Optional[str] = None,
                              limit: int = 100) -> List[Dict]:
        """
        Get alerts grouped by file path.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Optional repository name or ID
            limit: Maximum number of file paths to return
            
        Returns:
            List[Dict]: File paths with alert counts
        """
        query = '''
        SELECT pl.file_path, COUNT(*) as count
        FROM alerts a
        JOIN physical_locations pl ON a.id = pl.alert_id
        WHERE a.organization = ? AND a.project = ?
        '''
        params = [organization, project]
        
        if repository:
            query += ' AND a.repository = ?'
            params.append(repository)
        
        query += ' GROUP BY pl.file_path ORDER BY count DESC LIMIT ?'
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_alert_details(self, organization: str, project: str, repository: str, alert_id: int) -> Optional[Dict]:
        """
        Get detailed information for a specific alert.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            repository: Repository name or ID
            alert_id: ID of the alert
            
        Returns:
            Optional[Dict]: Alert details or None if not found
        """
        query = '''
        SELECT *
        FROM alerts
        WHERE organization = ? AND project = ? AND repository = ? AND alert_id = ?
        '''
        params = [organization, project, repository, alert_id]
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            row = cursor.fetchone()
            if not row:
                return None
            
            alert = dict(row)
            
            # Get physical locations
            cursor.execute(
                'SELECT file_path, start_line, end_line, start_column, end_column FROM physical_locations WHERE alert_id = ?',
                (row['id'],)
            )
            alert['physical_locations'] = [dict(loc) for loc in cursor.fetchall()]
            
            # Get logical locations
            cursor.execute(
                'SELECT name, kind FROM logical_locations WHERE alert_id = ?',
                (row['id'],)
            )
            alert['logical_locations'] = [dict(loc) for loc in cursor.fetchall()]
            
            return alert
    
    def search_alerts(self, organization: str, project: str,
                    query: str,
                    repository: Optional[str] = None,
                    limit: int = 100) -> List[Dict]:
        """
        Search alerts by keyword.
        
        Args:
            organization: Azure DevOps organization
            project: Azure DevOps project
            query: Search query
            repository: Optional repository name or ID
            limit: Maximum number of alerts to return
            
        Returns:
            List[Dict]: Matching alerts
        """
        search_term = f"%{query}%"
        
        sql_query = '''
        SELECT a.id, a.alert_id, a.repository, a.alert_type, a.severity, a.state,
               a.first_seen_date, a.last_seen_date, a.rule_name
        FROM alerts a
        LEFT JOIN physical_locations pl ON a.id = pl.alert_id
        WHERE a.organization = ? AND a.project = ?
        AND (
            a.rule_name LIKE ? OR
            pl.file_path LIKE ? OR
            a.raw_data LIKE ?
        )
        '''
        params = [organization, project, search_term, search_term, search_term]
        
        if repository:
            sql_query += ' AND a.repository = ?'
            params.append(repository)
        
        sql_query += ' GROUP BY a.id LIMIT ?'
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql_query, params)
            
            return [dict(row) for row in cursor.fetchall()]
