"""
Data loading module for authentication logs.

Implements a canonical authentication log schema with support for
CSV and JSON input formats.
"""

from __future__ import annotations

import json
import csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Union, Any
import logging

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """
    Canonical authentication event schema.
    
    This represents a single authentication or session event with
    all fields necessary for behavioral anomaly detection.
    """
    timestamp: datetime
    user_id: str
    event_type: str  # login, logout, session_refresh, failed_login, etc.
    
    # Network attributes
    ip_address: Optional[str] = None
    asn: Optional[str] = None  # Autonomous System Number
    country_code: Optional[str] = None
    
    # Device attributes
    user_agent: Optional[str] = None
    device_fingerprint: Optional[str] = None
    
    # Session attributes
    session_id: Optional[str] = None
    session_duration_seconds: Optional[float] = None
    
    # Authentication attributes
    auth_method: Optional[str] = None  # password, mfa, sso, api_key, etc.
    mfa_used: Optional[bool] = None
    
    # Outcome
    success: Optional[bool] = None
    failure_reason: Optional[str] = None
    
    # Raw data preservation
    raw_fields: dict[str, Any] = field(default_factory=dict, repr=False)
    
    # Event classification constants
    EVENT_LOGIN = "login"
    EVENT_LOGOUT = "logout"
    EVENT_FAILED_LOGIN = "failed_login"
    EVENT_SESSION_START = "session_start"
    EVENT_SESSION_END = "session_end"
    EVENT_SESSION_REFRESH = "session_refresh"
    EVENT_MFA_CHALLENGE = "mfa_challenge"
    EVENT_MFA_SUCCESS = "mfa_success"
    EVENT_MFA_FAILURE = "mfa_failure"
    EVENT_PASSWORD_RESET = "password_reset"
    EVENT_LOCKOUT = "lockout"
    
    @property
    def is_failure(self) -> bool:
        """Check if this event represents a failed authentication attempt."""
        return self.event_type in (self.EVENT_FAILED_LOGIN, self.EVENT_MFA_FAILURE)
    
    @property
    def is_successful_login(self) -> bool:
        """Check if this event represents a successful login."""
        return self.event_type == self.EVENT_LOGIN and self.success is True
    
    @property
    def is_session_event(self) -> bool:
        """Check if this event is session-related."""
        return self.event_type in (
            self.EVENT_SESSION_START,
            self.EVENT_SESSION_END,
            self.EVENT_SESSION_REFRESH,
        )
    
    @property
    def hour_of_day(self) -> int:
        """Extract hour of day from timestamp (0-23)."""
        return self.timestamp.hour
    
    @property
    def day_of_week(self) -> int:
        """Extract day of week from timestamp (0=Monday, 6=Sunday)."""
        return self.timestamp.weekday()
    
    @property
    def is_weekend(self) -> bool:
        """Check if event occurred on a weekend."""
        return self.day_of_week >= 5
    
    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "event_type": self.event_type,
            "ip_address": self.ip_address,
            "asn": self.asn,
            "country_code": self.country_code,
            "user_agent": self.user_agent,
            "device_fingerprint": self.device_fingerprint,
            "session_id": self.session_id,
            "session_duration_seconds": self.session_duration_seconds,
            "auth_method": self.auth_method,
            "mfa_used": self.mfa_used,
            "success": self.success,
            "failure_reason": self.failure_reason,
        }


class AuthLogLoader:
    """
    Loader for authentication logs in various formats.
    
    Supports CSV and JSON formats with configurable field mappings.
    """
    
    # Default field mappings for common log formats
    DEFAULT_FIELD_MAP = {
        "timestamp": ["timestamp", "time", "datetime", "date", "ts", "@timestamp"],
        "user_id": ["user_id", "user", "username", "user_name", "email", "userid", "subject"],
        "event_type": ["event_type", "event", "action", "activity", "eventname", "eventName"],
        "ip_address": ["ip_address", "ip", "source_ip", "src_ip", "remote_addr", "client_ip"],
        "asn": ["asn", "as_number", "autonomous_system", "as_org"],
        "country_code": ["country_code", "country", "geo_country", "cc"],
        "user_agent": ["user_agent", "useragent", "ua", "http_user_agent"],
        "device_fingerprint": ["device_fingerprint", "device_id", "fingerprint", "device"],
        "session_id": ["session_id", "session", "sid", "sessionId"],
        "session_duration_seconds": ["session_duration", "duration", "duration_seconds"],
        "auth_method": ["auth_method", "auth_type", "authentication_method", "method"],
        "mfa_used": ["mfa_used", "mfa", "multi_factor", "two_factor", "2fa"],
        "success": ["success", "outcome", "result", "status"],
        "failure_reason": ["failure_reason", "reason", "error", "error_message"],
    }
    
    def __init__(self, field_map: Optional[dict[str, list[str]]] = None):
        """
        Initialize the loader with optional custom field mappings.
        
        Args:
            field_map: Optional dictionary mapping canonical field names to
                      lists of possible input field names.
        """
        self.field_map = field_map or self.DEFAULT_FIELD_MAP
        self._timestamp_formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%d/%b/%Y:%H:%M:%S %z",  # Apache log format
            "%b %d %H:%M:%S",  # Syslog format
        ]
    
    def load(self, path: Union[str, Path]) -> list[AuthEvent]:
        """
        Load authentication events from a file.
        
        Args:
            path: Path to the log file (CSV or JSON)
            
        Returns:
            List of AuthEvent objects
            
        Raises:
            ValueError: If file format is not supported
            FileNotFoundError: If file does not exist
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        
        suffix = path.suffix.lower()
        
        if suffix == ".csv":
            return self._load_csv(path)
        elif suffix == ".json":
            return self._load_json(path)
        elif suffix == ".jsonl":
            return self._load_jsonl(path)
        else:
            raise ValueError(f"Unsupported file format: {suffix}. Use .csv, .json, or .jsonl")
    
    def load_dataframe(self, df: pd.DataFrame) -> list[AuthEvent]:
        """
        Convert a pandas DataFrame to AuthEvent objects.
        
        Args:
            df: DataFrame containing authentication log data
            
        Returns:
            List of AuthEvent objects
        """
        events = []
        field_mapping = self._detect_fields(df.columns)
        
        for _, row in df.iterrows():
            event = self._row_to_event(row, field_mapping)
            if event:
                events.append(event)
        
        logger.info(f"Loaded {len(events)} events from DataFrame")
        return events
    
    def _load_csv(self, path: Path) -> list[AuthEvent]:
        """Load events from CSV file."""
        df = pd.read_csv(path)
        events = self.load_dataframe(df)
        logger.info(f"Loaded {len(events)} events from CSV: {path}")
        return events
    
    def _load_json(self, path: Path) -> list[AuthEvent]:
        """Load events from JSON file (array of objects)."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, dict):
            # Handle nested structures
            if "events" in data:
                df = pd.DataFrame(data["events"])
            elif "logs" in data:
                df = pd.DataFrame(data["logs"])
            else:
                df = pd.DataFrame([data])
        else:
            raise ValueError("JSON must contain an array of objects or a single object")
        
        events = self.load_dataframe(df)
        logger.info(f"Loaded {len(events)} events from JSON: {path}")
        return events
    
    def _load_jsonl(self, path: Path) -> list[AuthEvent]:
        """Load events from JSON Lines file."""
        records = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        
        df = pd.DataFrame(records)
        events = self.load_dataframe(df)
        logger.info(f"Loaded {len(events)} events from JSONL: {path}")
        return events
    
    def _detect_fields(self, columns: pd.Index) -> dict[str, Optional[str]]:
        """
        Detect which input fields map to canonical fields.
        
        Args:
            columns: DataFrame column names
            
        Returns:
            Dictionary mapping canonical field names to actual column names
        """
        mapping = {}
        columns_lower = {col.lower(): col for col in columns}
        
        for canonical, alternatives in self.field_map.items():
            matched = None
            for alt in alternatives:
                if alt in columns:
                    matched = alt
                    break
                # Try case-insensitive match
                if alt.lower() in columns_lower:
                    matched = columns_lower[alt.lower()]
                    break
            mapping[canonical] = matched
        
        return mapping
    
    def _row_to_event(
        self, 
        row: pd.Series, 
        field_mapping: dict[str, Optional[str]]
    ) -> Optional[AuthEvent]:
        """
        Convert a DataFrame row to an AuthEvent.
        
        Args:
            row: DataFrame row
            field_mapping: Mapping of canonical to actual field names
            
        Returns:
            AuthEvent or None if conversion fails
        """
        try:
            # Required fields
            timestamp = self._parse_timestamp(
                row[field_mapping["timestamp"]] if field_mapping["timestamp"] else None
            )
            if timestamp is None:
                logger.warning(f"Could not parse timestamp for row: {row.to_dict()}")
                return None
            
            user_id = self._extract_value(row, field_mapping.get("user_id"))
            if not user_id:
                logger.warning("Missing user_id, skipping event")
                return None
            
            event_type = self._extract_value(row, field_mapping.get("event_type"))
            if not event_type:
                event_type = AuthEvent.EVENT_LOGIN  # Default assumption
            
            # Optional fields
            ip_address = self._extract_value(row, field_mapping.get("ip_address"))
            asn = self._extract_value(row, field_mapping.get("asn"))
            country_code = self._extract_value(row, field_mapping.get("country_code"))
            user_agent = self._extract_value(row, field_mapping.get("user_agent"))
            device_fingerprint = self._extract_value(row, field_mapping.get("device_fingerprint"))
            session_id = self._extract_value(row, field_mapping.get("session_id"))
            auth_method = self._extract_value(row, field_mapping.get("auth_method"))
            failure_reason = self._extract_value(row, field_mapping.get("failure_reason"))
            
            # Numeric fields
            session_duration = self._extract_numeric(
                row, field_mapping.get("session_duration_seconds")
            )
            
            # Boolean fields
            mfa_used = self._extract_boolean(row, field_mapping.get("mfa_used"))
            success = self._extract_boolean(row, field_mapping.get("success"))
            
            # Collect raw fields for preservation
            raw_fields = {k: v for k, v in row.items() if k not in field_mapping}
            
            return AuthEvent(
                timestamp=timestamp,
                user_id=str(user_id),
                event_type=str(event_type).lower(),
                ip_address=str(ip_address) if ip_address else None,
                asn=str(asn) if asn else None,
                country_code=str(country_code).upper() if country_code else None,
                user_agent=str(user_agent) if user_agent else None,
                device_fingerprint=str(device_fingerprint) if device_fingerprint else None,
                session_id=str(session_id) if session_id else None,
                session_duration_seconds=session_duration,
                auth_method=str(auth_method) if auth_method else None,
                mfa_used=mfa_used,
                success=success,
                failure_reason=str(failure_reason) if failure_reason else None,
                raw_fields=raw_fields,
            )
            
        except Exception as e:
            logger.warning(f"Error converting row to event: {e}")
            return None
    
    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        """Parse a timestamp value into a datetime object."""
        if value is None or pd.isna(value):
            return None
        
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, (int, float)):
            # Assume Unix timestamp
            if value > 1e12:  # Milliseconds
                value = value / 1000
            return datetime.fromtimestamp(value)
        
        value_str = str(value).strip()
        
        for fmt in self._timestamp_formats:
            try:
                return datetime.strptime(value_str, fmt)
            except ValueError:
                continue
        
        # Try pandas parser as fallback
        try:
            return pd.to_datetime(value_str).to_pydatetime()
        except Exception:
            pass
        
        return None
    
    def _extract_value(self, row: pd.Series, field_name: Optional[str]) -> Optional[str]:
        """Extract a string value from a row."""
        if field_name is None or field_name not in row:
            return None
        value = row[field_name]
        if pd.isna(value):
            return None
        return str(value)
    
    def _extract_numeric(self, row: pd.Series, field_name: Optional[str]) -> Optional[float]:
        """Extract a numeric value from a row."""
        if field_name is None or field_name not in row:
            return None
        value = row[field_name]
        if pd.isna(value):
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
    
    def _extract_boolean(self, row: pd.Series, field_name: Optional[str]) -> Optional[bool]:
        """Extract a boolean value from a row."""
        if field_name is None or field_name not in row:
            return None
        value = row[field_name]
        if pd.isna(value):
            return None
        
        if isinstance(value, bool):
            return value
        
        value_str = str(value).lower()
        if value_str in ("true", "success", "1", "yes", "pass", "passed"):
            return True
        elif value_str in ("false", "failure", "0", "no", "fail", "failed"):
            return False
        
        return None
    
    def validate_events(self, events: list[AuthEvent]) -> dict[str, Any]:
        """
        Validate a list of events and return statistics.
        
        Args:
            events: List of AuthEvent objects
            
        Returns:
            Dictionary with validation statistics
        """
        stats = {
            "total_events": len(events),
            "unique_users": len(set(e.user_id for e in events)),
            "date_range": None,
            "event_types": {},
            "fields_present": {
                "ip_address": sum(1 for e in events if e.ip_address),
                "asn": sum(1 for e in events if e.asn),
                "country_code": sum(1 for e in events if e.country_code),
                "user_agent": sum(1 for e in events if e.user_agent),
                "device_fingerprint": sum(1 for e in events if e.device_fingerprint),
                "session_id": sum(1 for e in events if e.session_id),
                "auth_method": sum(1 for e in events if e.auth_method),
                "mfa_used": sum(1 for e in events if e.mfa_used is not None),
                "success": sum(1 for e in events if e.success is not None),
            },
        }
        
        if events:
            timestamps = [e.timestamp for e in events]
            stats["date_range"] = {
                "start": min(timestamps).isoformat(),
                "end": max(timestamps).isoformat(),
            }
            
            for event in events:
                stats["event_types"][event.event_type] = \
                    stats["event_types"].get(event.event_type, 0) + 1
        
        return stats
