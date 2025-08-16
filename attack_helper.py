# attack_helper.py — Enhanced column normalization + dynamic risk flags + smart CSV processing
from typing import Dict, List, Tuple, Optional, Any
import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
import ipaddress
import streamlit as st

# Extended possible column name variants we normalize into a standard schema
COL_MAP = {
    "ip": ["ip", "src_ip", "source_ip", "client_ip", "remote_ip", "host_ip", "origin_ip", 
           "peer_ip", "sender_ip", "addr", "address", "ip_addr", "ipaddress", "src.address",
           "source_address", "client_address", "remote_address"],
    
    "asn": ["asn", "as", "autonomous_system", "asn_number", "as_number", "src.asn", 
            "source_asn", "origin_asn", "peer_asn", "as_num"],
    
    "country": ["country", "src_country", "source_country", "geo_country", "geoip_country",
                "country_code", "cc", "nation", "src.geo.country_name", "geo_country_name",
                "country_name", "origin_country", "location_country"],
    
    "timestamp": ["timestamp", "time", "event_time", "datetime", "ts", "@timestamp", "date",
                  "created_at", "occurred_at", "log_time", "event_timestamp", "when", "at"],
    
    "event_type": ["event_type", "event", "action", "activity", "event_name", "type", 
                   "category", "classification", "event_category", "log_type", "alert_type"],
    
    "status": ["status", "result", "outcome", "response", "response_status", "success",
               "failed", "state", "disposition", "verdict", "conclusion"],
    
    "user": ["user", "username", "account", "principal", "subject", "user_name", 
             "userid", "login", "account_name", "principal_name", "identity"],
    
    "lat": ["lat", "latitude", "geo_lat", "src_lat", "location_lat", "coord_lat"],
    "lon": ["lon", "lng", "longitude", "geo_lon", "src_lon", "location_lon", "coord_lon"],
    
    "port": ["port", "src_port", "source_port", "dest_port", "destination_port", "service_port"],
    "protocol": ["protocol", "proto", "ip_protocol", "transport", "layer4_protocol"],
    "bytes": ["bytes", "byte_count", "data_size", "packet_size", "transfer_size"],
    "packets": ["packets", "packet_count", "pkt_count", "frame_count"],
}

def detect_ip_columns(df: pd.DataFrame) -> List[str]:
    """Detect columns that might contain IP addresses by analyzing content."""
    ip_columns = []
    for col in df.columns:
        if df[col].dtype == 'object':
            # Sample first 100 non-null values
            sample = df[col].dropna().head(100)
            if len(sample) == 0:
                continue
            
            ip_count = 0
            for val in sample:
                try:
                    str_val = str(val).strip()
                    # Check if it looks like an IP
                    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', str_val):
                        parts = str_val.split('.')
                        if all(0 <= int(part) <= 255 for part in parts):
                            ip_count += 1
                except:
                    continue
            
            # If >70% of values look like IPs, consider it an IP column
            if ip_count / len(sample) > 0.7:
                ip_columns.append(col)
    
    return ip_columns

def detect_timestamp_columns(df: pd.DataFrame) -> List[str]:
    """Detect columns that might contain timestamps."""
    timestamp_columns = []
    for col in df.columns:
        # First check by name
        col_lower = col.lower().strip()
        if any(ts_name in col_lower for ts_name in ['time', 'date', 'when', '@timestamp', 'created', 'occurred']):
            timestamp_columns.append(col)
            continue
        
        # Then check by content
        if df[col].dtype == 'object':
            sample = df[col].dropna().head(50)
            if len(sample) == 0:
                continue
            
            timestamp_count = 0
            for val in sample:
                try:
                    pd.to_datetime(str(val))
                    timestamp_count += 1
                except:
                    continue
            
            if timestamp_count / len(sample) > 0.5:
                timestamp_columns.append(col)
    
    return timestamp_columns

def generate_synthetic_asn(ip_series: pd.Series) -> pd.Series:
    """Generate synthetic ASN numbers based on IP ranges for demo purposes."""
    def ip_to_asn(ip):
        try:
            ip_obj = ipaddress.IPv4Address(str(ip))
            # Simple mapping based on first octet for demo
            first_octet = int(str(ip_obj).split('.')[0])
            if first_octet < 64:
                return f"AS{7922 + (first_octet % 100)}"  # Comcast range
            elif first_octet < 128:
                return f"AS{13335 + (first_octet % 50)}"  # Cloudflare range
            elif first_octet < 192:
                return f"AS{16509 + (first_octet % 30)}"  # Amazon range
            else:
                return f"AS{8075 + (first_octet % 200)}"   # Microsoft range
        except:
            return "AS0"
    
    return ip_series.apply(ip_to_asn)

def generate_synthetic_country(ip_series: pd.Series) -> pd.Series:
    """Generate synthetic country codes based on IP ranges."""
    def ip_to_country(ip):
        try:
            ip_obj = ipaddress.IPv4Address(str(ip))
            first_octet = int(str(ip_obj).split('.')[0])
            # Simple geographic mapping
            if first_octet < 50:
                return "US"
            elif first_octet < 100:
                return "CN"
            elif first_octet < 120:
                return "RU"
            elif first_octet < 140:
                return "GB"
            elif first_octet < 160:
                return "DE"
            elif first_octet < 180:
                return "JP"
            elif first_octet < 200:
                return "FR"
            else:
                return "CA"
        except:
            return "XX"
    
    return ip_series.apply(ip_to_country)

def normalize_columns(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Intelligently normalize columns with detailed mapping report."""
    if df.empty:
        return df, {"status": "empty_dataframe", "mappings": {}, "synthetic": []}
    
    out = df.copy()
    mapping_report = {"mappings": {}, "synthetic": [], "detected": {}}
    
    # Create lowercase mapping for fuzzy matching
    lower_map = {c.lower().strip(): c for c in out.columns}
    renames = {}
    
    # First pass: exact and fuzzy matching
    for std_name, candidates in COL_MAP.items():
        found = False
        for candidate in candidates:
            if candidate.lower() in lower_map:
                original_col = lower_map[candidate.lower()]
                renames[original_col] = std_name
                mapping_report["mappings"][std_name] = original_col
                found = True
                break
        
        if not found and std_name in ["ip", "timestamp"]:
            # Use detection algorithms for critical columns
            if std_name == "ip":
                detected_ips = detect_ip_columns(out)
                if detected_ips:
                    renames[detected_ips[0]] = "ip"
                    mapping_report["mappings"]["ip"] = detected_ips[0]
                    mapping_report["detected"]["ip"] = detected_ips
            elif std_name == "timestamp":
                detected_ts = detect_timestamp_columns(out)
                if detected_ts:
                    renames[detected_ts[0]] = "timestamp"
                    mapping_report["mappings"]["timestamp"] = detected_ts[0]
                    mapping_report["detected"]["timestamp"] = detected_ts
    
    # Apply renames
    out = out.rename(columns=renames)
    
    # Generate missing critical columns
    required_cols = ["ip", "asn", "country", "timestamp", "event_type", "status", "user"]
    for req_col in required_cols:
        if req_col not in out.columns:
            if req_col == "asn" and "ip" in out.columns:
                out["asn"] = generate_synthetic_asn(out["ip"])
                mapping_report["synthetic"].append(f"asn (from ip)")
            elif req_col == "country" and "ip" in out.columns:
                out["country"] = generate_synthetic_country(out["ip"])
                mapping_report["synthetic"].append(f"country (from ip)")
            elif req_col == "timestamp":
                # Generate timestamps over last 24 hours
                base_time = datetime.now() - timedelta(hours=24)
                out["timestamp"] = [base_time + timedelta(minutes=i*5) for i in range(len(out))]
                mapping_report["synthetic"].append("timestamp (last 24h)")
            elif req_col == "event_type":
                # Infer from other columns or create generic
                if "port" in out.columns:
                    out["event_type"] = out.get("port", 80).apply(
                        lambda p: "web_request" if p in [80, 443] else 
                                 "ssh_attempt" if p == 22 else 
                                 "network_request"
                    )
                else:
                    out["event_type"] = "network_request"
                mapping_report["synthetic"].append("event_type (inferred)")
            elif req_col == "status":
                # Generate realistic success/failure ratio
                out["status"] = np.random.choice(
                    ["success", "failure"], 
                    size=len(out), 
                    p=[0.85, 0.15]  # 85% success rate
                )
                mapping_report["synthetic"].append("status (random)")
            elif req_col == "user":
                # Generate generic usernames
                out["user"] = [f"user_{i%1000:03d}" for i in range(len(out))]
                mapping_report["synthetic"].append("user (generated)")
            else:
                out[req_col] = np.nan
    
    # Normalize data types and values
    if "timestamp" in out.columns:
        out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce")
    
    if "status" in out.columns:
        out["status"] = (
            out["status"].astype(str).str.lower()
            .replace({
                "failed": "failure", "fail": "failure", "error": "failure", 
                "denied": "failure", "blocked": "failure", "reject": "failure",
                "ok": "success", "allow": "success", "permit": "success",
                "accept": "success", "pass": "success"
            })
        )
    
    if "event_type" in out.columns:
        out["event_type"] = out["event_type"].astype(str).str.lower().str.replace(" ", "_")
    
    # Handle geo coordinates
    for geo_col in ["lat", "lon"]:
        if geo_col in out.columns:
            out[geo_col] = pd.to_numeric(out[geo_col], errors="coerce")
    
    # Fill NaN values to prevent crashes
    for col in ["country", "asn", "ip", "event_type", "status", "user"]:
        if col in out.columns:
            out[col] = out[col].fillna("unknown")
    
    mapping_report["status"] = "success"
    mapping_report["total_rows"] = len(out)
    mapping_report["total_columns"] = len(out.columns)
    
    return out, mapping_report

def mark_country_high_risk(df: pd.DataFrame, failure_rate_cutoff: float = 0.5) -> pd.DataFrame:
    """Enhanced country risk marking with more sophisticated logic."""
    out = df.copy()
    if out.empty: 
        out["country_high_risk"] = False
        return out
    
    # Calculate failure rates by country
    country_stats = out.groupby("country").agg({
        "status": [
            lambda x: (x == "failure").sum(),  # failure count
            "count"  # total count
        ]
    }).round(3)
    
    country_stats.columns = ["failure_count", "total_count"]
    country_stats["failure_rate"] = country_stats["failure_count"] / country_stats["total_count"]
    
    # Countries with high failure rate OR suspicious patterns
    risky_countries = set()
    
    for country, stats in country_stats.iterrows():
        if stats["failure_rate"] > failure_rate_cutoff:
            risky_countries.add(country)
        # Also flag countries with very high absolute failure counts
        elif stats["failure_count"] > 100 and stats["failure_rate"] > 0.3:
            risky_countries.add(country)
    
    out["country_high_risk"] = out["country"].isin(risky_countries)
    return out

def mark_multiple_attempts(df: pd.DataFrame, attempt_threshold: int = 5) -> pd.DataFrame:
    """Enhanced multiple attempts detection with time-based analysis."""
    out = df.copy()
    if out.empty:
        out["multiple_attempts"] = False
        return out
    
    # Focus on failures only
    fails = out[out["status"] == "failure"].copy()
    if fails.empty:
        out["multiple_attempts"] = False
        return out
    
    # Count by ASN+IP combination
    attempt_counts = fails.groupby(["asn", "ip"]).agg({
        "timestamp": ["count", "min", "max"]
    })
    attempt_counts.columns = ["attempt_count", "first_attempt", "last_attempt"]
    attempt_counts["time_span"] = (
        attempt_counts["last_attempt"] - attempt_counts["first_attempt"]
    ).dt.total_seconds() / 3600  # hours
    
    # Flag combinations with many attempts, especially if in short timeframe
    suspicious = attempt_counts[
        (attempt_counts["attempt_count"] >= attempt_threshold) |
        ((attempt_counts["attempt_count"] >= 3) & (attempt_counts["time_span"] < 1))
    ].reset_index()
    
    if suspicious.empty:
        out["multiple_attempts"] = False
        return out
    
    # Create lookup key
    suspicious["lookup_key"] = (
        suspicious["asn"].astype(str) + "|" + suspicious["ip"].astype(str)
    )
    out["lookup_key"] = out["asn"].astype(str) + "|" + out["ip"].astype(str)
    out["multiple_attempts"] = out["lookup_key"].isin(set(suspicious["lookup_key"]))
    out = out.drop(columns=["lookup_key"])
    
    return out

def mark_ddos_like(df: pd.DataFrame, per_min_threshold: int = 80) -> pd.DataFrame:
    """Enhanced DDoS detection with multiple metrics."""
    out = df.copy()
    if out.empty:
        out["ddos_like"] = False
        return out
    
    # Look for network-related events
    network_events = out[
        out["event_type"].str.contains("network|request|http|tcp|udp", na=False, case=False)
    ].copy()
    
    if network_events.empty:
        out["ddos_like"] = False
        return out
    
    network_events["minute"] = network_events["timestamp"].dt.floor("min")
    
    # Calculate per-minute volumes by IP
    volume_stats = network_events.groupby(["ip", "minute"]).agg({
        "timestamp": "count"
    }).rename(columns={"timestamp": "requests_per_min"}).reset_index()
    
    # Also look at overall patterns
    ip_stats = network_events.groupby("ip").agg({
        "timestamp": ["count", "min", "max"]
    })
    ip_stats.columns = ["total_requests", "first_request", "last_request"]
    ip_stats["duration_hours"] = (
        ip_stats["last_request"] - ip_stats["first_request"]
    ).dt.total_seconds() / 3600
    ip_stats["avg_requests_per_hour"] = ip_stats["total_requests"] / ip_stats["duration_hours"].clip(lower=0.1)
    
    # Flag IPs with burst behavior or sustained high volume
    ddos_ips = set()
    
    # Burst detection
    burst_ips = volume_stats[volume_stats["requests_per_min"] >= per_min_threshold]["ip"].unique()
    ddos_ips.update(burst_ips)
    
    # Sustained high volume
    sustained_ips = ip_stats[
        (ip_stats["avg_requests_per_hour"] > 500) & (ip_stats["duration_hours"] > 0.5)
    ].index
    ddos_ips.update(sustained_ips)
    
    out["ddos_like"] = out["ip"].isin(ddos_ips)
    return out

def validate_csv_structure(df: pd.DataFrame) -> Dict[str, Any]:
    """Validate CSV structure and provide recommendations."""
    validation = {
        "is_valid": True,
        "warnings": [],
        "recommendations": [],
        "stats": {}
    }
    
    if df.empty:
        validation["is_valid"] = False
        validation["warnings"].append("CSV is empty")
        return validation
    
    # Check for common issues
    if len(df.columns) < 3:
        validation["warnings"].append(f"Only {len(df.columns)} columns detected - may be missing important data")
    
    # Check for duplicate rows
    duplicate_count = df.duplicated().sum()
    if duplicate_count > 0:
        validation["warnings"].append(f"{duplicate_count} duplicate rows found")
        validation["recommendations"].append("Consider removing duplicates for cleaner analysis")
    
    # Check data quality
    null_percentages = (df.isnull().sum() / len(df) * 100).round(1)
    high_null_cols = null_percentages[null_percentages > 50].index.tolist()
    if high_null_cols:
        validation["warnings"].append(f"Columns with >50% missing data: {high_null_cols}")
    
    validation["stats"] = {
        "rows": len(df),
        "columns": len(df.columns),
        "duplicates": duplicate_count,
        "null_percentages": null_percentages.to_dict()
    }
    
    return validation