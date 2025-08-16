# anomaly_detection.py — Enhanced with ML-like features and advanced risk scoring
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

def calculate_risk_score(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate numeric risk scores using multiple factors."""
    out = df.copy()
    
    # Initialize risk score
    out["risk_score"] = 0.0
    
    # Factor 1: Basic flags (weighted)
    if "multiple_attempts" in out.columns:
        out["risk_score"] += out["multiple_attempts"].astype(int) * 30
    if "country_high_risk" in out.columns:
        out["risk_score"] += out["country_high_risk"].astype(int) * 25
    if "ddos_like" in out.columns:
        out["risk_score"] += out["ddos_like"].astype(int) * 40
    
    # Factor 2: Status-based scoring
    if "status" in out.columns:
        status_scores = {"failure": 20, "success": 0}
        out["risk_score"] += out["status"].map(status_scores).fillna(5)
    
    # Factor 3: Time-based anomalies (off-hours activity)
    if "timestamp" in out.columns and out["timestamp"].notna().any():
        out["hour"] = out["timestamp"].dt.hour
        # Higher risk for unusual hours (night/early morning)
        night_hours = [0, 1, 2, 3, 4, 5, 22, 23]
        out["risk_score"] += out["hour"].isin(night_hours).astype(int) * 5
    
    # Factor 4: Frequency anomalies per IP
    if "ip" in out.columns:
        ip_counts = out.groupby("ip").size()
        # IPs with unusually high activity
        high_activity_threshold = ip_counts.quantile(0.95)
        high_activity_ips = set(ip_counts[ip_counts > high_activity_threshold].index)
        out["risk_score"] += out["ip"].isin(high_activity_ips).astype(int) * 15
    
    # Factor 5: Geographic anomalies
    if "country" in out.columns:
        country_counts = out.groupby("country").size()
        rare_countries = set(country_counts[country_counts <= 3].index)
        out["risk_score"] += out["country"].isin(rare_countries).astype(int) * 10
    
    return out

def detect_temporal_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Detect temporal anomalies like unusual time patterns."""
    out = df.copy()
    out["temporal_anomaly"] = False
    
    if "timestamp" not in out.columns or out["timestamp"].isna().all():
        return out
    
    # Create time-based features
    out["hour"] = out["timestamp"].dt.hour
    out["day_of_week"] = out["timestamp"].dt.dayofweek
    out["is_weekend"] = out["day_of_week"].isin([5, 6])
    
    # Detect burst patterns (many events in short time)
    out["minute_bucket"] = out["timestamp"].dt.floor("5min")
    minute_counts = out.groupby("minute_bucket").size()
    
    # Flag minutes with unusually high activity
    if len(minute_counts) > 1:
        burst_threshold = minute_counts.quantile(0.95)
        burst_minutes = set(minute_counts[minute_counts > burst_threshold].index)
        out["temporal_anomaly"] |= out["minute_bucket"].isin(burst_minutes)
    
    # Flag off-hours activity from specific IPs
    if "ip" in out.columns:
        night_activity = out[(out["hour"] < 6) | (out["hour"] > 22)]
        if not night_activity.empty:
            night_ips = night_activity.groupby("ip").size()
            frequent_night_ips = set(night_ips[night_ips >= 5].index)
            out["temporal_anomaly"] |= (
                out["ip"].isin(frequent_night_ips) & 
                ((out["hour"] < 6) | (out["hour"] > 22))
            )
    
    return out

def detect_behavioral_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Detect behavioral anomalies based on user/IP patterns."""
    out = df.copy()
    out["behavioral_anomaly"] = False
    
    # User behavior anomalies
    if "user" in out.columns and "ip" in out.columns:
        # Users accessing from multiple IPs
        user_ip_counts = out.groupby("user")["ip"].nunique()
        multi_ip_users = set(user_ip_counts[user_ip_counts > 5].index)
        out["behavioral_anomaly"] |= out["user"].isin(multi_ip_users)
        
        # IPs used by multiple users (potential compromise)
        ip_user_counts = out.groupby("ip")["user"].nunique()
        shared_ips = set(ip_user_counts[ip_user_counts > 10].index)
        out["behavioral_anomaly"] |= out["ip"].isin(shared_ips)
    
    # Event type anomalies
    if "event_type" in out.columns and "ip" in out.columns:
        # IPs performing diverse event types (reconnaissance)
        ip_event_diversity = out.groupby("ip")["event_type"].nunique()
        diverse_ips = set(ip_event_diversity[ip_event_diversity > 3].index)
        out["behavioral_anomaly"] |= out["ip"].isin(diverse_ips)
    
    return out

def assign_risk_levels(df: pd.DataFrame) -> pd.DataFrame:
    """Enhanced risk level assignment with numeric scoring."""
    out = df.copy()
    
    # Ensure flag columns exist
    for col in ["multiple_attempts", "country_high_risk", "ddos_like"]:
        if col not in out.columns:
            out[col] = False
    
    # Calculate comprehensive risk score
    out = calculate_risk_score(out)
    out = detect_temporal_anomalies(out)
    out = detect_behavioral_anomalies(out)
    
    # Add anomaly bonuses to risk score
    if "temporal_anomaly" in out.columns:
        out["risk_score"] += out["temporal_anomaly"].astype(int) * 15
    if "behavioral_anomaly" in out.columns:
        out["risk_score"] += out["behavioral_anomaly"].astype(int) * 20
    
    # Convert numeric score to categorical levels
    def score_to_level(score):
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        elif score >= 10:
            return "Low"
        else:
            return "Minimal"
    
    out["risk_level"] = out["risk_score"].apply(score_to_level)
    
    # Legacy rule-based backup for compatibility
    def legacy_rule(row):
        if row["ddos_like"] or (row["multiple_attempts"] and row["country_high_risk"]):
            return "High"
        if row["multiple_attempts"] or row["country_high_risk"] or str(row.get("status","")).lower()=="failure":
            return "Medium"
        return "Low"
    
    # Use numeric score primarily, fall back to rules if score is 0
    mask_zero_score = out["risk_score"] == 0
    if mask_zero_score.any():
        out.loc[mask_zero_score, "risk_level"] = out.loc[mask_zero_score].apply(legacy_rule, axis=1)
    
    return out

def generate_threat_intelligence(df: pd.DataFrame) -> Dict:
    """Generate comprehensive threat intelligence summary."""
    intel = {
        "executive_summary": {},
        "top_threats": {},
        "attack_patterns": {},
        "recommendations": []
    }
    
    if df.empty:
        return intel
    
    # Executive summary
    total_events = len(df)
    risk_dist = df["risk_level"].value_counts().to_dict() if "risk_level" in df else {}
    
    intel["executive_summary"] = {
        "total_events": total_events,
        "risk_distribution": risk_dist,
        "analysis_period": {
            "start": df["timestamp"].min().isoformat() if "timestamp" in df and df["timestamp"].notna().any() else "N/A",
            "end": df["timestamp"].max().isoformat() if "timestamp" in df and df["timestamp"].notna().any() else "N/A"
        },
        "critical_alerts": int(df[df["risk_level"] == "Critical"].shape[0]) if "risk_level" in df else 0
    }
    
    # Top threats by various dimensions
    intel["top_threats"] = {}
    
    if "ip" in df.columns:
        high_risk_events = df[df.get("risk_level", "Low").isin(["High", "Critical"])]
        if not high_risk_events.empty:
            intel["top_threats"]["malicious_ips"] = (
                high_risk_events["ip"].value_counts().head(10).to_dict()
            )
    
    if "country" in df.columns:
        intel["top_threats"]["threat_countries"] = (
            df[df.get("country_high_risk", False)]["country"].value_counts().head(10).to_dict()
        )
    
    if "asn" in df.columns and "risk_score" in df.columns:
        asn_risk = df.groupby("asn")["risk_score"].mean().sort_values(ascending=False)
        intel["top_threats"]["suspicious_asns"] = asn_risk.head(10).to_dict()
    
    # Attack patterns
    if "temporal_anomaly" in df.columns:
        intel["attack_patterns"]["temporal_attacks"] = int(df["temporal_anomaly"].sum())
    if "behavioral_anomaly" in df.columns:
        intel["attack_patterns"]["behavioral_attacks"] = int(df["behavioral_anomaly"].sum())
    if "ddos_like" in df.columns:
        intel["attack_patterns"]["ddos_attempts"] = int(df["ddos_like"].sum())
    if "multiple_attempts" in df.columns:
        intel["attack_patterns"]["brute_force_attempts"] = int(df["multiple_attempts"].sum())
    
    # Generate recommendations
    recommendations = []
    
    if intel["executive_summary"]["critical_alerts"] > 0:
        recommendations.append("IMMEDIATE: Investigate critical alerts - potential active threats detected")
    
    if "top_threats" in intel and "malicious_ips" in intel["top_threats"]:
        top_malicious = intel["top_threats"]["malicious_ips"]
        if top_malicious:
            top_ip = max(top_malicious.keys(), key=lambda k: top_malicious[k])
            recommendations.append(f"Consider blocking IP {top_ip} - highest threat activity ({top_malicious[top_ip]} incidents)")
    
    if intel["attack_patterns"].get("ddos_attempts", 0) > 0:
        recommendations.append("Implement rate limiting - DDoS-like patterns detected")
    
    if intel["attack_patterns"].get("brute_force_attempts", 0) > 10:
        recommendations.append("Enable account lockout policies - multiple brute force attempts detected")
    
    if intel["attack_patterns"].get("temporal_attacks", 0) > 0:
        recommendations.append("Review off-hours access policies - suspicious temporal patterns found")
    
    # Risk-based recommendations
    high_risk_ratio = risk_dist.get("High", 0) + risk_dist.get("Critical", 0)
    if high_risk_ratio > total_events * 0.1:  # >10% high risk
        recommendations.append("ALERT: High risk event ratio >10% - review security controls")
    
    intel["recommendations"] = recommendations
    return intel