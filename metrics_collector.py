#!/usr/bin/env python3
"""
Traffic Redirection Performance Metrics Collector
Measures latency and throughput as per Beltran Lopez et al. (2024)

Reference: 
  Beltran Lopez, P., et al. (2024). Cyber Deception Reactive:   
  TCP Stealth Redirection to On-Demand Honeypots. arXiv:2402.09191v2
  
Baseline metrics from paper:
  - Mean latency: 2.3ms
  - Max latency: 8.7ms
  - Detection rate: 0% (stealth requirement)
"""

import time
import threading
import json
from collections import deque
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class RedirectionMetrics:
    """
    Tracks performance metrics for traffic redirection to honeypot
    """
    
    def __init__(self, max_samples=10000):
        self.max_samples = max_samples
        self.latencies = deque(maxlen=max_samples)
        self.redirections = deque(maxlen=max_samples)
        self.lock = threading.Lock()
        
        # Counters
        self.total_attempts = 0
        self.successful = 0
        self.failed = 0
        
        # Timestamps
        self.start_time = time.time()
        self.last_redirection_time = None
        
    def record_redirection(self, flow_id, latency_ms, success, error_msg=None):
        """
        Record a single redirection event
        
        Args:
            flow_id: Flow identifier
            latency_ms:  Redirection latency in milliseconds
            success: Boolean indicating if redirection succeeded
            error_msg: Error message if failed
        """
        with self. lock:
            self.total_attempts += 1
            if success:
                self.successful += 1
            else:
                self.failed += 1
            
            self.latencies.append(latency_ms)
            self.last_redirection_time = time.time()
            
            record = {
                "flow_id": flow_id,
                "timestamp": datetime.now().isoformat(),
                "latency_ms": round(latency_ms, 3),
                "success": success,
                "error":  error_msg
            }
            self.redirections.append(record)
            
            # Log slow redirections (> 10ms threshold from paper)
            if latency_ms > 10.0:
                logger.warning(f"[SLOW] Flow {flow_id[: 16]} took {latency_ms:. 2f}ms (>10ms threshold)")
    
    def get_stats(self):
        """
        Get comprehensive statistics
        
        Returns: 
            dict: Statistics including latency percentiles and comparison with baseline
        """
        with self.lock:
            if not self.latencies:
                return {
                    "status": "no_data",
                    "message": "No redirections recorded yet"
                }
            
            latencies_list = sorted(self.latencies)
            n = len(latencies_list)
            
            # Calculate percentiles
            p50 = latencies_list[n // 2]
            p90 = latencies_list[int(n * 0.9)]
            p95 = latencies_list[int(n * 0.95)]
            p99 = latencies_list[int(n * 0.99)]
            
            mean_lat = sum(latencies_list) / n
            min_lat = min(latencies_list)
            max_lat = max(latencies_list)
            
            # Count below thresholds
            below_10ms = sum(1 for l in latencies_list if l < 10.0)
            below_5ms = sum(1 for l in latencies_list if l < 5.0)
            
            # Runtime
            uptime_seconds = time.time() - self.start_time
            throughput = self.total_attempts / uptime_seconds if uptime_seconds > 0 else 0
            
            stats = {
                "summary": {
                    "total_attempts": self.total_attempts,
                    "successful": self.successful,
                    "failed": self.failed,
                    "success_rate_percent": (self.successful / self. total_attempts * 100) if self.total_attempts > 0 else 0,
                    "uptime_seconds": round(uptime_seconds, 2),
                    "throughput_per_second": round(throughput, 2)
                },
                "latency_ms":  {
                    "mean": round(mean_lat, 3),
                    "median": round(p50, 3),
                    "min": round(min_lat, 3),
                    "max":  round(max_lat, 3),
                    "p90": round(p90, 3),
                    "p95":  round(p95, 3),
                    "p99": round(p99, 3)
                },
                "stealth_analysis": {
                    "below_10ms_count": below_10ms,
                    "below_10ms_percent": round(below_10ms / n * 100, 2),
                    "below_5ms_count": below_5ms,
                    "below_5ms_percent": round(below_5ms / n * 100, 2),
                    "stealth_requirement_met": (below_10ms / n) >= 0.95  # 95% below 10ms
                },
                "baseline_comparison": {
                    "paper_mean_ms": 2.3,
                    "paper_max_ms": 8.7,
                    "our_mean_ms": round(mean_lat, 3),
                    "our_max_ms": round(max_lat, 3),
                    "mean_delta_ms": round(mean_lat - 2.3, 3),
                    "max_delta_ms": round(max_lat - 8.7, 3),
                    "reference":  "Beltran Lopez et al. (2024) - arXiv:2402.09191v2"
                },
                "recent_samples": list(self.redirections)[-10:]  # Last 10 redirections
            }
            
            return stats
    
    def export_json(self, filepath="/home/ubuntu/logs/redirection_metrics.json"):
        """Export metrics to JSON file"""
        stats = self.get_stats()
        try:
            with open(filepath, 'w') as f:
                json.dump(stats, f, indent=2)
            logger.info(f"[METRICS] Exported to {filepath}")
            return True
        except Exception as e: 
            logger.error(f"[METRICS] Export failed: {e}")
            return False
    
    def get_summary_text(self):
        """Get human-readable summary"""
        stats = self.get_stats()
        if stats. get("status") == "no_data":
            return "No redirection data available"
        
        lat = stats["latency_ms"]
        stealth = stats["stealth_analysis"]
        baseline = stats["baseline_comparison"]
        
        summary = f"""
=== TRAFFIC REDIRECTION PERFORMANCE ===
Total Redirections: {stats['summary']['total_attempts']}
Success Rate: {stats['summary']['success_rate_percent']:.1f}%
Throughput: {stats['summary']['throughput_per_second']:.2f} redirections/sec

Latency Statistics:
  Mean: {lat['mean']}ms  | Paper: {baseline['paper_mean_ms']}ms (Δ {baseline['mean_delta_ms']: +.2f}ms)
  Median: {lat['median']}ms
  P95: {lat['p95']}ms
  Max: {lat['max']}ms  | Paper: {baseline['paper_max_ms']}ms (Δ {baseline['max_delta_ms']:+.2f}ms)

Stealth Requirement (<10ms):
  {stealth['below_10ms_percent']}% of redirections
  Status: {'✅ MET' if stealth['stealth_requirement_met'] else '❌ NOT MET'}

Reference: {baseline['reference']}
=========================================
"""
        return summary

# Global metrics instance
metrics = RedirectionMetrics()
