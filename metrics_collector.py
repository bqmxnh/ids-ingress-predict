#!/usr/bin/env python3

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
        with self.lock:
            self.total_attempts += 1
            if success:
                self.successful += 1
                self.latencies.append(latency_ms)
            else:
                self.failed += 1
            
            self.last_redirection_time = time.time()
            
            record = {
                "flow_id": flow_id,
                "timestamp": datetime.now().isoformat(),
                "latency_ms": round(latency_ms, 3),
                "success": success,
                "error": error_msg
            }
            # Lưu record vào deque để có dữ liệu cho hàm export_json
            self.redirections.append(record)
            
            # Log slow redirections (> 10ms threshold from paper)
            if latency_ms > 10.0:
                logger.warning(f"[SLOW] Flow {str(flow_id)[:16]} took {latency_ms:.2f}ms (>10ms threshold)")
    
    def get_stats(self):
        with self.lock:
            if not self.latencies:
                return {
                    "status": "no_data",
                    "message": "No redirections recorded yet",
                    "summary": {
                        "total_attempts": self.total_attempts,
                        "successful": self.successful,
                        "failed": self.failed,
                        "success_rate_percent": 0,
                        "uptime_seconds": round(time.time() - self.start_time, 2),
                        "throughput_per_second": 0
                    }
                }
            
            latencies_list = sorted(self.latencies)
            n = len(latencies_list)
            
            mean_lat = sum(latencies_list) / n
            min_lat = latencies_list[0]
            max_lat = latencies_list[-1]

            # Tính Percentile thủ công (không cần numpy)
            p50 = latencies_list[int(n * 0.5)]
            p90 = latencies_list[int(n * 0.9)]
            p95 = latencies_list[int(n * 0.95)]
            # Fix lỗi index out of range cho p99 nếu n < 100
            idx_99 = int(n * 0.99)
            p99 = latencies_list[idx_99] if idx_99 < n else max_lat
            
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
                    "success_rate_percent": round((self.successful / self.total_attempts * 100), 2),
                    "uptime_seconds": round(uptime_seconds, 2),
                    "throughput_per_second": round(throughput, 2)
                },
                "latency_ms": {
                    "mean": round(mean_lat, 3),
                    "median": round(p50, 3),
                    "min": round(min_lat, 3),
                    "max": round(max_lat, 3),
                    "p90": round(p90, 3),
                    "p95": round(p95, 3),
                    "p99": round(p99, 3)
                },
                "stealth_analysis": {
                    "below_10ms_count": below_10ms,
                    "below_10ms_percent": round(below_10ms / n * 100, 2),
                    "stealth_requirement_met": (below_10ms / n) >= 0.95 # Paper yêu cầu 95%
                },
                "baseline_comparison": {
                    "paper_mean_ms": 2.3,
                    "paper_max_ms": 8.7,
                    "our_mean_ms": round(mean_lat, 3),
                    "our_max_ms": round(max_lat, 3),
                    "mean_delta_ms": round(mean_lat - 2.3, 3),
                    "max_delta_ms": round(max_lat - 8.7, 3),
                    "reference": "Beltran Lopez et al. (2024)"
                }
            }
            
            return stats

    def reset_stats(self):
        with self.lock:
            self.latencies.clear()
            self.redirections.clear()
            self.total_attempts = 0
            self.successful = 0
            self.failed = 0
            self.start_time = time.time()

    # --- CÁC HÀM DƯỚI ĐÂY CẦN THIẾT CHO APPLICATION.PY ---
    
    def export_json(self, filepath):
        """Export metrics to JSON file"""
        try:
            stats = self.get_stats()
            # Thêm danh sách chi tiết 100 record cuối để debug
            with self.lock:
                stats["recent_redirections"] = list(self.redirections)[-100:]
                
            with open(filepath, 'w') as f:
                json.dump(stats, f, indent=2)
            logger.info(f"[METRICS] Exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"[METRICS] Export failed: {e}")
            return False

    def get_summary_text(self):
        """Get human-readable summary"""
        s = self.get_stats()
        if s.get("status") == "no_data":
            return "No redirection data available."
            
        lat = s["latency_ms"]
        summ = s["summary"]
        stealth = s["stealth_analysis"]
        
        return (
            f"=== REDIRECTION PERFORMANCE ===\n"
            f"Total: {summ['total_attempts']} | Success: {summ['success_rate_percent']}%\n"
            f"Latency (ms): Mean={lat['mean']} | P95={lat['p95']} | Max={lat['max']}\n"
            f"Stealth (<10ms): {stealth['below_10ms_percent']}% ({'Pass' if stealth['stealth_requirement_met'] else 'Fail'})\n"
        )

# Global metrics instance
metrics = RedirectionMetrics()
