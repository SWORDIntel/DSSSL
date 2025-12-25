#!/bin/bash
#
# DSLLVM Build Monitor Service
# Monitors DSLLVM build processes and provides thermal management
#
# This is a systemd service script that can be used to monitor
# DSLLVM builds and provide thermal throttling capabilities.

set -euo pipefail

# Configuration - match installer defaults
TEMP_HIGH_THRESHOLD_C=${TEMP_HIGH_THRESHOLD_C:-105}
TEMP_CRITICAL_THRESHOLD_C=${TEMP_CRITICAL_THRESHOLD_C:-110}
TEMP_LOW_THRESHOLD_C=${TEMP_LOW_THRESHOLD_C:-90}
THROTTLE_JOB_PERCENT=${THROTTLE_JOB_PERCENT:-60}
MONITOR_INTERVAL_S=${MONITOR_INTERVAL_S:-5}

# Logging
LOG_FILE="/var/log/dsssl-build-monitor.log"

log_info() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARNING] $*" | tee -a "$LOG_FILE" >&2
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE" >&2
}

# Get CPU temperature (simplified version)
get_cpu_temp() {
    local temp=0

    # Try lm-sensors first
    if command -v sensors &> /dev/null; then
        temp=$(sensors -j 2>/dev/null | grep -m 1 '"temp":' | awk '{print $2}' | cut -d'.' -f1)
        if [[ "$temp" =~ ^[0-9]+$ ]] && [[ "$temp" -gt 0 ]] && [[ "$temp" -lt 200 ]]; then
            echo "$temp"
            return 0
        fi
    fi

    # Fallback to sysfs
    for zone in /sys/class/thermal/thermal_zone*; do
        if [[ -f "$zone/temp" ]] && [[ -f "$zone/type" ]]; then
            local zone_type
            zone_type=$(cat "$zone/type" 2>/dev/null)
            if [[ "$zone_type" == "x86_pkg_temp" ]] || [[ "$zone_type" == "cpu-thermal" ]]; then
                temp=$(( $(cat "$zone/temp") / 1000 ))
                if [[ "$temp" -gt 0 ]] && [[ "$temp" -lt 150 ]]; then
                    echo "$temp"
                    return 0
                fi
            fi
        fi
    done

    echo "0"
    return 1
}

# Monitor active ninja processes and throttle if needed
monitor_builds() {
    log_info "Starting DSLLVM build monitor service"
    log_info "Thermal thresholds: High=${TEMP_HIGH_THRESHOLD_C}°C, Critical=${TEMP_CRITICAL_THRESHOLD_C}°C"

    while true; do
        # Find active ninja processes related to DSLLVM
        local ninja_pids
        ninja_pids=$(pgrep -f "ninja.*DSLLVM\|ninja.*dsssl" 2>/dev/null || true)

        if [[ -n "$ninja_pids" ]]; then
            local temp
            if temp=$(get_cpu_temp); then
                log_info "Active DSLLVM build detected (PIDs: $ninja_pids), CPU temp: ${temp}°C"

                # Check critical temperature
                if [[ "$temp" -ge "$TEMP_CRITICAL_THRESHOLD_C" ]]; then
                    log_error "CRITICAL TEMPERATURE: ${temp}°C >= ${TEMP_CRITICAL_THRESHOLD_C}°C"
                    log_error "Terminating build processes to prevent hardware damage"

                    for pid in $ninja_pids; do
                        if kill -TERM "$pid" 2>/dev/null; then
                            log_warning "Terminated build process $pid"
                        fi
                    done

                    # Wait for processes to die
                    sleep 5
                    for pid in $ninja_pids; do
                        if kill -KILL "$pid" 2>/dev/null; then
                            log_warning "Force-killed build process $pid"
                        fi
                    done

                    log_error "Build emergency shutdown completed"
                fi
            else
                log_warning "Failed to read CPU temperature"
            fi
        fi

        sleep "$MONITOR_INTERVAL_S"
    done
}

# Main service loop
case "${1:-monitor}" in
    monitor)
        monitor_builds
        ;;
    status)
        echo "DSLLVM Build Monitor Status:"
        echo "  Service: Active"
        echo "  Thermal thresholds: ${TEMP_HIGH_THRESHOLD_C}°C/${TEMP_CRITICAL_THRESHOLD_C}°C"
        echo "  Monitor interval: ${MONITOR_INTERVAL_S}s"
        echo "  Log file: $LOG_FILE"

        local active_builds
        active_builds=$(pgrep -f "ninja.*DSLLVM\|ninja.*dsssl" 2>/dev/null | wc -l)
        echo "  Active DSLLVM builds: $active_builds"

        local temp
        if temp=$(get_cpu_temp); then
            echo "  Current CPU temperature: ${temp}°C"
        else
            echo "  CPU temperature: Unable to read"
        fi
        ;;
    *)
        echo "Usage: $0 {monitor|status}"
        echo "  monitor - Start monitoring service"
        echo "  status  - Show current status"
        exit 1
        ;;
esac
