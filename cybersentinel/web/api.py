"""CyberSentinel Web API Backend

Provides REST endpoints for:
- File upload and analysis
- URL scanning
- Real-time threat monitoring
- Quarantine management
- Statistics and reporting
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import asyncio
import os
import queue
import threading
from pathlib import Path
from datetime import datetime
import logging

from cybersentinel.common.event_bus import EventBus
from cybersentinel.orchestrator import ThreatOrchestrator
from cybersentinel.monitoring.monitor import FileMonitor
from cybersentinel.quarantine.manager import QuarantineManager
from cybersentinel.common import EventType
from cybersentinel.malware_engine.analyzer import MalwareEngine
from cybersentinel.phishing_engine.analyzer import PhishingEngine
from cybersentinel.service.background_agent import BackgroundAgent
from cybersentinel.notifications.desktop_notifications import DesktopNotifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for browser extension

# Configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
UPLOAD_FOLDER = Path("./uploads/temp")
QUARANTINE_FOLDER = Path("./quarantine")
HOME = Path.home()
DEFAULT_DOWNLOADS = HOME / "Downloads"
MONITORED_PATHS = [str(Path("./monitored")), str(DEFAULT_DOWNLOADS)]

# Initialize security components
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
QUARANTINE_FOLDER.mkdir(parents=True, exist_ok=True)

event_bus = EventBus()
orchestrator = ThreatOrchestrator(event_bus=event_bus)
malware_engine = MalwareEngine()
phishing_engine = PhishingEngine()
for index, analyzer in enumerate(malware_engine.analyzers):
    orchestrator.register_malware_engine(f"malware_layer_{index + 1}", analyzer)
for index, analyzer in enumerate(phishing_engine.analyzers):
    orchestrator.register_phishing_engine(f"phishing_layer_{index + 1}", analyzer)
metamorphic_detector = malware_engine.metamorphic
quarantine_manager = QuarantineManager(quarantine_root=str(QUARANTINE_FOLDER))
file_monitor = FileMonitor(
    paths=[str(p) for p in MONITORED_PATHS],
    event_bus=event_bus,
    poll_interval=0.25
)

# Store for async task tracking
active_analyses = {}
analysis_queue = queue.Queue(maxsize=64)
analysis_stop = threading.Event()
analysis_workers = []
analysis_in_progress = set()
analysis_metrics = {"completed": 0, "failed": 0, "dropped": 0}

background_agent = BackgroundAgent(
    orchestrator=orchestrator,
    file_monitor=file_monitor,
    analysis_queue=analysis_queue,
    metrics=analysis_metrics,
    monitored_paths=[str(p) for p in MONITORED_PATHS],
)
notifier = DesktopNotifier()

# Wire the shared engine's response actions. Real-time detections (worker thread)
# quarantine + notify; a manual website upload only reports (auto_quarantine off).
orchestrator.notifier = notifier
orchestrator.quarantine_manager = quarantine_manager
orchestrator.auto_quarantine = False


def _handle_threat_detected(event) -> None:
    """Safety net for a high-risk file the orchestrator did not already isolate.

    The orchestrator quarantines (never deletes) on the real-time path. This
    handler only acts if the file still exists AND still sits in a monitored
    download directory - it moves it into quarantine (it never permanently
    deletes and never touches OS antivirus settings).
    """
    try:
        data = event.data or {}
        file_path = data.get("file_path")
        score = float(data.get("risk_score", 0.0) or 0.0)
        if not file_path or score < 80:
            return
        candidate = Path(file_path).resolve()
        if not candidate.exists() or candidate.is_dir():
            return  # already quarantined / removed
        if not any(str(candidate).startswith(str(Path(p).resolve())) for p in MONITORED_PATHS):
            return
        try:
            record = quarantine_manager.quarantine_file(
                file_path=str(candidate),
                threat_type="malware",
                risk_score=score,
                explanation=str(data.get("explanation", "High-risk download")),
                threat_name=str(data.get("classification", "malware")),
            )
            logger.warning("Quarantined high-risk download (%.0f%%): %s -> %s",
                           score, file_path, record.get("quarantine_path"))
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.error("Failed to quarantine malicious download %s: %s", file_path, exc)
    except Exception as exc:
        logger.error("Threat-detected handler failed: %s", exc)


event_bus.subscribe(EventType.THREAT_DETECTED, _handle_threat_detected)


def _analysis_worker() -> None:
    while not analysis_stop.is_set():
        try:
            file_path = analysis_queue.get(timeout=0.25)
        except queue.Empty:
            continue
        try:
            # Real-time path: enforce response actions (quarantine + desktop warning).
            asyncio.run(orchestrator.analyze_file(file_path, enforce=True))
            analysis_metrics["completed"] += 1
        except Exception as exc:
            analysis_metrics["failed"] += 1
            logger.error("Realtime analysis failed for %s: %s", file_path, exc)
        finally:
            analysis_in_progress.discard(file_path)
            analysis_queue.task_done()


def _start_analysis_workers() -> None:
    if analysis_workers and any(worker.is_alive() for worker in analysis_workers):
        return
    analysis_stop.clear()
    worker = threading.Thread(target=_analysis_worker, name="cybersentinel-analysis", daemon=True)
    analysis_workers[:] = [worker]
    worker.start()


def _stop_analysis_workers() -> None:
    analysis_stop.set()
    for worker in analysis_workers:
        worker.join(timeout=1.0)
    analysis_workers.clear()


def _enqueue_file_event(event) -> None:
    file_path = event.data.get("file_path")
    if not orchestrator.protection_active or not file_path:
        return
    try:
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size > MAX_FILE_SIZE:
            return
        if file_path in analysis_in_progress:
            return
        analysis_in_progress.add(file_path)
        analysis_queue.put_nowait(file_path)
    except (OSError, queue.Full):
        analysis_in_progress.discard(file_path)
        analysis_metrics["dropped"] += 1


event_bus.subscribe(EventType.FILE_CREATED, _enqueue_file_event)
event_bus.subscribe(EventType.FILE_MODIFIED, _enqueue_file_event)
event_bus.subscribe(EventType.FILE_DOWNLOADED, _enqueue_file_event)


@app.route('/api/v1/download/stop', methods=['POST'])
def stop_download_for_api():
    """Manual safety hook for a browser extension or local UI to stop a downloaded
    file that a backend detection event has surfaced as malicious.
    """
    payload = request.get_json(silent=True) or {}
    file_path = payload.get('file_path') or payload.get('path')
    if not file_path:
        return jsonify({"error": "file_path is required"}), 400
    path = Path(file_path)
    try:
        if path.exists() and path.is_file():
            path.unlink(missing_ok=True)
        return jsonify({"status": "stopped", "file_path": str(path)}), 200
    except Exception as exc:
        logger.error("Download stop endpoint failed for %s: %s", file_path, exc)
        return jsonify({"error": "failed_to_stop_download", "details": str(exc)}), 500


@app.route('/images/<path:filename>', methods=['GET'])
def image_asset(filename):
    """Serve the repository image assets from the same origin for the frontend UI."""
    root = Path(__file__).resolve().parents[2]
    asset = root / 'images' / filename
    if not asset.exists() or not asset.is_file():
        return jsonify({"error": "Image not found"}), 404
    return send_file(asset)


@app.route('/', methods=['GET'])
@app.route('/dashboard.html', methods=['GET'])
def dashboard():
    """Serve the browser dashboard from the same origin as the API."""
    return send_file(Path(__file__).with_name('dashboard.html'))


@app.route('/api/v1/metamorphic/layers', methods=['GET'])
def metamorphic_layers():
    """Return the configured metamorphic detection layer catalog and future layer inventory."""
    layers = metamorphic_detector.get_layer_catalog()
    return jsonify({
        "total": len(layers),
        "implemented": sum(layer["status"] == "implemented" for layer in layers),
        "partial": sum(layer["status"] == "partial" for layer in layers),
        "not_configured": sum(layer["status"] == "not_configured" for layer in layers),
        "future_surface": {
            "sandbox_research": any(layer["name"].startswith("Sandbox") for layer in layers),
            "network_investigation": any(layer["name"].startswith("Network") for layer in layers),
            "cloud_intelligence": any(layer["name"].startswith("Cloud") for layer in layers),
            "semantic_association": any(layer["name"].startswith("Semantic") for layer in layers),
            "omniscient_monitoring": any(layer["name"].startswith("Omniscient") for layer in layers),
        },
        "layers": layers,
    }), 200


@app.route('/api/v1/future/services', methods=['GET'])
def future_services():
    """Expose a structured future-services manifest for onboarding remote research and evidence services."""
    layers = metamorphic_detector.get_layer_catalog()
    service_names = {
        "Sandbox Research & Runtime Telemetry": "sandbox_research",
        "Network Investigation & Communications": "network_investigation",
        "Cloud Intelligence & Evidence Federation": "cloud_intelligence",
        "Semantic Association Explorer": "semantic_association",
        "Omniscient Monitoring Surface": "omniscient_monitoring",
    }
    surface = {
        key: any(layer["name"] == service for service in service_names)
        for service, key in service_names.items()
    }
    # Stable machine-readable shape across same-origin and extension integrations.
    return jsonify({
        "status": "future",
        "services": [
            {
                "name": service,
                "code": key,
                "mode": "not_configured",
                "description": "External, future-facing service surface requested by product requirements.",
                "integrated": False,
            }
            for service, key in service_names.items()
        ],
        "layer_count": len(layers),
    }), 200


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "phase": "Phase 4 - Full Platform"
    })


@app.route('/api/v1/file/upload', methods=['POST'])
def upload_file():
    """Upload and analyze a file for threats.
    
    Request: multipart/form-data with 'file' field
    Response: JSON with analysis_id and initial assessment
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if file.content_length and file.content_length > MAX_FILE_SIZE:
        return jsonify({"error": f"File too large (max {MAX_FILE_SIZE / 1024 / 1024:.0f} MB)"}), 413
    
    # Save uploaded file temporarily
    temp_path = UPLOAD_FOLDER / f"{datetime.utcnow().timestamp()}_{file.filename}"
    file.save(str(temp_path))
    
    # Analyze asynchronously
    analysis_id = str(temp_path)
    try:
        result = asyncio.run(orchestrator.analyze_file(str(temp_path)))
        
        active_analyses[analysis_id] = {
            "filename": file.filename,
            "result": result,
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(temp_path)
        }
        
        payload = dict(result.outcome or {})
        payload.update({
            "analysis_id": analysis_id,
            "filename": file.filename,
            # legacy keys kept for existing dashboard JS
            "risk_level": result.risk_assessment.risk_level.value,
            "risk_score": result.risk_assessment.risk_score,
            "recommendation": result.risk_assessment.recommendation,
            "analysis_time_ms": result.analysis_time_ms,
            "timestamp": datetime.utcnow().isoformat(),
        })
        return jsonify(payload), 200

    except Exception as e:
        logger.error(f"Analysis failed for {file.filename}: {str(e)}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route('/api/v1/url/scan', methods=['POST'])
def scan_url():
    """Scan a URL for phishing threats.
    
    Request: JSON with 'url' field
    Response: Risk assessment
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    url = data['url']
    
    try:
        result = asyncio.run(orchestrator.analyze_url(url))

        payload = dict(result.outcome or {})
        payload.update({
            "url": url,
            "risk_level": result.risk_assessment.risk_level.value,
            "risk_score": result.risk_assessment.risk_score,
            "recommendation": result.risk_assessment.recommendation,
            "individual_predictions": [
                {
                    "model": pred.model_name,
                    "score": pred.malicious_probability,
                    "confidence": pred.confidence,
                }
                for pred in result.risk_assessment.individual_predictions
            ],
            "timestamp": datetime.utcnow().isoformat(),
        })
        return jsonify(payload), 200

    except Exception as e:
        logger.error(f"URL scan failed for {url}: {str(e)}")
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500


@app.route('/api/v1/analysis/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    """Retrieve detailed analysis results.
    
    Response: Full risk assessment with explanations
    """
    if analysis_id not in active_analyses:
        return jsonify({"error": "Analysis not found"}), 404
    
    analysis = active_analyses[analysis_id]
    result = analysis['result']
    
    return jsonify({
        "analysis_id": analysis_id,
        "filename": analysis['filename'],
        "risk_level": result.risk_assessment.risk_level.value,
        "risk_score": result.risk_assessment.risk_score,
        "recommendation": result.risk_assessment.recommendation,
        "explanation": result.risk_assessment.explanation,
        "consensus_count": result.risk_assessment.consensus_count,
        "model_disagreement": result.risk_assessment.model_disagreement,
        "individual_predictions": [
            {
                "model": pred.model_name,
                "score": pred.risk_score,
                "confidence": pred.confidence,
                "evidence": pred.evidence
            }
            for pred in result.risk_assessment.individual_predictions
        ],
        "analysis_time_ms": result.analysis_time_ms,
        "timestamp": analysis['timestamp']
    }), 200


@app.route('/api/v1/quarantine/list', methods=['GET'])
def list_quarantine():
    """List all quarantined files (from the threat database)."""
    try:
        records = quarantine_manager.list_quarantine()
        return jsonify({"total": len(records), "records": records}), 200
    except Exception as e:
        logger.error(f"Failed to list quarantine: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/quarantine/restore/<quarantine_id>', methods=['POST'])
def restore_from_quarantine(quarantine_id):
    """Restore a quarantined file after an explicit user action.

    Body (optional): {"restore_path": "..."}  - defaults to the original path.
    """
    try:
        restore_path = (request.get_json(silent=True) or {}).get('restore_path')
        result = quarantine_manager.restore_file(quarantine_id, restore_path)
        return jsonify({
            "success": True,
            "message": f"File restored to {result}",
            "quarantine_id": quarantine_id,
            "restored_to": result,
        }), 200
    except (FileNotFoundError, ValueError) as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.error(f"Restore failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/quarantine/delete/<quarantine_id>', methods=['POST', 'DELETE'])
def delete_from_quarantine(quarantine_id):
    """Permanently delete a quarantined payload - requires explicit confirmation.

    Body: {"confirm": true}  (or ?confirm=true). Returns the real OS error on
    failure; never reports a fake success.
    """
    body = request.get_json(silent=True) or {}
    confirm = bool(body.get("confirm")) or request.args.get("confirm") == "true"
    if not confirm:
        return jsonify({"error": "confirmation required", "hint": "send {\"confirm\": true}"}), 400
    try:
        result = quarantine_manager.delete_file(quarantine_id, confirm=True)
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("Quarantine delete failed: %s", e)
        return jsonify({"error": str(e)}), 500
    status = 200 if result.get("deleted") else 500
    return jsonify(result), status


# --- sandbox (isolated on-demand deep analysis) -------------------------------
from cybersentinel.sandbox import SandboxManager  # noqa: E402

sandbox_manager = SandboxManager(root=str(Path("./sandbox_jobs")))


@app.route('/api/v1/sandbox/submit', methods=['POST'])
def sandbox_submit():
    """Run an isolated static-analysis job.

    Body: multipart 'file', OR JSON {"quarantine_id": "..."} to analyse a
    quarantined payload, OR JSON {"path": "..."} for a local path.
    The host never executes the sample.
    """
    tmp_path = None
    try:
        if 'file' in request.files:
            f = request.files['file']
            if not f.filename:
                return jsonify({"error": "no file"}), 400
            tmp_path = UPLOAD_FOLDER / f"sandbox_{datetime.utcnow().timestamp()}_{f.filename}"
            f.save(str(tmp_path))
            target = str(tmp_path)
        else:
            body = request.get_json(silent=True) or {}
            if body.get("quarantine_id"):
                rec = quarantine_manager._find_record(body["quarantine_id"])
                target = quarantine_manager._resolved_payload_path(rec).as_posix()
            elif body.get("path"):
                target = body["path"]
            else:
                return jsonify({"error": "provide a file, quarantine_id, or path"}), 400

        run_dynamic = bool((request.get_json(silent=True) or {}).get("run_dynamic"))
        job = sandbox_manager.submit(target, run_dynamic=run_dynamic)
        return jsonify(job.to_dict()), 200
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.error("Sandbox submit failed: %s", e)
        return jsonify({"error": str(e)}), 500
    finally:
        if tmp_path is not None:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass


@app.route('/api/v1/sandbox/jobs', methods=['GET'])
def sandbox_jobs():
    return jsonify({"jobs": sandbox_manager.list_jobs()}), 200


@app.route('/api/v1/sandbox/jobs/<job_id>', methods=['GET'])
def sandbox_job(job_id):
    job = sandbox_manager.get_job(job_id)
    if job is None:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job.to_dict()), 200


@app.route('/api/v1/protection/enable', methods=['POST'])
def enable_protection():
    """Enable the local background protection façade for the current runtime."""
    try:
        payload = request.get_json(silent=True) or {}
        paths = payload.get("paths") or [str(p) for p in MONITORED_PATHS]
        global file_monitor
        try:
            file_monitor.stop()
        except Exception:
            pass
        file_monitor = FileMonitor(paths=paths, event_bus=event_bus, poll_interval=0.25)
        background_agent.replace_monitor(file_monitor, paths)

        enabled = background_agent.enable()
        _start_analysis_workers()
        file_monitor.start()
        return jsonify({
            "status": "enabled",
            "protection": enabled,
            "paths": paths,
            "queue_limit": analysis_queue.maxsize,
            "timestamp": datetime.utcnow().isoformat(),
        }), 200
    except Exception as exc:
        logger.error("Protection enable failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route('/api/v1/protection/disable', methods=['POST'])
def disable_protection():
    """Disable the local background protection façade cleanly."""
    try:
        disabled = background_agent.disable()
        file_monitor.stop()
        _stop_analysis_workers()
        return jsonify({
            "status": "disabled",
            "protection": disabled,
            "timestamp": datetime.utcnow().isoformat(),
        }), 200
    except Exception as exc:
        logger.error("Protection disable failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route('/api/v1/protection/status', methods=['GET'])
def protection_status():
    """Return the local protection surface status.

    Prefers the standalone background agent's on-disk snapshot (written even
    when this website is closed); falls back to this process's own view.
    """
    from cybersentinel.service.scan_log import StatusFile

    agent_snapshot = StatusFile.read(Path(__file__).resolve().parents[2] / "logs")
    return jsonify({
        "agent": agent_snapshot,                       # None if the agent never ran
        "in_process": background_agent.get_status(),
        "source": "background_agent" if agent_snapshot else "in_process",
        "timestamp": datetime.utcnow().isoformat(),
    }), 200


@app.route('/api/v1/realtime/health', methods=['GET'])
def realtime_health():
    """Health of the real-time protection surface (spec part 22).

    Reports a component as 'active' only if it is genuinely usable - never
    'active' when the malware engine or monitor is actually unavailable.
    """
    from cybersentinel.service.scan_log import StatusFile

    logs_dir = Path(__file__).resolve().parents[2] / "logs"
    snap = StatusFile.read(logs_dir)

    # live engine check
    try:
        yara_ok = bool(malware_engine.yara.status.get("available"))
        engine_ok = yara_ok and len(malware_engine.analyzers) >= 4
        engine_state = "active" if engine_ok else "degraded"
    except Exception as exc:
        engine_state = "unavailable"
        yara_ok = False

    agent_running = bool(snap and snap.get("malware_protection") == "ACTIVE")
    in_proc = background_agent.get_status()
    monitor_active = agent_running or bool(in_proc.get("enabled"))
    queue_active = (analysis_workers and any(w.is_alive() for w in analysis_workers)) or agent_running

    try:
        notif_ok = notifier._backend in ("plyer", "powershell")
    except Exception:
        notif_ok = False

    components = {
        "service": "active" if (agent_running or orchestrator.protection_active) else "stopped",
        "file_monitor": "active" if monitor_active else "stopped",
        "analysis_queue": "active" if queue_active else "stopped",
        "malware_engine": engine_state,
        "notification_system": "active" if notif_ok else "degraded",
    }
    if engine_state in ("unavailable", "degraded") or "stopped" in (components["service"], components["file_monitor"]):
        protection = "PROTECTION DEGRADED"
    elif all(v == "active" for v in components.values()):
        protection = "PROTECTION ACTIVE"
    else:
        protection = "PROTECTION DEGRADED"
    if components["service"] == "stopped" and components["file_monitor"] == "stopped":
        protection = "PROTECTION OFFLINE"

    return jsonify({
        **components,
        "protection": protection,
        "yara": "available" if yara_ok else "unavailable",
        "last_scan": (snap or {}).get("last_scan"),
        "queue_depth": (snap or {}).get("queue_depth", in_proc.get("queue_size", 0)),
        "files_analyzed": (snap or {}).get("files_analyzed"),
        "threats_detected": (snap or {}).get("threats_detected"),
        "timestamp": datetime.utcnow().isoformat(),
    }), 200


@app.route('/api/v1/protection/scans', methods=['GET'])
def protection_scans():
    """Recent structured scan-log entries from the background agent (Part 23)."""
    from cybersentinel.service.scan_log import ScanLog

    try:
        limit = min(500, max(1, int(request.args.get("limit", 100))))
    except (TypeError, ValueError):
        limit = 100
    entries = ScanLog(Path(__file__).resolve().parents[2] / "logs").tail(limit)
    return jsonify({"total": len(entries), "scans": entries}), 200


@app.route('/api/v1/monitoring/start', methods=['POST'])
def start_monitoring():
    """Backward-compatible start route for event-bus monitoring."""
    try:
        monitor_paths = (request.get_json(silent=True) or {}).get('paths', [])
        if monitor_paths:
            global file_monitor
            file_monitor.stop()
            file_monitor = FileMonitor(
                paths=monitor_paths,
                event_bus=event_bus,
                poll_interval=0.25
            )
            background_agent.replace_monitor(file_monitor, monitor_paths)
        
        _start_analysis_workers()
        file_monitor.start()
        orchestrator.start_protection()
        
        return jsonify({
            "status": "monitoring_active",
            "paths": monitor_paths or [str(p) for p in MONITORED_PATHS],
            "queue_limit": analysis_queue.maxsize,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Monitoring start failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop real-time file monitoring."""
    try:
        file_monitor.stop()
        _stop_analysis_workers()
        orchestrator.stop_protection()
        
        return jsonify({
            "status": "monitoring_stopped",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Monitoring stop failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/statistics', methods=['GET'])
def get_statistics():
    """Get event statistics and threat summary."""
    try:
        stats = event_bus.get_stats()
        history = event_bus.get_event_history()
        
        # Count threats
        threat_events = [e for e in history if e.event_type.value == "threat_detected"]
        quarantined_events = [e for e in history if e.event_type.value == "threat_quarantined"]
        
        return jsonify({
            "total_events": stats["total_events"],
            "threat_events": len(threat_events),
            "quarantined_files": len(quarantined_events),
            "event_types": stats["event_types"],
            "subscribers": stats["subscribers"],
            "monitoring": {
                "protection_active": orchestrator.protection_active,
                "queue_depth": analysis_queue.qsize(),
                "queue_limit": analysis_queue.maxsize,
                **analysis_metrics,
            },
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Stats retrieval failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/config', methods=['GET'])
def get_config():
    """Get current configuration."""
    return jsonify({
        "max_file_size_mb": MAX_FILE_SIZE / 1024 / 1024,
        "monitored_paths": [str(p) for p in MONITORED_PATHS],
        "quarantine_enabled": True,
        "api_version": "1.0.0",
        "features": {
            "file_analysis": True,
            "url_scanning": True,
            "phishing_detection": True,
            "malware_detection": True,
            "real_time_monitoring": True,
            "quarantine_management": True
        }
    }), 200


@app.route('/api/v1/config', methods=['POST'])
def update_config():
    """Update configuration (admin only)."""
    data = request.get_json()
    
    # In production, validate permissions here
    
    if 'monitored_paths' in data:
        global file_monitor
        file_monitor.stop()
        file_monitor = FileMonitor(
            paths=data['monitored_paths'],
            event_bus=event_bus,
            poll_interval=0.25
        )
        background_agent.replace_monitor(file_monitor, data['monitored_paths'])
    
    return jsonify({
        "status": "updated",
        "config": get_config().get_json()
    }), 200


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    # Keep the real-time monitor running while the website backend is active.
    _start_analysis_workers()
    orchestrator.start_protection()
    file_monitor.start()
    # Start with debug mode for development.
    # In production, use a WSGI server like Gunicorn.
    app.run(host='0.0.0.0', port=5000, debug=True)
