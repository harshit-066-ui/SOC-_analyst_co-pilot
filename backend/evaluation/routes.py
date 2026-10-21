"""FastAPI routes for the Evaluation Lab.

All endpoints are prefixed with /api/eval.

Endpoints
---------
POST   /api/eval/run
    Upload log files, normalize once, run selected configurations, return experiment.

POST   /api/eval/run/session/{session_id}
    Run evaluation against an already-normalized L1 session.

GET    /api/eval/experiments
    List all stored experiments (summary only).

GET    /api/eval/experiments/{experiment_id}
    Get full experiment data.

DELETE /api/eval/experiments/{experiment_id}
    Delete a stored experiment.

GET    /api/eval/experiments/{experiment_id}/export/json
    Download experiment as JSON.

GET    /api/eval/experiments/{experiment_id}/export/csv
    Download case-level results as CSV.

GET    /api/eval/configurations
    List the five configuration descriptors.

POST   /api/eval/ground-truth
    Upload a ground truth JSON dataset.

GET    /api/eval/ground-truth
    List available ground truth datasets.

GET    /api/eval/ground-truth/{dataset_id}
    Get a ground truth dataset.

GET    /api/eval/health
    Health check for the evaluation module.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from evaluation.models import (
    CONFIGURATION_REGISTRY,
    ConfigurationID,
    DatasetInfo,
    Experiment,
    ExperimentConfig,
    ExperimentStatus,
    GroundTruthDataset,
    GroundTruthLabel,
)
from evaluation.orchestrator import run_experiment
from evaluation.persistence import (
    delete_experiment,
    list_experiments,
    list_ground_truth_datasets,
    load_experiment,
    load_ground_truth,
    save_ground_truth,
)
from evaluation.metrics import results_to_csv_rows
from l1.api.ingestion_routes import pipeline as l1_pipeline
from l1.config import MAX_FILE_SIZE_BYTES, SUPPORTED_EXTENSIONS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/eval", tags=["Evaluation Lab"])

SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RunExperimentRequest(BaseModel):
    """Body for running an evaluation from an existing session."""

    session_id: str
    selected_configurations: list[ConfigurationID] = Field(
        default_factory=lambda: list(ConfigurationID)
    )
    batch_size: int = Field(default=10, ge=1, le=50)
    max_llm_alerts: int = Field(default=20, ge=1, le=50)
    ground_truth_dataset_id: str = ""
    notes: str = ""
    repeated_runs: int = Field(default=1, ge=1, le=3)


class GroundTruthUploadRequest(BaseModel):
    """Inline upload of a labelled dataset."""

    name: str
    description: str = ""
    is_synthetic: bool = False
    labels: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_session_id(session_id: str) -> None:
    if not SESSION_ID_PATTERN.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id format.")


def _load_normalized_events(session_id: str) -> list[dict[str, Any]]:
    """Load normalized events from an L1 session."""
    _validate_session_id(session_id)
    path = l1_pipeline.get_session_output(session_id, "normalized_json")
    if not path:
        raise HTTPException(
            status_code=404,
            detail=f"No normalized events found for session '{session_id}'. "
                   "Upload and normalize a file via /api/l1/upload first.",
        )
    with open(path, encoding="utf-8") as fh:
        events = json.load(fh)
    if not isinstance(events, list):
        raise HTTPException(
            status_code=500, detail="Normalized events file is malformed."
        )
    return events


def _build_dataset_info(
    session_id: str,
    events: list[dict[str, Any]],
    ground_truth: GroundTruthDataset | None,
) -> DatasetInfo:
    """Build DatasetInfo from session and events."""
    # Try to load normalization report for enriched metadata
    report_path = l1_pipeline.get_session_output(session_id, "report")
    raw_count = len(events)
    dedup_removed = 0
    norm_errors = 0
    input_format = "unknown"

    if report_path and report_path.exists():
        try:
            with open(report_path, encoding="utf-8") as fh:
                report = json.load(fh)
            raw_count = report.get("total_events", len(events))
            dedup_removed = report.get("duplicates_removed", 0)
            norm_errors = report.get("failed_events", 0)
            input_format = report.get("input_format", "json")
        except Exception:
            pass

    di = DatasetInfo(
        dataset_id=session_id,
        name=f"session_{session_id}",
        input_format=input_format,
        raw_event_count=raw_count,
        normalized_event_count=len(events),
        deduplicated_event_count=len(events),
        duplicates_removed=dedup_removed,
        normalization_errors=norm_errors,
        normalization_status="ok" if norm_errors == 0 else "completed_with_errors",
        ground_truth_available=ground_truth is not None,
        labelled_case_count=len(ground_truth.labels) if ground_truth else 0,
    )
    di.compute_fingerprint(events)
    return di


# ---------------------------------------------------------------------------
# POST /api/eval/run/upload — upload files + run evaluation
# ---------------------------------------------------------------------------


@router.post(
    "/run/upload",
    summary="Upload log files and run evaluation",
    description=(
        "Upload one or more log files. They are normalized once via L1, then "
        "the selected configurations are run against the same normalized events. "
        "Returns the full experiment record."
    ),
)
async def run_evaluation_from_upload(
    files: list[UploadFile] = File(...),
    configurations: str = Form(
        default="",
        description="Comma-separated configuration IDs, or empty for all five.",
    ),
    ground_truth_dataset_id: str = Form(default=""),
    max_llm_alerts: int = Form(default=20),
    notes: str = Form(default=""),
    source_hint: str = Form(default=""),
) -> JSONResponse:
    """Normalize uploaded files once, then run the evaluation."""
    # --- Validate uploads ---
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    file_tuples: list[tuple[bytes, str]] = []
    for upload in files:
        suffix = "." + upload.filename.rsplit(".", 1)[-1].lower() if "." in upload.filename else ""
        if suffix not in SUPPORTED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type '{suffix}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}",
            )
        content = await upload.read()
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"File '{upload.filename}' exceeds 20 MB limit.",
            )
        file_tuples.append((content, upload.filename))

    # --- L1 Normalization (once) ---
    try:
        l1_result = l1_pipeline.process_files(
            file_tuples,
            source_hint=source_hint or None,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"L1 normalization failed: {exc}",
        ) from exc

    session_id: str = l1_result["session_id"]
    events: list[dict[str, Any]] = l1_result["events"]

    if not events:
        raise HTTPException(
            status_code=422,
            detail="No events could be normalized from the uploaded files.",
        )

    # --- Parse selected configurations ---
    selected = _parse_config_list(configurations)

    # --- Ground truth ---
    ground_truth = None
    if ground_truth_dataset_id:
        ground_truth = load_ground_truth(ground_truth_dataset_id)
        if ground_truth is None:
            raise HTTPException(
                status_code=404,
                detail=f"Ground truth dataset '{ground_truth_dataset_id}' not found.",
            )

    # --- Build experiment config ---
    exp_config = ExperimentConfig(
        selected_configurations=selected,
        max_llm_alerts=max(1, min(max_llm_alerts, 20)),
        ground_truth_dataset_id=ground_truth_dataset_id,
        notes=notes,
    )
    dataset_info = _build_dataset_info(session_id, events, ground_truth)

    # --- Run experiment ---
    try:
        experiment = run_experiment(
            normalized_events=events,
            config=exp_config,
            dataset_info=dataset_info,
            ground_truth=ground_truth,
        )
    except Exception as exc:
        logger.exception("Experiment failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Experiment failed: {exc}") from exc

    return JSONResponse(
        content=json.loads(experiment.model_dump_json()),
        status_code=200,
    )


# ---------------------------------------------------------------------------
# POST /api/eval/run/session/{session_id}
# ---------------------------------------------------------------------------


@router.post(
    "/run/session/{session_id}",
    summary="Run evaluation against an existing L1 session",
)
async def run_evaluation_from_session(
    session_id: str,
    request: RunExperimentRequest,
) -> JSONResponse:
    """Run configured evaluation on an already-normalized session."""
    _validate_session_id(session_id)
    request.session_id = session_id
    events = _load_normalized_events(session_id)

    if not events:
        raise HTTPException(
            status_code=422, detail="Session has zero normalized events."
        )

    ground_truth = None
    if request.ground_truth_dataset_id:
        ground_truth = load_ground_truth(request.ground_truth_dataset_id)
        if ground_truth is None:
            raise HTTPException(
                status_code=404,
                detail=f"Ground truth dataset '{request.ground_truth_dataset_id}' not found.",
            )

    exp_config = ExperimentConfig(
        selected_configurations=request.selected_configurations,
        batch_size=request.batch_size,
        max_llm_alerts=request.max_llm_alerts,
        ground_truth_dataset_id=request.ground_truth_dataset_id,
        notes=request.notes,
        repeated_runs=request.repeated_runs,
    )
    dataset_info = _build_dataset_info(session_id, events, ground_truth)

    try:
        experiment = run_experiment(
            normalized_events=events,
            config=exp_config,
            dataset_info=dataset_info,
            ground_truth=ground_truth,
        )
    except Exception as exc:
        logger.exception("Experiment failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Experiment failed: {exc}") from exc

    return JSONResponse(content=json.loads(experiment.model_dump_json()))


# ---------------------------------------------------------------------------
# GET /api/eval/experiments
# ---------------------------------------------------------------------------


@router.get("/experiments", summary="List all stored experiments")
async def list_all_experiments() -> JSONResponse:
    return JSONResponse(list_experiments())


# ---------------------------------------------------------------------------
# GET /api/eval/experiments/{experiment_id}
# ---------------------------------------------------------------------------


@router.get(
    "/experiments/{experiment_id}",
    summary="Get full experiment data",
)
async def get_experiment(experiment_id: str) -> JSONResponse:
    experiment = load_experiment(experiment_id)
    if not experiment:
        raise HTTPException(
            status_code=404, detail=f"Experiment '{experiment_id}' not found."
        )
    return JSONResponse(json.loads(experiment.model_dump_json()))


# ---------------------------------------------------------------------------
# DELETE /api/eval/experiments/{experiment_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/experiments/{experiment_id}",
    summary="Delete a stored experiment",
)
async def remove_experiment(experiment_id: str) -> JSONResponse:
    deleted = delete_experiment(experiment_id)
    if not deleted:
        raise HTTPException(
            status_code=404, detail=f"Experiment '{experiment_id}' not found."
        )
    return JSONResponse({"deleted": True, "experiment_id": experiment_id})


# ---------------------------------------------------------------------------
# GET /api/eval/experiments/{experiment_id}/export/json
# ---------------------------------------------------------------------------


@router.get(
    "/experiments/{experiment_id}/export/json",
    summary="Download experiment as JSON",
)
async def export_experiment_json(experiment_id: str) -> StreamingResponse:
    experiment = load_experiment(experiment_id)
    if not experiment:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found.")

    content = experiment.model_dump_json(indent=2)
    return StreamingResponse(
        io.StringIO(content),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="experiment_{experiment_id}.json"'
        },
    )


# ---------------------------------------------------------------------------
# GET /api/eval/experiments/{experiment_id}/export/csv
# ---------------------------------------------------------------------------


@router.get(
    "/experiments/{experiment_id}/export/csv",
    summary="Download case-level results as CSV",
)
async def export_experiment_csv(experiment_id: str) -> StreamingResponse:
    experiment = load_experiment(experiment_id)
    if not experiment:
        raise HTTPException(status_code=404, detail=f"Experiment '{experiment_id}' not found.")

    from evaluation.models import CaseConfigResult

    all_rows: list[dict[str, Any]] = []
    for config_id_str, case_dicts in experiment.case_results.items():
        for case_dict in case_dicts:
            try:
                result = CaseConfigResult.model_validate(case_dict)
                rows = results_to_csv_rows([result])
                all_rows.extend(rows)
            except Exception:
                pass

    if not all_rows:
        raise HTTPException(status_code=404, detail="No case results to export.")

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(all_rows[0].keys()))
    writer.writeheader()
    writer.writerows(all_rows)
    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="experiment_{experiment_id}_cases.csv"'
        },
    )


# ---------------------------------------------------------------------------
# GET /api/eval/configurations
# ---------------------------------------------------------------------------


@router.get("/configurations", summary="List the five evaluation configurations")
async def list_configurations() -> JSONResponse:
    configs = [
        {
            "config_id": spec.config_id.value,
            "name": spec.name,
            "description": spec.description,
            "components": spec.components,
            "notes": spec.notes,
        }
        for spec in CONFIGURATION_REGISTRY.values()
    ]
    return JSONResponse(configs)


# ---------------------------------------------------------------------------
# POST /api/eval/ground-truth
# ---------------------------------------------------------------------------


@router.post("/ground-truth", summary="Upload a labelled ground truth dataset")
async def upload_ground_truth(request: GroundTruthUploadRequest) -> JSONResponse:
    """Create a ground truth dataset from inline JSON labels."""
    if not request.name:
        raise HTTPException(status_code=400, detail="name is required.")

    dataset_id = uuid.uuid4().hex[:12]
    labels: list[GroundTruthLabel] = []

    for raw_label in request.labels:
        try:
            lbl = GroundTruthLabel(
                event_id=str(raw_label.get("event_id", "")),
                label=str(raw_label.get("label", "benign")).lower(),
                expected_rule_ids=raw_label.get("expected_rule_ids", []),
                expected_risk_level=raw_label.get("expected_risk_level"),
                notes=str(raw_label.get("notes", "")),
                is_synthetic=bool(raw_label.get("is_synthetic", False)),
            )
            if lbl.label not in ("malicious", "benign"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Label must be 'malicious' or 'benign', got '{lbl.label}'.",
                )
            labels.append(lbl)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Invalid label entry: {exc}"
            ) from exc

    dataset = GroundTruthDataset(
        dataset_id=dataset_id,
        name=request.name,
        description=request.description,
        labels=labels,
        is_synthetic=request.is_synthetic,
    )
    save_ground_truth(dataset)
    return JSONResponse(
        {"dataset_id": dataset_id, "name": dataset.name, "label_count": len(labels)},
        status_code=201,
    )


@router.post(
    "/ground-truth/upload",
    summary="Upload ground truth dataset as JSON file",
)
async def upload_ground_truth_file(
    file: UploadFile = File(...),
) -> JSONResponse:
    """Accept a JSON file containing a ground truth dataset."""
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json files are accepted.")
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Ground truth file exceeds 5 MB.")
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    # Validate required structure
    if "labels" not in data:
        raise HTTPException(
            status_code=400, detail="JSON must contain a 'labels' array."
        )
    for lbl in data.get("labels", []):
        if lbl.get("label") not in ("malicious", "benign"):
            raise HTTPException(
                status_code=400,
                detail=f"Each label must be 'malicious' or 'benign', got '{lbl.get('label')}'.",
            )

    dataset_id = data.get("dataset_id") or uuid.uuid4().hex[:12]
    data["dataset_id"] = dataset_id

    try:
        dataset = GroundTruthDataset.model_validate(data)
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail=f"Ground truth file schema error: {exc}"
        ) from exc

    save_ground_truth(dataset)
    return JSONResponse(
        {
            "dataset_id": dataset.dataset_id,
            "name": dataset.name,
            "label_count": len(dataset.labels),
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# GET /api/eval/ground-truth
# ---------------------------------------------------------------------------


@router.get("/ground-truth", summary="List ground truth datasets")
async def list_ground_truth() -> JSONResponse:
    return JSONResponse(list_ground_truth_datasets())


# ---------------------------------------------------------------------------
# GET /api/eval/ground-truth/{dataset_id}
# ---------------------------------------------------------------------------


@router.get("/ground-truth/{dataset_id}", summary="Get a ground truth dataset")
async def get_ground_truth(dataset_id: str) -> JSONResponse:
    dataset = load_ground_truth(dataset_id)
    if not dataset:
        raise HTTPException(
            status_code=404, detail=f"Ground truth dataset '{dataset_id}' not found."
        )
    return JSONResponse(json.loads(dataset.model_dump_json()))


# ---------------------------------------------------------------------------
# GET /api/eval/health
# ---------------------------------------------------------------------------


@router.get("/health", summary="Evaluation Lab health check")
async def eval_health() -> JSONResponse:
    from evaluation.persistence import EXPERIMENTS_DIR, GROUND_TRUTH_DIR
    experiment_count = len(list(EXPERIMENTS_DIR.glob("*.json"))) if EXPERIMENTS_DIR.exists() else 0
    gt_count = len(list(GROUND_TRUTH_DIR.glob("*.json"))) if GROUND_TRUTH_DIR.exists() else 0

    return JSONResponse(
        {
            "status": "ok",
            "module": "EvaluationLab",
            "schema_version": "1.0",
            "stored_experiments": experiment_count,
            "ground_truth_datasets": gt_count,
            "configurations_available": len(CONFIGURATION_REGISTRY),
        }
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_config_list(raw: str) -> list[ConfigurationID]:
    """Parse a comma-separated string of config IDs; default to all five."""
    if not raw or not raw.strip():
        return list(ConfigurationID)
    ids: list[ConfigurationID] = []
    for part in raw.split(","):
        part = part.strip()
        try:
            ids.append(ConfigurationID(part))
        except ValueError:
            valid = [c.value for c in ConfigurationID]
            raise HTTPException(
                status_code=400,
                detail=f"Unknown configuration ID '{part}'. Valid: {valid}",
            )
    return ids or list(ConfigurationID)
