"""Evaluation experiment persistence — file-based JSON storage.

Experiments are stored in:  backend/output/eval_experiments/<experiment_id>.json
Ground truth datasets are stored in: backend/output/eval_ground_truth/<dataset_id>.json

No new database is introduced. The existing output directory is reused.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from l1.config import OUTPUT_DIR
from evaluation.models import Experiment, GroundTruthDataset

logger = logging.getLogger(__name__)

EXPERIMENTS_DIR = OUTPUT_DIR / "eval_experiments"
GROUND_TRUTH_DIR = OUTPUT_DIR / "eval_ground_truth"


def _ensure_dirs() -> None:
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)
    GROUND_TRUTH_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Experiment persistence
# ---------------------------------------------------------------------------


def save_experiment(experiment: Experiment) -> Path:
    """Persist experiment to disk. Returns the file path."""
    _ensure_dirs()
    path = EXPERIMENTS_DIR / f"{experiment.experiment_id}.json"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(experiment.model_dump_json(indent=2))
    logger.debug("Saved experiment %s to %s", experiment.experiment_id, path)
    return path


def load_experiment(experiment_id: str) -> Experiment | None:
    """Load an experiment by ID. Returns None if not found."""
    _ensure_dirs()
    path = EXPERIMENTS_DIR / f"{experiment_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return Experiment.model_validate(data)
    except Exception as exc:
        logger.error("Failed to load experiment %s: %s", experiment_id, exc)
        return None


def list_experiments() -> list[dict[str, Any]]:
    """Return a summary list of all stored experiments (not full data)."""
    _ensure_dirs()
    summaries: list[dict[str, Any]] = []
    for path in sorted(EXPERIMENTS_DIR.glob("*.json"), reverse=True):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            summaries.append(
                {
                    "experiment_id": data.get("experiment_id", path.stem),
                    "created_at": data.get("created_at", ""),
                    "completed_at": data.get("completed_at"),
                    "status": data.get("status", "unknown"),
                    "dataset_name": data.get("dataset", {}).get("name", ""),
                    "selected_configurations": data.get("config", {}).get(
                        "selected_configurations", []
                    ),
                    "errors_count": len(data.get("errors", [])),
                }
            )
        except Exception as exc:
            logger.warning("Skipping malformed experiment file %s: %s", path, exc)
    return summaries


def delete_experiment(experiment_id: str) -> bool:
    """Delete a stored experiment. Returns True if deleted."""
    path = EXPERIMENTS_DIR / f"{experiment_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# Ground truth persistence
# ---------------------------------------------------------------------------


def save_ground_truth(dataset: GroundTruthDataset) -> Path:
    """Persist ground truth dataset. Returns file path."""
    _ensure_dirs()
    path = GROUND_TRUTH_DIR / f"{dataset.dataset_id}.json"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dataset.model_dump_json(indent=2))
    return path


def load_ground_truth(dataset_id: str) -> GroundTruthDataset | None:
    """Load a ground truth dataset by ID."""
    _ensure_dirs()
    path = GROUND_TRUTH_DIR / f"{dataset_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return GroundTruthDataset.model_validate(data)
    except Exception as exc:
        logger.error("Failed to load ground truth %s: %s", dataset_id, exc)
        return None


def list_ground_truth_datasets() -> list[dict[str, Any]]:
    """Return a summary list of all ground truth datasets."""
    _ensure_dirs()
    summaries: list[dict[str, Any]] = []
    for path in sorted(GROUND_TRUTH_DIR.glob("*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            summaries.append(
                {
                    "dataset_id": data.get("dataset_id", path.stem),
                    "name": data.get("name", ""),
                    "description": data.get("description", ""),
                    "label_count": len(data.get("labels", [])),
                    "is_synthetic": data.get("is_synthetic", False),
                    "created_at": data.get("created_at", ""),
                }
            )
        except Exception as exc:
            logger.warning("Skipping malformed GT file %s: %s", path, exc)
    return summaries
