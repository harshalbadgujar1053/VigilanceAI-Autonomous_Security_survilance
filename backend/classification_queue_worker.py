"""
FIXED VERSION — two changes from the original:

1. Every blocking psycopg2/SQLAlchemy call is now wrapped in
   run_in_executor, so it never blocks the asyncio event loop. This was
   likely a major cause of the 30s tail latencies across ALL endpoints
   during the load test — a single-threaded event loop stalls entirely
   while a synchronous DB call runs inline inside an `async def`.

2. The worker loop now catches ALL exceptions per-iteration and keeps
   running, logging clearly instead of dying silently. Previously, any
   unhandled exception inside the while-loop would kill the whole
   background task with nothing logging it — almost certainly why
   processing stopped completely after item #1 (the smoke test) and
   never resumed despite 1774 items piling up with zero visible errors.

Replace your existing classification_queue_worker.py with this file.
"""
import asyncio
import time
from datetime import datetime, timedelta
import os
import logging

from sqlalchemy import asc

from database import SessionLocal, ClassificationQueue, AlertRecord
from rate_limiter import SteadyRateLimiter
from agent.classify_with_rag import classify_alert_with_rag

logger = logging.getLogger("vigilance-ai")

RATE_PER_MINUTE = 15
MAX_ATTEMPTS = 3

_limiter = SteadyRateLimiter(rate_per_minute=RATE_PER_MINUTE)


def _fetch_next_pending_sync(db):
    return (
        db.query(ClassificationQueue)
        .filter(ClassificationQueue.status == "pending")
        .order_by(asc(ClassificationQueue.enqueued_at))
        .first()
    )


def _claim_item_sync():
    """Runs entirely synchronously — called via run_in_executor. Fetches
    the oldest pending item and marks it 'processing' in one DB session,
    returns its id and alert_id, or None if nothing pending."""
    db = SessionLocal()
    try:
        item = _fetch_next_pending_sync(db)
        if item is None:
            return None
        item.status = "processing"
        item.updated_at = datetime.utcnow()
        db.commit()
        return item.id, item.alert_id
    finally:
        db.close()


def _fetch_alert_dict_sync(alert_id):
    db = SessionLocal()
    try:
        record = db.query(AlertRecord).filter(AlertRecord.id == alert_id).first()
        if not record:
            return None
        return {
            "id": record.id,
            "timestamp": record.timestamp,
            "rule_id": record.rule_id,
            "rule_level": record.rule_level,
            "description": record.description,
            "agent_name": record.agent_name,
            "agent_ip": record.agent_ip,
            "raw_data": record.raw_data,
        }
    finally:
        db.close()


def _mark_result_sync(item_id, alert_id, success, rag_result=None, error=None):
    """Runs synchronously via run_in_executor. Handles both the success
    path (calls the existing save logic) and the failure path (retry
    counting / marking failed) in one DB session."""
    db = SessionLocal()
    try:
        item = db.query(ClassificationQueue).filter(ClassificationQueue.id == item_id).first()
        if item is None:
            return
        if success:
            from main import _save_classification_result
            _save_classification_result(db, alert_id, rag_result)
            item.status = "done"
            db.commit()
            logger.info(f"Queue item {item_id} (alert {alert_id}) classified successfully")
        else:
            item.attempts += 1
            item.error = str(error)
            if item.attempts >= MAX_ATTEMPTS:
                item.status = "failed"
                logger.error(f"Queue item {item_id} (alert {alert_id}) failed permanently "
                             f"after {item.attempts} attempts: {error}")
            else:
                item.status = "pending"
                logger.warning(f"Queue item {item_id} (alert {alert_id}) attempt "
                                f"{item.attempts} failed, will retry: {error}")
            db.commit()
    finally:
        db.close()


CALL_TIMEOUT_S = int(os.getenv("CALL_TIMEOUT_S", "120"))


def _requeue_sync(item_id):
    db = SessionLocal()
    try:
        item = db.query(ClassificationQueue).filter(ClassificationQueue.id == item_id).first()
        if item is not None and item.status == "processing":
            item.status = "pending"
            item.error = "gemini call timed out - requeued"
            db.commit()
    finally:
        db.close()


async def _process_one(item_id: int, alert_id: str, loop):
    alert = await loop.run_in_executor(None, _fetch_alert_dict_sync, alert_id)
    if alert is None:
        await loop.run_in_executor(
            None, _mark_result_sync, item_id, alert_id, False, None, "alert record not found"
        )
        return

    try:
        if os.getenv("CLASSIFIER_STUB") == "1":
            await asyncio.sleep(1.0)
            rag_result = {"classification": STUB_TEXT}
        else:
            rag_result = await asyncio.wait_for(
                loop.run_in_executor(None, classify_alert_with_rag, alert),
                timeout=CALL_TIMEOUT_S,
            )
        await loop.run_in_executor(None, _mark_result_sync, item_id, alert_id, True, rag_result, None)
    except Exception as e:
        if isinstance(e, asyncio.TimeoutError):
            logger.warning(f"Queue item {item_id}: Gemini call timed out after {CALL_TIMEOUT_S}s, requeueing")
            await loop.run_in_executor(None, _requeue_sync, item_id)
            await asyncio.sleep(10)
        else:
            await loop.run_in_executor(None, _mark_result_sync, item_id, alert_id, False, None, e)



STALE_PROCESSING_S = int(os.getenv("STALE_PROCESSING_S", "300"))
_last_sweep = 0.0


def _requeue_stale_sync():
    """Visibility timeout: put rows stuck in 'processing' back to 'pending'."""
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(seconds=STALE_PROCESSING_S)
        n = (
            db.query(ClassificationQueue)
            .filter(ClassificationQueue.status == "processing",
                    ClassificationQueue.updated_at < cutoff)
            .update({"status": "pending"}, synchronize_session=False)
        )
        db.commit()
        return n
    finally:
        db.close()


async def _maybe_sweep(loop):
    global _last_sweep
    now = time.monotonic()
    if now - _last_sweep < 30:
        return
    _last_sweep = now
    n = await loop.run_in_executor(None, _requeue_stale_sync)
    if n:
        logger.warning(f"Requeued {n} stale 'processing' queue item(s)")

async def _worker_loop():
    loop = asyncio.get_event_loop()
    logger.info(f"Classification queue worker started (rate limit: {RATE_PER_MINUTE}/min)")
    while True:
        try:
            await _maybe_sweep(loop)
            claimed = await loop.run_in_executor(None, _claim_item_sync)
            if claimed is None:
                await asyncio.sleep(1)
                continue
            item_id, alert_id = claimed

            await _limiter.acquire()
            await _process_one(item_id, alert_id, loop)

        except Exception as e:
            # CRITICAL: catch everything here so a single bad iteration
            # can never kill the whole worker task silently. This is the
            # fix for the "stopped after item #1 with zero errors" bug —
            # previously any exception here would propagate out of the
            # while loop and terminate the task with nothing logging it.
            logger.error(f"Queue worker iteration failed unexpectedly, continuing: {e}", exc_info=True)
            await asyncio.sleep(1)


async def start_queue_worker():
    """Entry point called from main.py's startup event. Wrapped so that
    even a failure to start (e.g. import error surfacing late) is logged
    clearly instead of vanishing."""
    try:
        await _worker_loop()
    except Exception as e:
        logger.critical(f"Classification queue worker crashed and will NOT restart: {e}", exc_info=True)
        raise


# ---- test-only stub (active only when CLASSIFIER_STUB=1) ----
STUB_TEXT = """[SEVERITY] MEDIUM
[VERDICT] NEEDS INVESTIGATION
[CONFIDENCE] MEDIUM
[TECHNIQUE] T1110 - Brute Force
[REASONING]
- stub classification for resilience testing"""
if os.getenv("CLASSIFIER_STUB") == "1":
    class _NoLimit:
        async def acquire(self):
            return None
    _limiter = _NoLimit()
