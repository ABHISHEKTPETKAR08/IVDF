"""
Celery application factory — production-grade configuration.

Key design decisions:
- broker_connection_retry_on_startup=True  : workers wait for Redis instead of dying
- task_acks_late=True                      : task re-queued if worker crashes mid-run
- worker_prefetch_multiplier=1             : one task at a time per worker (fair dispatch)
- task_reject_on_worker_lost=True          : lost tasks go back to queue, not lost
- Separate broker (DB 0) and result (DB 1) : avoids key collisions, easier flush
"""
from celery import Celery
from celery.signals import worker_ready, worker_shutdown, task_prerun, task_postrun, task_failure
from celery.utils.log import get_task_logger

from backend.config import settings

logger = get_task_logger(__name__)


# ── Application factory ───────────────────────────────────────────────────────

celery_app = Celery(
    "ivdaf",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["backend.automation.tasks"],
)

celery_app.conf.update(
    # ── Serialisation ─────────────────────────────────────────────────────────
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # ── Timezone ──────────────────────────────────────────────────────────────
    timezone="UTC",
    enable_utc=True,

    # ── Task execution policy ─────────────────────────────────────────────────
    task_track_started=True,
    task_acks_late=True,                    # ack after completion, not on receive
    task_reject_on_worker_lost=True,        # requeue on worker crash
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,

    # ── Worker tuning ─────────────────────────────────────────────────────────
    worker_prefetch_multiplier=1,           # prevents one worker hoarding all tasks
    worker_max_tasks_per_child=50,          # restart worker every 50 tasks (leak prevention)
    worker_hijack_root_logger=False,        # keep our own logging config
    worker_log_color=False,                 # cleaner log output in files/Docker

    # ── Time limits per scan task ─────────────────────────────────────────────
    task_soft_time_limit=600,               # 10 min soft → raises SoftTimeLimitExceeded
    task_time_limit=720,                    # 12 min hard  → SIGKILL

    # ── Results ───────────────────────────────────────────────────────────────
    result_expires=86_400,                  # keep results 24 h
    result_extended=True,                   # store args/kwargs in result for debugging

    # ── Broker reliability ────────────────────────────────────────────────────
    broker_connection_retry_on_startup=settings.CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP,
    broker_connection_max_retries=10,
    broker_connection_retry=True,
    broker_heartbeat=10,                    # detect dropped connections every 10 s
    broker_pool_limit=settings.WORKER_CONCURRENCY + 2,

    # ── Redis transport options ───────────────────────────────────────────────
    broker_transport_options={
        "visibility_timeout": 3600,         # 1 h: task invisible to other workers while running
        "socket_connect_timeout": 5,
        "socket_timeout": 5,
        "retry_policy": {
            "timeout": 30,                  # total retry window on disconnect
        },
    },
    result_backend_transport_options={
        "socket_connect_timeout": 5,
        "socket_timeout": 5,
    },

    # ── Monitoring (Flower / events) ──────────────────────────────────────────
    worker_send_task_events=True,
    task_send_sent_event=True,
    event_queue_expires=60,
    event_queue_ttl=5,
)


# ── Lifecycle signals (structured logging) ────────────────────────────────────

@worker_ready.connect
def _on_worker_ready(sender, **kwargs):
    logger.info("Celery worker ready: %s | broker=%s", sender, settings.CELERY_BROKER_URL)


@worker_shutdown.connect
def _on_worker_shutdown(sender, **kwargs):
    logger.info("Celery worker shutting down: %s", sender)


@task_prerun.connect
def _on_task_prerun(task_id, task, args, kwargs, **extra):
    logger.info("TASK START  task_id=%s name=%s", task_id, task.name)


@task_postrun.connect
def _on_task_postrun(task_id, task, retval, state, **extra):
    logger.info("TASK DONE   task_id=%s name=%s state=%s", task_id, task.name, state)


@task_failure.connect
def _on_task_failure(task_id, exception, traceback, sender, **extra):
    logger.error(
        "TASK FAILED task_id=%s name=%s error=%s",
        task_id, sender.name, exception,
    )
