"""
Phase 27: Asynchronous Detection Pipeline and Queue Reliability.

Implements a bounded asynchronous worker pipeline decoupling streaming telemetry
ingestion from CPU-intensive calibrated machine learning detection, feature extraction,
and incident correlation.

Key Architectural Guarantees:
1. In-Memory Volatile Queue: Telemetry accepted into this queue is held in process memory.
   It is NOT a durable queue; events queued in memory can be lost if the server process terminates.
2. Bounded Capacity & Backpressure: Configurable maximum queue size with explicit
   rejection or timeout policies (never unbounded memory growth).
3. Thread-Safe Worker Offloading: CPU-intensive feature extraction and model inference
   are offloaded to a worker thread pool, preventing blocking the FastAPI event loop.
4. Host-Partitioned Ordering: Concurrency is partitioned such that events belonging to
   the same host (host_id or src_entity) are processed sequentially in arrival order,
   preventing race conditions in causal sequence and graph trackers.
5. Idempotent Incident Correlation: Completed event IDs are tracked to prevent
   repeated delivery or retried tasks from inflating incident evidence.
6. Transient vs. Permanent Failure Classification: Exponential backoff retries for
   transient faults; non-retryable dead-letter recording for permanent errors.
"""

import asyncio
import contextlib
import logging
import math
import time
from collections import deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Callable

try:
    from backend.core.schemas import (
        UnifiedEvent,
        DetectionResult,
        Alert,
        EventProcessingState,
        QueueBackpressurePolicy,
        AsyncQueueConfig,
        DeadLetterItem,
        QueueMetrics,
    )
except ModuleNotFoundError:
    from core.schemas import (
        UnifiedEvent,
        DetectionResult,
        Alert,
        EventProcessingState,
        QueueBackpressurePolicy,
        AsyncQueueConfig,
        DeadLetterItem,
        QueueMetrics,
    )

logger = logging.getLogger("aegis.async_queue")


class TransientDetectionError(Exception):
    """Exception representing a temporary fault eligible for retry (e.g., lock contention, timeout)."""
    pass


class PermanentDetectionError(Exception):
    """Exception representing a non-retryable failure (e.g., corrupted structure, type error)."""
    pass


class SimulatedTransientError(TransientDetectionError):
    """Synthetic transient error used specifically for fault injection testing."""
    pass


@dataclass
class QueuedEventItem:
    """Internal container wrapping an event queued for asynchronous detection."""
    event: UnifiedEvent
    enqueued_at: float
    partition_key: str
    attempts: int = 0
    state: EventProcessingState = EventProcessingState.QUEUED
    last_error: Optional[str] = None


class AsyncDetectionQueue:
    """
    Bounded asynchronous queue and worker pool for ML threat detection.
    """

    def __init__(
        self,
        config: Optional[AsyncQueueConfig] = None,
        detection_handler: Optional[Callable[[UnifiedEvent], Tuple[Optional[DetectionResult], Optional[Alert]]]] = None,
        detection_batch_handler: Optional[Callable[[List[UnifiedEvent]], List[Tuple[Optional[DetectionResult], Optional[Alert]]]]] = None,
        batch_size: int = 16,
    ):
        self.config = config or AsyncQueueConfig()
        self.detection_handler = detection_handler
        self.detection_batch_handler = detection_batch_handler
        self.batch_size = max(1, batch_size)

        # Internal queue and dead-letter records
        self._queue: asyncio.Queue[QueuedEventItem] = asyncio.Queue(maxsize=self.config.max_queue_size)
        self._dead_letter_queue: deque[DeadLetterItem] = deque(maxlen=self.config.dead_letter_capacity)

        # Worker tasks & threading
        self._workers: List[asyncio.Task] = []
        self._running: bool = False
        self._executor: Optional[ThreadPoolExecutor] = None

        # Concurrency & host partitioning locks
        self._host_locks: Dict[str, asyncio.Lock] = {}
        self._master_host_lock = asyncio.Lock()

        # Idempotency cache: bounded LRU of completed event IDs -> completion timestamp
        self._completed_event_ids: OrderedDict[str, float] = OrderedDict()
        self._max_completed_ids = 10000

        # Metrics counters
        self.accepted_events: int = 0
        self.queued_events: int = 0
        self.processing_events: int = 0
        self.completed_events: int = 0
        self.failed_events: int = 0
        self.retry_count: int = 0
        self.duplicate_count: int = 0
        self.rejected_count: int = 0

        # Latency sliding windows (ms)
        self._wait_times: deque[float] = deque(maxlen=1000)
        self._processing_times: deque[float] = deque(maxlen=1000)
        self._e2e_latencies: deque[float] = deque(maxlen=1000)

        # Fault injection hooks for testing
        self._fault_hook: Optional[Callable[[UnifiedEvent, int], None]] = None

    @property
    def queue_depth(self) -> int:
        """Current number of items waiting in the in-memory queue."""
        return self._queue.qsize()

    @property
    def is_running(self) -> bool:
        """Whether detection workers are active."""
        return self._running

    async def _get_host_lock(self, partition_key: str) -> asyncio.Lock:
        """Retrieve or create an asyncio.Lock for a specific host partition."""
        async with self._master_host_lock:
            if partition_key not in self._host_locks:
                self._host_locks[partition_key] = asyncio.Lock()
            return self._host_locks[partition_key]

    async def start(self) -> None:
        """Start the background worker pool and thread executor."""
        if self._running:
            return

        running_loop = asyncio.get_running_loop()
        try:
            queue_loop = getattr(self._queue, "_loop", None)
            if queue_loop is not None and queue_loop != running_loop:
                if self._queue.empty():
                    self._queue = asyncio.Queue(maxsize=self.config.max_queue_size)
                    self._master_host_lock = asyncio.Lock()
                    self._host_locks.clear()
        except Exception:
            pass

        self._running = True
        self._executor = ThreadPoolExecutor(
            max_workers=max(2, self.config.worker_concurrency * 2),
            thread_name_prefix="aegis-detect-worker",
        )

        for i in range(self.config.worker_concurrency):
            task = asyncio.create_task(
                self._worker_loop(worker_id=i),
                name=f"aegis-detection-worker-{i}",
            )
            self._workers.append(task)

        logger.info(
            f"[AsyncDetectionQueue] Started {self.config.worker_concurrency} workers "
            f"(queue_capacity={self.config.max_queue_size}, policy={self.config.backpressure_policy})"
        )

    async def stop(self, timeout_seconds: float = 5.0) -> None:
        """Gracefully stop worker tasks and shut down thread pool."""
        if not self._running:
            return

        self._running = False

        # Cancel active worker tasks
        for task in self._workers:
            if not task.done():
                task.cancel()

        # Wait for cancellation with timeout
        if self._workers:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._workers, return_exceptions=True),
                    timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning("[AsyncDetectionQueue] Timed out waiting for worker tasks to cancel.")

        self._workers.clear()

        # Shut down executor
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None

        logger.info("[AsyncDetectionQueue] Stopped all detection workers.")

    async def flush(self, timeout_seconds: float = 5.0) -> bool:
        """Wait until all queued items have completed processing."""
        try:
            await asyncio.wait_for(self._queue.join(), timeout=timeout_seconds)
            return True
        except asyncio.TimeoutError:
            logger.warning("[AsyncDetectionQueue] Flush timed out waiting for queue to empty.")
            return False

    async def enqueue(self, event: UnifiedEvent) -> Tuple[bool, str, Optional[int]]:
        """
        Attempt to enqueue an accepted UnifiedEvent for asynchronous detection.

        Returns:
            (success: bool, status_reason: str, queue_position: Optional[int])
        """
        self.accepted_events += 1

        # Check idempotency: if already processed recently, skip re-queue
        if event.event_id and event.event_id in self._completed_event_ids:
            self.duplicate_count += 1
            return False, "duplicate_event_already_processed", None

        partition_key = str(event.host_id or event.src_entity or "global")
        item = QueuedEventItem(
            event=event,
            enqueued_at=time.perf_counter(),
            partition_key=partition_key,
        )

        # Handle queue saturation according to BackpressurePolicy
        if self._queue.full():
            if self.config.backpressure_policy == QueueBackpressurePolicy.REJECT:
                self.rejected_count += 1
                logger.warning(
                    f"[AsyncDetectionQueue] Rejected event {event.event_id}: queue full ({self._queue.qsize()}/{self.config.max_queue_size})"
                )
                return False, "queue_full", None

            elif self.config.backpressure_policy == QueueBackpressurePolicy.BLOCK_TIMEOUT:
                try:
                    await asyncio.wait_for(
                        self._queue.put(item),
                        timeout=self.config.timeout_seconds,
                    )
                    self.queued_events += 1
                    return True, "queued", self._queue.qsize()
                except asyncio.TimeoutError:
                    self.rejected_count += 1
                    logger.warning(
                        f"[AsyncDetectionQueue] Saturation timeout ({self.config.timeout_seconds}s) on event {event.event_id}"
                    )
                    return False, "queue_saturated", None

        # Space available: enqueue immediately
        try:
            self._queue.put_nowait(item)
            self.queued_events += 1
            return True, "queued", self._queue.qsize()
        except asyncio.QueueFull:
            self.rejected_count += 1
            return False, "queue_full", None

    def enqueue_nowait(self, event: UnifiedEvent) -> Tuple[bool, str, Optional[int]]:
        """
        Synchronous non-blocking enqueue helper.
        Enqueues immediately if space is available; rejects immediately if queue is full.
        """
        self.accepted_events += 1

        if event.event_id and event.event_id in self._completed_event_ids:
            self.duplicate_count += 1
            return False, "duplicate_event_already_processed", None

        partition_key = str(event.host_id or event.src_entity or "global")
        item = QueuedEventItem(
            event=event,
            enqueued_at=time.perf_counter(),
            partition_key=partition_key,
        )

        if self._queue.full():
            self.rejected_count += 1
            logger.warning(
                f"[AsyncDetectionQueue] Rejected event {event.event_id}: queue full ({self._queue.qsize()}/{self.config.max_queue_size})"
            )
            return False, "queue_full", None

        try:
            self._queue.put_nowait(item)
            self.queued_events += 1
            return True, "queued", self._queue.qsize()
        except asyncio.QueueFull:
            self.rejected_count += 1
            return False, "queue_full", None

    async def _worker_loop(self, worker_id: int) -> None:
        """Main worker consumption loop supporting both single-event and safe batched processing."""
        loop = asyncio.get_running_loop()

        while self._running:
            try:
                first_item = await self._queue.get()
            except asyncio.CancelledError:
                break
            except Exception as e:
                if not self._running:
                    break
                logger.error(f"[Worker-{worker_id}] Unexpected error dequeuing: {e}")
                try:
                    await asyncio.sleep(0.05)
                except (asyncio.CancelledError, RuntimeError):
                    break
                continue

            # Batch collection if batch handler is available
            items = [first_item]
            if self.detection_batch_handler is not None and self.batch_size > 1:
                while len(items) < self.batch_size:
                    try:
                        next_item = self._queue.get_nowait()
                        items.append(next_item)
                    except (asyncio.QueueEmpty, ValueError):
                        break

            batch_count = len(items)
            try:
                now = time.perf_counter()
                for it in items:
                    wait_time_ms = (now - it.enqueued_at) * 1000.0
                    self._wait_times.append(wait_time_ms)
                    it.state = EventProcessingState.PROCESSING
                self.processing_events += batch_count

                if self.detection_batch_handler is not None and len(items) > 1:
                    # Multi-item batch path: acquire locks in deterministic sorted order
                    unique_keys = sorted(list(set(it.partition_key for it in items)))
                    locks = [await self._get_host_lock(k) for k in unique_keys]
                    async with contextlib.AsyncExitStack() as stack:
                        for lock in locks:
                            await stack.enter_async_context(lock)

                        # Filter idempotency under lock
                        active_items = []
                        for it in items:
                            if it.event.event_id and it.event.event_id in self._completed_event_ids:
                                it.state = EventProcessingState.COMPLETED
                            else:
                                active_items.append(it)

                        if active_items:
                            proc_start = time.perf_counter()
                            try:
                                if self._executor:
                                    await loop.run_in_executor(
                                        self._executor,
                                        self.detection_batch_handler,
                                        [it.event for it in active_items],
                                    )
                                proc_ms = (time.perf_counter() - proc_start) * 1000.0
                                per_item_ms = proc_ms / len(active_items)
                                completed_ts = time.time()
                                for it in active_items:
                                    it.state = EventProcessingState.COMPLETED
                                    self.completed_events += 1
                                    self._processing_times.append(per_item_ms)
                                    self._e2e_latencies.append((time.perf_counter() - it.enqueued_at) * 1000.0)
                                    if it.event.event_id:
                                        self._completed_event_ids[it.event.event_id] = completed_ts
                                        if len(self._completed_event_ids) > self._max_completed_ids:
                                            self._completed_event_ids.popitem(last=False)
                            except Exception as batch_err:
                                logger.warning(f"[Worker-{worker_id}] Batch handler error, falling back to sequential retries: {batch_err}")
                                for it in active_items:
                                    await self._process_item_with_retries(it, loop)
                else:
                    # Single-item path (standard single event or fallback)
                    single_item = items[0]
                    host_lock = await self._get_host_lock(single_item.partition_key)
                    async with host_lock:
                        await self._process_item_with_retries(single_item, loop)

            except Exception as e:
                logger.error(f"[Worker-{worker_id}] Unhandled error processing item(s): {e}")
                for it in items:
                    if it.state == EventProcessingState.PROCESSING:
                        it.state = EventProcessingState.FAILED
            finally:
                self.processing_events = max(0, self.processing_events - batch_count)
                for _ in range(batch_count):
                    self._queue.task_done()

    async def _process_item_with_retries(
        self,
        item: QueuedEventItem,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Process a single event with transient failure classification and exponential backoff."""
        event = item.event

        # Check idempotency again under host lock
        if event.event_id and event.event_id in self._completed_event_ids:
            item.state = EventProcessingState.COMPLETED
            return

        while True:
            proc_start = time.perf_counter()
            try:
                # Fault injection check (for tests)
                if self._fault_hook:
                    self._fault_hook(event, item.attempts)

                # Execute detection handler in thread executor if handler is available
                if self.detection_handler and self._executor:
                    det_res, alert_res = await loop.run_in_executor(
                        self._executor,
                        self.detection_handler,
                        event,
                    )
                else:
                    det_res, alert_res = None, None

                # Processing succeeded
                proc_end = time.perf_counter()
                proc_time_ms = (proc_end - proc_start) * 1000.0
                e2e_time_ms = (proc_end - item.enqueued_at) * 1000.0

                self._processing_times.append(proc_time_ms)
                self._e2e_latencies.append(e2e_time_ms)

                item.state = EventProcessingState.COMPLETED
                self.completed_events += 1

                # Record in bounded idempotency cache
                if event.event_id:
                    self._completed_event_ids[event.event_id] = proc_end
                    if len(self._completed_event_ids) > self._max_completed_ids:
                        self._completed_event_ids.popitem(last=False)

                return

            except TransientDetectionError as exc:
                item.attempts += 1
                self.retry_count += 1
                item.last_error = str(exc)

                if item.attempts < self.config.max_retries:
                    item.state = EventProcessingState.RETRY_PENDING
                    # Exponential backoff
                    backoff = min(
                        self.config.retry_backoff_base_seconds * (self.config.retry_backoff_multiplier ** (item.attempts - 1)),
                        2.0,
                    )
                    logger.debug(
                        f"[AsyncDetectionQueue] Transient failure for {event.event_id} (attempt {item.attempts}/{self.config.max_retries}). "
                        f"Retrying in {backoff:.3f}s: {exc}"
                    )
                    await asyncio.sleep(backoff)
                    continue
                else:
                    # Retry limit exhausted -> Dead letter
                    item.state = EventProcessingState.FAILED
                    self.failed_events += 1
                    logger.warning(
                        f"[AsyncDetectionQueue] Retry exhausted for {event.event_id} after {item.attempts} attempts: {exc}"
                    )
                    self._record_dead_letter(item, failure_reason=str(exc), transient=True)
                    return

            except Exception as exc:
                # Permanent failure -> Immediate Dead Letter
                item.state = EventProcessingState.FAILED
                self.failed_events += 1
                logger.error(f"[AsyncDetectionQueue] Permanent failure for event {event.event_id}: {exc}")
                self._record_dead_letter(item, failure_reason=str(exc), transient=False)
                return

    def _record_dead_letter(
        self,
        item: QueuedEventItem,
        failure_reason: str,
        transient: bool,
    ) -> None:
        """Store terminal failure in bounded dead-letter record."""
        raw_dict = (
            item.event.model_dump()
            if hasattr(item.event, "model_dump")
            else (item.event.dict() if hasattr(item.event, "dict") else {})
        )
        dl_item = DeadLetterItem(
            event_id=item.event.event_id,
            event=raw_dict,
            failed_at=datetime.now(timezone.utc),
            attempts=item.attempts,
            failure_reason=failure_reason,
            transient=transient,
        )
        self._dead_letter_queue.append(dl_item)

    def _calculate_percentiles(self, samples: deque[float]) -> Dict[str, float]:
        """Compute p50, p95, and mean from a sliding window of float samples."""
        if not samples:
            return {"p50": 0.0, "p95": 0.0, "mean": 0.0}

        sorted_s = sorted(samples)
        n = len(sorted_s)
        mean_v = sum(sorted_s) / n

        p50_idx = min(int(n * 0.50), n - 1)
        p95_idx = min(int(n * 0.95), n - 1)

        return {
            "p50": round(sorted_s[p50_idx], 3),
            "p95": round(sorted_s[p95_idx], 3),
            "mean": round(mean_v, 3),
        }

    def get_metrics(self) -> QueueMetrics:
        """Generate structured QueueMetrics snapshot."""
        health = "healthy"
        if not self._running:
            health = "stopped"
        elif self.failed_events > 0 and self.failed_events > self.completed_events:
            health = "degraded"

        return QueueMetrics(
            queue_depth=self._queue.qsize(),
            queue_capacity=self.config.max_queue_size,
            accepted_events=self.accepted_events,
            queued_events=self.queued_events,
            processing_events=self.processing_events,
            completed_events=self.completed_events,
            failed_events=self.failed_events,
            retry_count=self.retry_count,
            duplicate_count=self.duplicate_count,
            rejected_count=self.rejected_count,
            dead_letter_count=len(self._dead_letter_queue),
            queue_wait_time_ms=self._calculate_percentiles(self._wait_times),
            processing_time_ms=self._calculate_percentiles(self._processing_times),
            end_to_end_latency_ms=self._calculate_percentiles(self._e2e_latencies),
            worker_health=health,
            active_workers=len([w for w in self._workers if not w.done()]),
            is_durable=False,
            durability_guarantee="in_memory_volatile_queue_loss_possible_on_process_restart",
        )

    def get_dead_letter_items(self) -> List[DeadLetterItem]:
        """Return list of current dead letter items."""
        return list(self._dead_letter_queue)

    def reset(self) -> None:
        """Reset internal queue, idempotency cache, metrics, and dead letter records."""
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except Exception:
                break

        self._dead_letter_queue.clear()
        self._completed_event_ids.clear()
        self._wait_times.clear()
        self._processing_times.clear()
        self._e2e_latencies.clear()

        self.accepted_events = 0
        self.queued_events = 0
        self.processing_events = 0
        self.completed_events = 0
        self.failed_events = 0
        self.retry_count = 0
        self.duplicate_count = 0
        self.rejected_count = 0
        logger.info("[AsyncDetectionQueue] Reset queue state and metrics.")
