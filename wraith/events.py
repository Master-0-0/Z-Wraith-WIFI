"""进程内事件总线：实时日志 / 攻击进度推送到 WebSocket。"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any, Iterable

from .models import Event

LEVELS = {"debug", "info", "success", "warning", "error", "attack"}


class EventBus:
    """极简发布/订阅总线.

    - ``emit`` 可在同步上下文中调用（攻击模块、子进程解析器）。
    - 订阅者通过 :meth:`subscribe` 获得一个 ``asyncio.Queue``，断线后调用
      :meth:`unsubscribe` 释放。
    - 保留最近 ``history_size`` 条事件供页面刷新后回放。
    """

    def __init__(self, history_size: int = 800) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._history: deque[Event] = deque(maxlen=history_size)
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    # ------------------------------------------------------------- publish
    def emit(
        self,
        level: str,
        source: str,
        message: str,
        **data: Any,
    ) -> Event:
        level = level if level in LEVELS else "info"
        event = Event(ts=time.time(), level=level, source=source, message=message, data=data)
        self.publish(event)
        return event

    def publish(self, event: Event) -> None:
        self._history.append(event)
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # 慢客户端丢弃最旧事件，避免拖垮攻击流程
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass
            except RuntimeError:
                self._subscribers.discard(queue)

    # ------------------------------------------------------------- consume
    def subscribe(self, maxsize: int = 600) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def history(self, limit: int = 200) -> list[dict[str, Any]]:
        items: Iterable[Event] = list(self._history)[-limit:]
        return [e.to_dict() for e in items]

    def clear(self) -> None:
        self._history.clear()
