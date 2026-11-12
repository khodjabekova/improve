"""Рассылка назначений в личные сообщения."""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from aiogram.exceptions import TelegramAPIError, TelegramNetworkError, TelegramRetryAfter

from . import texts
from .db import Assignment, Database, DeliveryStats

log = logging.getLogger(__name__)

Sender = Callable[[int, str], Awaitable[object]]


class DeliveryService:
    """Отправляет сохранённые назначения и записывает статус доставки.

    Рассылки одной игры выполняются строго последовательно (lock на игру),
    поэтому ``/end``, ``/retry`` и повторный ``/start`` не отправят одно
    назначение дважды. Ошибка у одного участника не мешает остальным.
    """

    def __init__(self, db: Database, send: Sender, *, pause: float = 0.05) -> None:
        self._db = db
        self._send = send
        self._pause = pause
        self._locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def deliver(self, game_id: int, giver_id: int | None = None) -> DeliveryStats:
        async with self._locks[game_id]:
            for assignment in await self._db.undelivered_assignments(game_id, giver_id):
                error = await self._send_one(assignment)
                await self._db.mark_delivery(assignment.id, ok=error is None, error=error)
                if self._pause:
                    await asyncio.sleep(self._pause)
            return await self._db.delivery_stats(game_id)

    async def _send_one(self, assignment: Assignment) -> str | None:
        text = texts.assignment_message(assignment)
        for attempt in range(3):
            try:
                await self._send(assignment.giver_chat_id, text)
                return None
            except TelegramRetryAfter as exc:
                log.warning("Flood control, ждём %s c", exc.retry_after)
                await asyncio.sleep(exc.retry_after)
            except TelegramNetworkError as exc:
                log.warning("Сетевая ошибка при отправке %s: %s", assignment.giver_id, exc)
                await asyncio.sleep(1 + attempt)
            except TelegramAPIError as exc:  # заблокировал бота, не начинал диалог и т. п.
                log.info("Не доставлено участнику %s: %s", assignment.giver_id, exc)
                return str(exc)[:500]
            except Exception as exc:  # noqa: BLE001 — один сбой не должен ломать рассылку
                log.exception("Неожиданная ошибка при отправке участнику %s", assignment.giver_id)
                return repr(exc)[:500]
        return "Не удалось отправить после нескольких попыток"
