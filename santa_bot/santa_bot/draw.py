"""Жеребьёвка: случайный цикл по всем участникам."""
from __future__ import annotations

import random
from collections.abc import Sequence
from typing import TypeVar

T = TypeVar("T")

_rng = random.SystemRandom()


def make_pairs(items: Sequence[T], rng: random.Random | None = None) -> list[tuple[T, T]]:
    """Перемешивает участников и замыкает их в один цикл.

    Каждый дарит следующему в перемешанном списке, последний — первому.
    Поэтому у каждого ровно один получатель, каждый получает ровно один
    подарок и никто не дарит самому себе (при n >= 2).
    """
    if len(items) < 2:
        raise ValueError("Для жеребьёвки нужно минимум два участника")
    if len(set(items)) != len(items):
        raise ValueError("Участники должны быть уникальными")
    order = list(items)
    (rng or _rng).shuffle(order)
    n = len(order)
    return [(order[i], order[(i + 1) % n]) for i in range(n)]
