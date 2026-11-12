"""Хранилище SQLite.

Каждая операция открывает своё соединение. Изменяющие операции выполняются
в транзакции ``BEGIN IMMEDIATE``: SQLite сразу берёт блокировку на запись,
поэтому проверка статуса игры и изменение данных атомарны относительно
других запросов (двойной ``/end``, регистрация во время жеребьёвки и т. п.).
"""
from __future__ import annotations

import enum
import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from .draw import make_pairs

SCHEMA = """
CREATE TABLE IF NOT EXISTS games (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_chat_id   INTEGER NOT NULL,
    group_title     TEXT    NOT NULL DEFAULT '',
    organizer_id    INTEGER NOT NULL,
    join_token      TEXT    NOT NULL UNIQUE,
    status          TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'drawn')),
    created_at      TEXT    NOT NULL,
    drawn_at        TEXT
);
-- В одной группе одновременно может быть только одна открытая игра.
CREATE UNIQUE INDEX IF NOT EXISTS games_one_open_per_group
    ON games(group_chat_id) WHERE status = 'open';

CREATE TABLE IF NOT EXISTS participants (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id             INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    telegram_user_id    INTEGER NOT NULL,
    private_chat_id     INTEGER NOT NULL,
    username            TEXT    NOT NULL,
    username_normalized TEXT    NOT NULL,
    full_name           TEXT    NOT NULL DEFAULT '',
    wish                TEXT,
    joined_at           TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL,
    UNIQUE (game_id, telegram_user_id),
    UNIQUE (game_id, username_normalized)
);

CREATE TABLE IF NOT EXISTS assignments (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id           INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    giver_id          INTEGER NOT NULL,
    receiver_id       INTEGER NOT NULL,
    receiver_username TEXT    NOT NULL,
    receiver_wish     TEXT,
    delivery_status   TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (delivery_status IN ('pending', 'sent', 'failed')),
    delivery_error    TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0,
    sent_at           TEXT,
    UNIQUE (game_id, giver_id),
    UNIQUE (game_id, receiver_id),
    CHECK (giver_id <> receiver_id),
    FOREIGN KEY (game_id, giver_id) REFERENCES participants(game_id, telegram_user_id),
    FOREIGN KEY (game_id, receiver_id) REFERENCES participants(game_id, telegram_user_id)
);

-- Пожелание, ожидающее выбора группы (когда пользователь в нескольких играх).
CREATE TABLE IF NOT EXISTS pending_wishes (
    telegram_user_id INTEGER PRIMARY KEY,
    text             TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
"""

OPEN = "open"
DRAWN = "drawn"


def normalize_username(username: str) -> str:
    return username.strip().lstrip("@").lower()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True, slots=True)
class Game:
    id: int
    group_chat_id: int
    group_title: str
    organizer_id: int
    join_token: str
    status: str
    created_at: str
    drawn_at: str | None

    @property
    def is_open(self) -> bool:
        return self.status == OPEN


@dataclass(frozen=True, slots=True)
class Participant:
    game_id: int
    telegram_user_id: int
    private_chat_id: int
    username: str
    full_name: str
    wish: str | None


@dataclass(frozen=True, slots=True)
class Assignment:
    id: int
    game_id: int
    giver_id: int
    giver_chat_id: int
    giver_username: str
    receiver_id: int
    receiver_username: str
    receiver_wish: str | None
    delivery_status: str
    group_title: str


@dataclass(frozen=True, slots=True)
class DeliveryStats:
    total: int
    sent: int
    failed_usernames: list[str]  # получатели личных сообщений (дарители), которым не доставлено


class RegisterStatus(enum.Enum):
    CREATED = "created"
    UPDATED = "updated"
    NOT_FOUND = "not_found"
    CLOSED = "closed"
    USERNAME_TAKEN = "username_taken"


@dataclass(frozen=True, slots=True)
class RegisterResult:
    status: RegisterStatus
    game: Game | None = None
    participant: Participant | None = None
    # Участник, за которым в базе числится этот @username (устаревшие данные).
    conflicting: Participant | None = None


class WishStatus(enum.Enum):
    SAVED = "saved"
    CLOSED = "closed"
    NOT_PARTICIPANT = "not_participant"


class DrawStatus(enum.Enum):
    DRAWN = "drawn"
    NOT_FOUND = "not_found"
    ALREADY_DRAWN = "already_drawn"
    NOT_ENOUGH = "not_enough"


@dataclass(frozen=True, slots=True)
class DrawResult:
    status: DrawStatus
    participants: int = 0


@dataclass(frozen=True, slots=True)
class UsernameProblem:
    participant: Participant
    reason: str  # "no_username" | "conflict"


def _game(row: aiosqlite.Row) -> Game:
    return Game(
        id=row["id"],
        group_chat_id=row["group_chat_id"],
        group_title=row["group_title"],
        organizer_id=row["organizer_id"],
        join_token=row["join_token"],
        status=row["status"],
        created_at=row["created_at"],
        drawn_at=row["drawn_at"],
    )


def _participant(row: aiosqlite.Row) -> Participant:
    return Participant(
        game_id=row["game_id"],
        telegram_user_id=row["telegram_user_id"],
        private_chat_id=row["private_chat_id"],
        username=row["username"],
        full_name=row["full_name"],
        wish=row["wish"],
    )


_ASSIGNMENT_SELECT = """
SELECT a.id, a.game_id, a.giver_id, p.private_chat_id AS giver_chat_id,
       p.username AS giver_username, a.receiver_id, a.receiver_username,
       a.receiver_wish, a.delivery_status, g.group_title
FROM assignments a
JOIN participants p ON p.game_id = a.game_id AND p.telegram_user_id = a.giver_id
JOIN games g ON g.id = a.game_id
"""


def _assignment(row: aiosqlite.Row) -> Assignment:
    return Assignment(**{key: row[key] for key in row.keys()})


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)

    # ------------------------------------------------------------------ infra
    @asynccontextmanager
    async def _connect(self) -> AsyncIterator[aiosqlite.Connection]:
        conn = await aiosqlite.connect(self.path, isolation_level=None)
        conn.row_factory = aiosqlite.Row
        try:
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.execute("PRAGMA busy_timeout = 10000")
            yield conn
        finally:
            await conn.close()

    @asynccontextmanager
    async def _transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        async with self._connect() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                await conn.execute("ROLLBACK")
                raise
            else:
                await conn.execute("COMMIT")

    async def init(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        async with self._connect() as conn:
            await conn.execute("PRAGMA journal_mode = WAL")
            await conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ games
    async def get_or_create_open_game(
        self, group_chat_id: int, group_title: str, organizer_id: int
    ) -> tuple[Game, bool]:
        """Возвращает открытую игру группы или создаёт новую. Второй элемент — создана ли."""
        async with self._transaction() as conn:
            cur = await conn.execute(
                "SELECT * FROM games WHERE group_chat_id = ? AND status = 'open'",
                (group_chat_id,),
            )
            row = await cur.fetchone()
            if row is not None:
                await conn.execute(
                    "UPDATE games SET group_title = ? WHERE id = ?", (group_title, row["id"])
                )
                return _game(row), False
            cur = await conn.execute(
                "INSERT INTO games (group_chat_id, group_title, organizer_id, join_token, created_at)"
                " VALUES (?, ?, ?, ?, ?) RETURNING *",
                (group_chat_id, group_title, organizer_id, secrets.token_urlsafe(16), _now()),
            )
            return _game(await cur.fetchone()), True

    async def get_game(self, game_id: int) -> Game | None:
        async with self._connect() as conn:
            cur = await conn.execute("SELECT * FROM games WHERE id = ?", (game_id,))
            row = await cur.fetchone()
            return _game(row) if row else None

    async def get_game_by_token(self, token: str) -> Game | None:
        async with self._connect() as conn:
            cur = await conn.execute("SELECT * FROM games WHERE join_token = ?", (token,))
            row = await cur.fetchone()
            return _game(row) if row else None

    async def get_current_game(self, group_chat_id: int) -> Game | None:
        """Открытая игра группы, а если её нет — последняя проведённая."""
        async with self._connect() as conn:
            cur = await conn.execute(
                "SELECT * FROM games WHERE group_chat_id = ?"
                " ORDER BY (status = 'open') DESC, id DESC LIMIT 1",
                (group_chat_id,),
            )
            row = await cur.fetchone()
            return _game(row) if row else None

    async def migrate_group(self, old_chat_id: int, new_chat_id: int) -> None:
        """Группа превратилась в супергруппу и получила новый ID."""
        async with self._transaction() as conn:
            await conn.execute(
                "UPDATE games SET group_chat_id = ? WHERE group_chat_id = ?",
                (new_chat_id, old_chat_id),
            )

    # ----------------------------------------------------------- participants
    async def register(
        self,
        token: str,
        user_id: int,
        private_chat_id: int,
        username: str,
        full_name: str = "",
    ) -> RegisterResult:
        normalized = normalize_username(username)
        username = username.strip().lstrip("@")
        now = _now()
        async with self._transaction() as conn:
            cur = await conn.execute("SELECT * FROM games WHERE join_token = ?", (token,))
            row = await cur.fetchone()
            if row is None:
                return RegisterResult(RegisterStatus.NOT_FOUND)
            game = _game(row)
            if not game.is_open:
                return RegisterResult(RegisterStatus.CLOSED, game)

            cur = await conn.execute(
                "SELECT * FROM participants WHERE game_id = ? AND username_normalized = ?"
                " AND telegram_user_id <> ?",
                (game.id, normalized, user_id),
            )
            other = await cur.fetchone()
            if other is not None:
                return RegisterResult(
                    RegisterStatus.USERNAME_TAKEN, game, conflicting=_participant(other)
                )

            cur = await conn.execute(
                "SELECT 1 FROM participants WHERE game_id = ? AND telegram_user_id = ?",
                (game.id, user_id),
            )
            existed = await cur.fetchone() is not None
            cur = await conn.execute(
                """
                INSERT INTO participants (game_id, telegram_user_id, private_chat_id, username,
                                          username_normalized, full_name, joined_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (game_id, telegram_user_id) DO UPDATE SET
                    private_chat_id = excluded.private_chat_id,
                    username = excluded.username,
                    username_normalized = excluded.username_normalized,
                    full_name = excluded.full_name,
                    updated_at = excluded.updated_at
                RETURNING *
                """,
                (game.id, user_id, private_chat_id, username, normalized, full_name, now, now),
            )
            participant = _participant(await cur.fetchone())
            status = RegisterStatus.UPDATED if existed else RegisterStatus.CREATED
            return RegisterResult(status, game, participant)

    async def list_participants(self, game_id: int) -> list[Participant]:
        async with self._connect() as conn:
            cur = await conn.execute(
                "SELECT * FROM participants WHERE game_id = ? ORDER BY id", (game_id,)
            )
            return [_participant(r) for r in await cur.fetchall()]

    async def get_participant(self, game_id: int, user_id: int) -> Participant | None:
        async with self._connect() as conn:
            cur = await conn.execute(
                "SELECT * FROM participants WHERE game_id = ? AND telegram_user_id = ?",
                (game_id, user_id),
            )
            row = await cur.fetchone()
            return _participant(row) if row else None

    async def games_for_user(self, user_id: int, *, only_open: bool) -> list[Game]:
        query = (
            "SELECT g.* FROM games g JOIN participants p ON p.game_id = g.id"
            " WHERE p.telegram_user_id = ?"
        )
        if only_open:
            query += " AND g.status = 'open'"
        async with self._connect() as conn:
            cur = await conn.execute(query + " ORDER BY g.id", (user_id,))
            return [_game(r) for r in await cur.fetchall()]

    async def sync_usernames(
        self, game_id: int, fetched: Mapping[int, str | None]
    ) -> list[UsernameProblem]:
        """Подтягивает актуальные @username перед жеребьёвкой.

        ``fetched`` — то, что вернул Telegram (``None`` — username удалён);
        участники, которых нет в словаре, сохраняют записанный username.
        Если кто-то остался без username или записанный (устаревший) username
        совпал с актуальным username другого участника, ничего не меняется и
        возвращается список проблем — регистрация остаётся открытой.
        """
        async with self._transaction() as conn:
            cur = await conn.execute(
                "SELECT g.status FROM games g WHERE g.id = ?", (game_id,)
            )
            row = await cur.fetchone()
            if row is None or row["status"] != OPEN:
                return []
            cur = await conn.execute(
                "SELECT * FROM participants WHERE game_id = ? ORDER BY id", (game_id,)
            )
            participants = [_participant(r) for r in await cur.fetchall()]

            problems: list[UsernameProblem] = []
            final: dict[int, str] = {}
            for p in participants:
                if p.telegram_user_id in fetched:
                    current = fetched[p.telegram_user_id]
                    if not current:
                        problems.append(UsernameProblem(p, "no_username"))
                        continue
                    final[p.telegram_user_id] = current.lstrip("@")
                else:
                    final[p.telegram_user_id] = p.username

            owners: dict[str, list[Participant]] = {}
            for p in participants:
                if p.telegram_user_id in final:
                    owners.setdefault(normalize_username(final[p.telegram_user_id]), []).append(p)
            for group in owners.values():
                if len(group) > 1:
                    # Telegram username уникален, значит устаревшие — те, кого не удалось
                    # проверить. Если проверить не удалось никого, просим всех.
                    stale = [p for p in group if p.telegram_user_id not in fetched] or group
                    problems.extend(UsernameProblem(p, "conflict") for p in stale)
            if problems:
                return problems

            changed = [p for p in participants if final[p.telegram_user_id] != p.username]
            now = _now()
            # Два прохода, чтобы обмен username между участниками не нарушил UNIQUE.
            for p in changed:
                await conn.execute(
                    "UPDATE participants SET username_normalized = ? WHERE game_id = ? AND telegram_user_id = ?",
                    (f"#{p.telegram_user_id}", game_id, p.telegram_user_id),
                )
            for p in changed:
                name = final[p.telegram_user_id]
                await conn.execute(
                    "UPDATE participants SET username = ?, username_normalized = ?, updated_at = ?"
                    " WHERE game_id = ? AND telegram_user_id = ?",
                    (name, normalize_username(name), now, game_id, p.telegram_user_id),
                )
            return []

    # ------------------------------------------------------------------ wishes
    async def set_wish(self, game_id: int, user_id: int, wish: str) -> WishStatus:
        async with self._transaction() as conn:
            cur = await conn.execute("SELECT status FROM games WHERE id = ?", (game_id,))
            row = await cur.fetchone()
            if row is None:
                return WishStatus.NOT_PARTICIPANT
            if row["status"] != OPEN:
                return WishStatus.CLOSED
            cur = await conn.execute(
                "UPDATE participants SET wish = ?, updated_at = ?"
                " WHERE game_id = ? AND telegram_user_id = ?",
                (wish, _now(), game_id, user_id),
            )
            return WishStatus.SAVED if cur.rowcount else WishStatus.NOT_PARTICIPANT

    async def save_pending_wish(self, user_id: int, text: str) -> None:
        async with self._transaction() as conn:
            await conn.execute(
                "INSERT INTO pending_wishes (telegram_user_id, text, created_at) VALUES (?, ?, ?)"
                " ON CONFLICT (telegram_user_id) DO UPDATE SET text = excluded.text,"
                " created_at = excluded.created_at",
                (user_id, text, _now()),
            )

    async def pop_pending_wish(self, user_id: int) -> str | None:
        async with self._transaction() as conn:
            cur = await conn.execute(
                "DELETE FROM pending_wishes WHERE telegram_user_id = ? RETURNING text", (user_id,)
            )
            row = await cur.fetchone()
            return row["text"] if row else None

    # -------------------------------------------------------------------- draw
    async def draw(self, game_id: int) -> DrawResult:
        """Атомарно проводит жеребьёвку: пары сохраняются один раз."""
        async with self._transaction() as conn:
            cur = await conn.execute("SELECT status FROM games WHERE id = ?", (game_id,))
            row = await cur.fetchone()
            if row is None:
                return DrawResult(DrawStatus.NOT_FOUND)
            if row["status"] != OPEN:
                return DrawResult(DrawStatus.ALREADY_DRAWN)
            cur = await conn.execute(
                "SELECT * FROM participants WHERE game_id = ? ORDER BY id", (game_id,)
            )
            participants = {r["telegram_user_id"]: _participant(r) for r in await cur.fetchall()}
            if len(participants) < 2:
                return DrawResult(DrawStatus.NOT_ENOUGH, len(participants))

            pairs = make_pairs(list(participants))
            await conn.executemany(
                "INSERT INTO assignments (game_id, giver_id, receiver_id, receiver_username,"
                " receiver_wish) VALUES (?, ?, ?, ?, ?)",
                [
                    (game_id, giver, receiver, participants[receiver].username,
                     participants[receiver].wish)
                    for giver, receiver in pairs
                ],
            )
            await conn.execute(
                "UPDATE games SET status = 'drawn', drawn_at = ? WHERE id = ?", (_now(), game_id)
            )
            return DrawResult(DrawStatus.DRAWN, len(participants))

    # ---------------------------------------------------------------- delivery
    async def undelivered_assignments(
        self, game_id: int, giver_id: int | None = None
    ) -> list[Assignment]:
        query = _ASSIGNMENT_SELECT + " WHERE a.game_id = ? AND a.delivery_status <> 'sent'"
        params: tuple = (game_id,)
        if giver_id is not None:
            query += " AND a.giver_id = ?"
            params += (giver_id,)
        async with self._connect() as conn:
            cur = await conn.execute(query + " ORDER BY a.id", params)
            return [_assignment(r) for r in await cur.fetchall()]

    async def undelivered_games_for_giver(self, giver_id: int) -> list[int]:
        async with self._connect() as conn:
            cur = await conn.execute(
                "SELECT game_id FROM assignments WHERE giver_id = ? AND delivery_status <> 'sent'"
                " ORDER BY game_id",
                (giver_id,),
            )
            return [r["game_id"] for r in await cur.fetchall()]

    async def mark_delivery(self, assignment_id: int, ok: bool, error: str | None = None) -> None:
        async with self._transaction() as conn:
            await conn.execute(
                "UPDATE assignments SET delivery_status = ?, delivery_error = ?,"
                " attempts = attempts + 1, sent_at = CASE WHEN ? THEN ? ELSE sent_at END"
                " WHERE id = ?",
                ("sent" if ok else "failed", error, ok, _now(), assignment_id),
            )

    async def update_private_chat(self, user_id: int, private_chat_id: int) -> None:
        async with self._transaction() as conn:
            await conn.execute(
                "UPDATE participants SET private_chat_id = ? WHERE telegram_user_id = ?",
                (private_chat_id, user_id),
            )

    async def delivery_stats(self, game_id: int) -> DeliveryStats:
        async with self._connect() as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) AS total,"
                " COALESCE(SUM(delivery_status = 'sent'), 0) AS sent"
                " FROM assignments WHERE game_id = ?",
                (game_id,),
            )
            row = await cur.fetchone()
            cur = await conn.execute(
                "SELECT p.username FROM assignments a JOIN participants p"
                " ON p.game_id = a.game_id AND p.telegram_user_id = a.giver_id"
                " WHERE a.game_id = ? AND a.delivery_status <> 'sent' ORDER BY a.id",
                (game_id,),
            )
            failed = [r["username"] for r in await cur.fetchall()]
            return DeliveryStats(total=row["total"], sent=row["sent"], failed_usernames=failed)
