"""Сквозной сценарий через Dispatcher с имитацией Bot API."""
from __future__ import annotations

import itertools
from datetime import datetime, timezone

import pytest
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.base import BaseSession
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramForbiddenError
from aiogram.methods import AnswerCallbackQuery, EditMessageText, GetChatMember, GetMe, SendMessage
from aiogram.types import (
    CallbackQuery,
    Chat,
    ChatMemberLeft,
    ChatMemberMember,
    ChatMemberUpdated,
    Message,
    Update,
    User,
)

from santa_bot.config import Config
from santa_bot.delivery import DeliveryService
from santa_bot.handlers import router

BOT_USER = User(id=999, is_bot=True, first_name="Santa", username="santa_test_bot")
GROUP = Chat(id=-1001, type="supergroup", title="Офис")
_ids = itertools.count(1)


class FakeTelegram(BaseSession):
    def __init__(self):
        super().__init__()
        self.users: dict[int, User] = {}
        self.group_members: set[int] = set()
        self.blocked: set[int] = set()
        self.sent: list[SendMessage] = []
        self.edited: list[EditMessageText] = []

    async def make_request(self, bot, method, timeout=None):
        if isinstance(method, GetMe):
            return BOT_USER
        if isinstance(method, SendMessage):
            if method.chat_id in self.blocked:
                raise TelegramForbiddenError(method=method, message="Forbidden: bot was blocked by the user")
            self.sent.append(method)
            return Message(
                message_id=next(_ids),
                date=datetime.now(timezone.utc),
                chat=Chat(id=method.chat_id, type="private"),
                text=method.text,
            )
        if isinstance(method, GetChatMember):
            user = self.users.get(method.user_id) or User(id=method.user_id, is_bot=False, first_name="?")
            if method.user_id in self.group_members:
                return ChatMemberMember(user=user)
            return ChatMemberLeft(user=user)
        if isinstance(method, EditMessageText):
            self.edited.append(method)
            return True
        if isinstance(method, AnswerCallbackQuery):
            return True
        raise AssertionError(f"Unexpected method {method!r}")

    async def close(self):
        pass

    async def stream_content(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError

    def to(self, chat_id: int) -> list[str]:
        return [m.text for m in self.sent if m.chat_id == chat_id]

    def last(self, chat_id: int) -> SendMessage:
        return [m for m in self.sent if m.chat_id == chat_id][-1]


@pytest.fixture(scope="module")
def dispatcher():
    dp = Dispatcher()
    dp.include_router(router)
    return dp


class Env:
    def __init__(self, dp, db, require_membership=True):
        self.dp = dp
        self.db = db
        self.tg = FakeTelegram()
        self.bot = Bot("42:TEST", session=self.tg, default=DefaultBotProperties(parse_mode=ParseMode.HTML))

        async def send(chat_id, text):
            await self.bot.send_message(chat_id, text)

        self.delivery = DeliveryService(db, send, pause=0)
        self.config = Config(bot_token="42:TEST", require_group_membership=require_membership)

    def user(self, uid, username=None, member=True):
        u = User(id=uid, is_bot=False, first_name=f"Имя{uid}", username=username)
        self.tg.users[uid] = u
        if member:
            self.tg.group_members.add(uid)
        return u

    async def feed(self, **update):
        await self.dp.feed_update(
            self.bot,
            Update(update_id=next(_ids), **update),
            db=self.db,
            delivery=self.delivery,
            config=self.config,
        )

    async def add_bot(self, by: User):
        await self.feed(
            my_chat_member=ChatMemberUpdated(
                chat=GROUP,
                from_user=by,
                date=datetime.now(timezone.utc),
                old_chat_member=ChatMemberLeft(user=BOT_USER),
                new_chat_member=ChatMemberMember(user=BOT_USER),
            )
        )

    async def private(self, user: User, text: str):
        await self.feed(
            message=Message(
                message_id=next(_ids),
                date=datetime.now(timezone.utc),
                chat=Chat(id=user.id, type="private"),
                from_user=user,
                text=text,
            )
        )

    async def group(self, user: User, text: str):
        await self.feed(
            message=Message(
                message_id=next(_ids),
                date=datetime.now(timezone.utc),
                chat=GROUP,
                from_user=user,
                text=text,
            )
        )

    async def click(self, user: User, data: str):
        await self.feed(
            callback_query=CallbackQuery(
                id=str(next(_ids)),
                from_user=user,
                chat_instance="ci",
                data=data,
                message=Message(
                    message_id=next(_ids),
                    date=datetime.now(timezone.utc),
                    chat=Chat(id=user.id, type="private"),
                    from_user=BOT_USER,
                    text="choose",
                ),
            )
        )

    async def join_link_payload(self) -> str:
        game = await self.db.get_current_game(GROUP.id)
        return f"/start santa_{game.join_token}"


@pytest.fixture
def env(dispatcher, db):
    return Env(dispatcher, db)


async def test_full_game(env):
    org = env.user(1, "Organizer")
    alina = env.user(2, "Alina")
    timur = env.user(3, "timur")
    nouser = env.user(4, None)
    outsider = env.user(5, "Outsider", member=False)

    await env.add_bot(org)
    announce = env.tg.last(GROUP.id)
    url = announce.reply_markup.inline_keyboard[0][0].url
    game = await env.db.get_current_game(GROUP.id)
    assert url == f"https://t.me/santa_test_bot?start=santa_{game.join_token}"
    assert game.organizer_id == org.id

    # Повторное добавление использует ту же игру.
    await env.add_bot(org)
    assert env.tg.last(GROUP.id).reply_markup.inline_keyboard[0][0].url == url

    start = await env.join_link_payload()
    await env.private(alina, start)
    await env.private(alina, start)  # повторный Start
    assert "Данные обновлены" in env.tg.to(alina.id)[-1]
    await env.private(timur, start)
    await env.private(nouser, start)
    assert "нужен @username" in env.tg.to(nouser.id)[-1]
    await env.private(outsider, start)
    assert "только участники группы" in env.tg.to(outsider.id)[-1]

    await env.private(alina, "/wish Чай")
    await env.private(alina, "/wish Хочу книгу или чай")
    assert "сохранено" in env.tg.to(alina.id)[-1]
    await env.private(timur, "/wish")
    assert "/wish Хочу книгу или чай" in env.tg.to(timur.id)[-1]

    await env.group(alina, "/stat")
    stat = env.tg.last(GROUP.id).text
    assert "Участников: <b>2</b>" in stat and "@Alina" in stat and "@timur" in stat
    assert "книгу" not in stat

    await env.group(alina, "/end")
    assert "только организатор" in env.tg.last(GROUP.id).text

    await env.group(org, "/end")
    assert "Жеребьёвка завершена. Доставлено 2 из 2 сообщений." in env.tg.last(GROUP.id).text
    assert env.tg.to(timur.id)[-1].startswith("🎅 Ты — Тайный Санта для @Alina\n🎁 Пожелание: «Хочу книгу или чай».")
    assert env.tg.to(alina.id)[-1].startswith("🎅 Ты — Тайный Санта для @timur")
    # Пожелание Алины увидел только её Санта.
    assert not any("книгу или чай»." in t for t in env.tg.to(alina.id) if t.startswith("🎅"))

    sent_before = len(env.tg.sent)
    await env.group(org, "/end")
    assert "уже проведена" in env.tg.last(GROUP.id).text
    assert len(env.tg.sent) == sent_before + 1  # только статус в группу

    late = env.user(6, "late")
    await env.private(late, start)
    assert "регистрация закрыта" in env.tg.to(late.id)[-1]
    assert len(await env.db.list_participants(game.id)) == 2


async def test_end_requires_two_participants(env):
    org = env.user(1, "Organizer")
    await env.add_bot(org)
    await env.private(org, await env.join_link_payload())
    await env.group(org, "/end")
    assert "минимум 2 участника, сейчас: 1" in env.tg.last(GROUP.id).text
    assert (await env.db.get_current_game(GROUP.id)).is_open


async def test_blocked_user_and_retry(env):
    org = env.user(1, "Organizer")
    users = [env.user(uid, f"u{uid}") for uid in range(2, 7)]
    await env.add_bot(org)
    start = await env.join_link_payload()
    for u in users:
        await env.private(u, start)
    env.tg.blocked.add(4)

    await env.group(org, "/end")
    status = env.tg.last(GROUP.id).text
    assert "Доставлено 4 из 5 сообщений." in status and "@u4" in status

    await env.group(org, "/retry")
    assert "Доставлено 4 из 5" in env.tg.last(GROUP.id).text

    game = await env.db.get_current_game(GROUP.id)
    (assignment,) = await env.db.undelivered_assignments(game.id)

    env.tg.blocked.clear()
    await env.private(users[2], "/start")  # разблокировал и нажал Start
    assert env.tg.to(4)[-1].startswith(f"🎅 Ты — Тайный Санта для @{assignment.receiver_username}")
    assert (await env.db.delivery_stats(game.id)).sent == 5

    before = len(env.tg.sent)
    await env.group(org, "/retry")
    assert len(env.tg.sent) == before + 1
    assert "Доставлено 5 из 5 сообщений." in env.tg.last(GROUP.id).text


async def test_wish_with_several_games(env, db):
    org = env.user(1, "Organizer")
    alina = env.user(2, "Alina")
    await env.add_bot(org)
    await env.private(alina, await env.join_link_payload())
    other, _ = await db.get_or_create_open_game(-2002, "Семья", organizer_id=1)
    await db.register(other.join_token, alina.id, alina.id, "Alina")

    await env.private(alina, "/wish Варежки")
    keyboard = env.tg.last(alina.id).reply_markup.inline_keyboard
    assert [row[0].text for row in keyboard] == ["Офис", "Семья"]
    await env.click(alina, keyboard[1][0].callback_data)
    assert "Семья" in env.tg.edited[-1].text
    assert (await db.get_participant(other.id, alina.id)).wish == "Варежки"
    office = await db.get_current_game(GROUP.id)
    assert (await db.get_participant(office.id, alina.id)).wish is None


async def test_username_changed_before_end_is_refreshed(env, db):
    org = env.user(1, "Organizer")
    a = env.user(2, "old_name")
    b = env.user(3, "bob")
    await env.add_bot(org)
    start = await env.join_link_payload()
    await env.private(a, start)
    await env.private(b, start)
    env.user(2, "new_name")
    env.user(3, None)  # удалил username

    await env.group(org, "/end")
    assert "Жеребьёвка отложена" in env.tg.last(GROUP.id).text
    assert (await db.get_current_game(GROUP.id)).is_open

    env.user(3, "bob2")
    await env.group(org, "/end")
    assert "Доставлено 2 из 2" in env.tg.last(GROUP.id).text
    assert env.tg.to(3)[-1].startswith("🎅 Ты — Тайный Санта для @new_name")


async def test_username_taken_by_stale_participant(env, db):
    org = env.user(1, "Organizer")
    a = env.user(2, "alina")
    await env.add_bot(org)
    start = await env.join_link_payload()
    await env.private(a, start)
    env.user(2, None)  # удалила username, ссылку заново не открывала
    b = env.user(3, "Alina")  # другой человек занял имя
    await env.private(b, start)
    assert "устаревшие данные" in env.tg.to(b.id)[-1]
    assert "откройте ссылку ещё раз" in env.tg.to(a.id)[-1]
    a = env.user(2, "alina_new")
    await env.private(a, start)
    await env.private(b, start)
    assert "Вы участвуете" in env.tg.to(b.id)[-1]


async def test_username_conflict_resolved_automatically(env, db):
    org = env.user(1, "Organizer")
    a = env.user(2, "alina")
    await env.add_bot(org)
    start = await env.join_link_payload()
    await env.private(a, start)
    env.user(2, "alina_new")  # сменила имя, но ссылку не открывала
    b = env.user(3, "Alina")
    await env.private(b, start)
    assert "Вы участвуете" in env.tg.to(b.id)[-1]
    game = await db.get_current_game(GROUP.id)
    assert {p.username for p in await db.list_participants(game.id)} == {"alina_new", "Alina"}
