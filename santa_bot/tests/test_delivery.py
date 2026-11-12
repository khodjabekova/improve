from aiogram.exceptions import TelegramForbiddenError
from aiogram.methods import SendMessage

from santa_bot.db import DrawStatus
from santa_bot.delivery import DeliveryService


class FakeSender:
    def __init__(self):
        self.blocked: set[int] = set()
        self.sent: list[tuple[int, str]] = []

    async def __call__(self, chat_id: int, text: str) -> None:
        if chat_id in self.blocked:
            raise TelegramForbiddenError(
                method=SendMessage(chat_id=chat_id, text=text),
                message="Forbidden: bot was blocked by the user",
            )
        self.sent.append((chat_id, text))


async def test_blocked_user_does_not_stop_delivery_and_gets_original_on_retry(db, game):
    for uid in range(10, 15):
        await db.register(game.join_token, uid, uid, f"User{uid}")
    await db.set_wish(game.id, 10, "Хочу <книгу> & чай")
    assert (await db.draw(game.id)).status is DrawStatus.DRAWN
    original = {a.giver_id: a.receiver_username for a in await db.undelivered_assignments(game.id)}

    sender = FakeSender()
    sender.blocked.add(12)
    service = DeliveryService(db, sender, pause=0)

    stats = await service.deliver(game.id)
    assert (stats.sent, stats.total) == (4, 5)
    assert stats.failed_usernames == ["User12"]
    assert {chat for chat, _ in sender.sent} == {10, 11, 13, 14}
    for chat, text in sender.sent:
        assert f"@{original[chat]}" in text
    wish_texts = [t for _, t in sender.sent if "книгу" in t]
    assert all("&lt;книгу&gt; &amp; чай" in t for t in wish_texts)

    # Пока заблокирован — повтор снова неудачен, остальным повторно не шлём.
    sender.sent.clear()
    stats = await service.deliver(game.id)
    assert (stats.sent, stats.total) == (4, 5)
    assert sender.sent == []

    sender.blocked.clear()
    stats = await service.deliver(game.id)
    assert (stats.sent, stats.total, stats.failed_usernames) == (5, 5, [])
    assert len(sender.sent) == 1
    chat, text = sender.sent[0]
    assert chat == 12 and f"🎅 Ты — Тайный Санта для @{original[12]}" in text

    sender.sent.clear()
    await service.deliver(game.id)
    assert sender.sent == []


async def test_concurrent_deliveries_send_once(db, game):
    import asyncio

    for uid in range(10, 13):
        await db.register(game.join_token, uid, uid, f"User{uid}")
    await db.draw(game.id)
    sender = FakeSender()
    service = DeliveryService(db, sender, pause=0)
    await asyncio.gather(service.deliver(game.id), service.deliver(game.id))
    assert sorted(chat for chat, _ in sender.sent) == [10, 11, 12]
