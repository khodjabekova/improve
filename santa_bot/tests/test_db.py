import asyncio
import sqlite3

import pytest

from santa_bot.db import DrawStatus, RegisterStatus, WishStatus


async def register_many(db, game, n):
    for uid in range(10, 10 + n):
        result = await db.register(game.join_token, uid, uid, f"User{uid}")
        assert result.status is RegisterStatus.CREATED


async def test_game_is_reused_for_same_group(db, game):
    again, created = await db.get_or_create_open_game(-100, "Офис 2", organizer_id=2)
    assert not created
    assert again.id == game.id and again.join_token == game.join_token
    assert again.organizer_id == 1


async def test_new_game_after_draw(db, game):
    await register_many(db, game, 2)
    await db.draw(game.id)
    new, created = await db.get_or_create_open_game(-100, "Офис", organizer_id=1)
    assert created and new.id != game.id


async def test_repeat_registration_does_not_duplicate_and_keeps_wish(db, game):
    first = await db.register(game.join_token, 10, 10, "Alina")
    assert first.status is RegisterStatus.CREATED
    assert await db.set_wish(game.id, 10, "Книга") is WishStatus.SAVED
    second = await db.register(game.join_token, 10, 10, "Alina_new")
    assert second.status is RegisterStatus.UPDATED
    participants = await db.list_participants(game.id)
    assert len(participants) == 1
    assert participants[0].username == "Alina_new"
    assert participants[0].wish == "Книга"


async def test_username_conflict_is_case_insensitive(db, game):
    await db.register(game.join_token, 10, 10, "Alina")
    result = await db.register(game.join_token, 11, 11, "@alina")
    assert result.status is RegisterStatus.USERNAME_TAKEN
    assert result.conflicting.telegram_user_id == 10
    assert len(await db.list_participants(game.id)) == 1


async def test_wish_is_replaced(db, game):
    await db.register(game.join_token, 10, 10, "Alina")
    await db.set_wish(game.id, 10, "Чай")
    await db.set_wish(game.id, 10, "Хочу книгу\nили чай")
    (p,) = await db.list_participants(game.id)
    assert p.wish == "Хочу книгу\nили чай"


async def test_wish_for_non_participant(db, game):
    assert await db.set_wish(game.id, 999, "x") is WishStatus.NOT_PARTICIPANT


async def test_draw_needs_two(db, game):
    await register_many(db, game, 1)
    result = await db.draw(game.id)
    assert result.status is DrawStatus.NOT_ENOUGH
    assert (await db.get_game(game.id)).is_open


@pytest.mark.parametrize("n", [2, 3, 5])
async def test_draw_assignments_valid(db, game, n):
    await register_many(db, game, n)
    await db.set_wish(game.id, 10, "Носки")
    assert (await db.draw(game.id)).status is DrawStatus.DRAWN
    assignments = await db.undelivered_assignments(game.id)
    assert len(assignments) == n
    assert {a.giver_id for a in assignments} == set(range(10, 10 + n))
    assert {a.receiver_id for a in assignments} == set(range(10, 10 + n))
    assert all(a.giver_id != a.receiver_id for a in assignments)
    for a in assignments:
        assert a.receiver_username == f"User{a.receiver_id}"
        assert a.receiver_wish == ("Носки" if a.receiver_id == 10 else None)
        assert a.delivery_status == "pending"


async def test_double_draw_keeps_single_set(db, game):
    await register_many(db, game, 5)
    results = await asyncio.gather(*(db.draw(game.id) for _ in range(5)))
    assert [r.status for r in results].count(DrawStatus.DRAWN) == 1
    first = {(a.giver_id, a.receiver_id) for a in await db.undelivered_assignments(game.id)}
    assert len(first) == 5
    assert (await db.draw(game.id)).status is DrawStatus.ALREADY_DRAWN
    second = {(a.giver_id, a.receiver_id) for a in await db.undelivered_assignments(game.id)}
    assert first == second


async def test_no_registration_or_wish_after_draw(db, game):
    await register_many(db, game, 2)
    await db.draw(game.id)
    result = await db.register(game.join_token, 99, 99, "Late")
    assert result.status is RegisterStatus.CLOSED
    assert await db.set_wish(game.id, 10, "Поздно") is WishStatus.CLOSED
    assert len(await db.list_participants(game.id)) == 2


async def test_wish_snapshot_frozen_at_draw(db, game):
    await register_many(db, game, 2)
    await db.set_wish(game.id, 11, "Чай")
    await db.draw(game.id)
    (a,) = [a for a in await db.undelivered_assignments(game.id) if a.receiver_id == 11]
    assert a.receiver_wish == "Чай"


async def test_constraints_enforced(db, game):
    await register_many(db, game, 2)
    conn = sqlite3.connect(db.path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO assignments (game_id, giver_id, receiver_id, receiver_username)"
            " VALUES (?, 10, 10, 'x')",
            (game.id,),
        )
    conn.execute(
        "INSERT INTO assignments (game_id, giver_id, receiver_id, receiver_username)"
        " VALUES (?, 10, 11, 'x')",
        (game.id,),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO assignments (game_id, giver_id, receiver_id, receiver_username)"
            " VALUES (?, 10, 11, 'x')",
            (game.id,),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO participants (game_id, telegram_user_id, private_chat_id, username,"
            " username_normalized, joined_at, updated_at) VALUES (?, 12, 12, 'X', 'user10', '', '')",
            (game.id,),
        )
    conn.close()


async def test_sync_usernames_updates_and_swaps(db, game):
    await db.register(game.join_token, 10, 10, "a")
    await db.register(game.join_token, 11, 11, "b")
    assert await db.sync_usernames(game.id, {10: "b", 11: "a"}) == []
    names = {p.telegram_user_id: p.username for p in await db.list_participants(game.id)}
    assert names == {10: "b", 11: "a"}


async def test_sync_usernames_reports_problems(db, game):
    await db.register(game.join_token, 10, 10, "alina")
    await db.register(game.join_token, 11, 11, "timur")
    await db.register(game.join_token, 12, 12, "malika")
    # 10 сменил имя на "timur" (11 его освободил, но мы не смогли проверить 11), 12 удалил username
    problems = await db.sync_usernames(game.id, {10: "Timur", 12: None})
    reasons = {p.participant.telegram_user_id: p.reason for p in problems}
    assert reasons == {11: "conflict", 12: "no_username"}
    names = [p.username for p in await db.list_participants(game.id)]
    assert names == ["alina", "timur", "malika"]  # ничего не изменилось
