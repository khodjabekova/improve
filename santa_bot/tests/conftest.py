import pytest

from santa_bot.db import Database


@pytest.fixture
async def db(tmp_path):
    database = Database(tmp_path / "santa.db")
    await database.init()
    return database


@pytest.fixture
async def game(db):
    game, _ = await db.get_or_create_open_game(-100, "Офис", organizer_id=1)
    return game
