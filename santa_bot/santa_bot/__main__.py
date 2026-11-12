"""Точка входа: python -m santa_bot"""
from __future__ import annotations

import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import BotCommand, BotCommandScopeAllGroupChats, BotCommandScopeAllPrivateChats

from .config import load_config
from .db import Database
from .delivery import DeliveryService
from .handlers import router


async def set_commands(bot: Bot) -> None:
    await bot.set_my_commands(
        [
            BotCommand(command="wish", description="Сохранить пожелание"),
            BotCommand(command="info", description="Как играть"),
            BotCommand(command="help", description="Список команд"),
        ],
        scope=BotCommandScopeAllPrivateChats(),
    )
    await bot.set_my_commands(
        [
            BotCommand(command="stat", description="Участники игры"),
            BotCommand(command="end", description="Провести жеребьёвку (организатор)"),
            BotCommand(command="retry", description="Повторить рассылку (организатор)"),
            BotCommand(command="info", description="Как играть"),
            BotCommand(command="help", description="Список команд"),
        ],
        scope=BotCommandScopeAllGroupChats(),
    )


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    config = load_config()
    db = Database(config.database_path)
    await db.init()

    bot = Bot(config.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))

    async def send(chat_id: int, text: str) -> None:
        await bot.send_message(chat_id, text)

    delivery = DeliveryService(db, send)
    dp = Dispatcher()
    dp.include_router(router)

    await set_commands(bot)
    try:
        await dp.start_polling(
            bot,
            db=db,
            delivery=delivery,
            config=config,
            allowed_updates=dp.resolve_used_update_types(),
        )
    finally:
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())
