"""Обработчики апдейтов Telegram."""
from __future__ import annotations

import logging
from html import escape

from aiogram import Bot, F, Router
from aiogram.enums import ChatMemberStatus, ChatType
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import JOIN_TRANSITION, ChatMemberUpdatedFilter, Command, CommandObject, CommandStart
from aiogram.types import (
    CallbackQuery,
    ChatMemberUpdated,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    User,
)

from . import texts
from .config import Config
from .db import Database, DrawStatus, Game, RegisterStatus, WishStatus, normalize_username
from .delivery import DeliveryService

log = logging.getLogger(__name__)

GROUP_TYPES = {ChatType.GROUP, ChatType.SUPERGROUP}
DEEP_LINK_PREFIX = "santa_"
WISH_CALLBACK = "wish:"

router = Router(name="santa")


# ------------------------------------------------------------------ helpers
def join_keyboard(link: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="🎁 Участвовать", url=link)]]
    )


async def game_link(bot: Bot, game: Game) -> str:
    me = await bot.me()
    return texts.join_link(me.username or "", game.join_token)


async def fetch_member(bot: Bot, chat_id: int, user_id: int):
    try:
        return await bot.get_chat_member(chat_id, user_id)
    except TelegramAPIError as exc:
        log.info("getChatMember(%s, %s) failed: %s", chat_id, user_id, exc)
        return None


def is_member(member) -> bool:
    if member is None:
        return False
    if member.status in (ChatMemberStatus.CREATOR, ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.MEMBER):
        return True
    return member.status == ChatMemberStatus.RESTRICTED and bool(getattr(member, "is_member", False))


def full_name(user: User) -> str:
    return user.full_name or user.username or str(user.id)


# ------------------------------------------------- bot added to a group
@router.my_chat_member(F.chat.type.in_(GROUP_TYPES), ChatMemberUpdatedFilter(JOIN_TRANSITION))
async def on_bot_added(event: ChatMemberUpdated, bot: Bot, db: Database) -> None:
    game, created = await db.get_or_create_open_game(
        group_chat_id=event.chat.id,
        group_title=event.chat.title or "",
        organizer_id=event.from_user.id,
    )
    link = await game_link(bot, game)
    me = await bot.me()
    text = texts.game_announcement(me.username or "") if created else texts.game_already_open()
    await bot.send_message(event.chat.id, text, reply_markup=join_keyboard(link))


@router.message(F.migrate_to_chat_id)
async def on_migrate(message: Message, db: Database) -> None:
    await db.migrate_group(message.chat.id, message.migrate_to_chat_id)


# ------------------------------------------------------------- private chat
@router.message(CommandStart(deep_link=True), F.chat.type == ChatType.PRIVATE)
async def on_start_deep_link(
    message: Message,
    command: CommandObject,
    bot: Bot,
    db: Database,
    config: Config,
    delivery: DeliveryService,
) -> None:
    payload = command.args or ""
    if not payload.startswith(DEEP_LINK_PREFIX):
        await on_start_plain(message, db, delivery)
        return
    token = payload.removeprefix(DEEP_LINK_PREFIX)
    user = message.from_user

    game = await db.get_game_by_token(token)
    if game is None:
        await message.answer(texts.GAME_NOT_FOUND)
        return
    if not game.is_open:
        await message.answer(texts.REGISTRATION_CLOSED)
        await redeliver_for(user.id, message.chat.id, db, delivery)
        return

    if config.require_group_membership:
        member = await fetch_member(bot, game.group_chat_id, user.id)
        if not is_member(member):
            await message.answer(texts.NOT_A_MEMBER.format(title=escape(game.group_title)))
            return

    if not user.username:
        await message.answer(
            texts.NEED_USERNAME, reply_markup=join_keyboard(await game_link(bot, game))
        )
        return

    result = await db.register(
        token, user.id, message.chat.id, user.username, full_name(user)
    )
    if result.status is RegisterStatus.USERNAME_TAKEN:
        # Возможно, прежний владелец имени просто сменил username — проверим и обновим.
        stale = result.conflicting
        member = await fetch_member(bot, game.group_chat_id, stale.telegram_user_id)
        current = member.user.username if member is not None else None
        if current and normalize_username(current) != normalize_username(stale.username):
            if not await db.sync_usernames(game.id, {stale.telegram_user_id: current}):
                result = await db.register(
                    token, user.id, message.chat.id, user.username, full_name(user)
                )
    if result.status is RegisterStatus.NOT_FOUND:
        await message.answer(texts.GAME_NOT_FOUND)
    elif result.status is RegisterStatus.CLOSED:
        await message.answer(texts.REGISTRATION_CLOSED)
    elif result.status is RegisterStatus.USERNAME_TAKEN:
        await message.answer(texts.USERNAME_TAKEN.format(username=escape(user.username)))
        stale = result.conflicting
        try:
            await bot.send_message(
                stale.private_chat_id,
                texts.STALE_USERNAME_NOTICE.format(
                    title=escape(game.group_title), username=escape(stale.username)
                ),
                reply_markup=join_keyboard(await game_link(bot, game)),
            )
        except TelegramAPIError as exc:
            log.info("Не удалось предупредить участника %s: %s", stale.telegram_user_id, exc)
    else:
        await message.answer(
            texts.registered(
                game.group_title,
                created=result.status is RegisterStatus.CREATED,
                wish=result.participant.wish,
            )
        )


@router.message(CommandStart(), F.chat.type == ChatType.PRIVATE)
async def on_start_plain(message: Message, db: Database, delivery: DeliveryService) -> None:
    delivered = await redeliver_for(message.from_user.id, message.chat.id, db, delivery)
    if not delivered:
        await message.answer(texts.START_PLAIN)


async def redeliver_for(
    user_id: int, chat_id: int, db: Database, delivery: DeliveryService
) -> bool:
    """Если у пользователя есть недоставленные назначения (например, он блокировал бота),
    отправляем их сейчас. Возвращает True, если что-то было отправлено."""
    game_ids = await db.undelivered_games_for_giver(user_id)
    if not game_ids:
        return False
    await db.update_private_chat(user_id, chat_id)
    for game_id in game_ids:
        await delivery.deliver(game_id, giver_id=user_id)
    return True


@router.message(Command("wish"), F.chat.type == ChatType.PRIVATE)
async def on_wish(message: Message, command: CommandObject, db: Database) -> None:
    wish = (command.args or "").strip()
    if not wish:
        await message.answer(texts.WISH_EXAMPLE)
        return
    if len(wish) > texts.MAX_WISH_LENGTH:
        await message.answer(texts.WISH_TOO_LONG)
        return

    user_id = message.from_user.id
    games = await db.games_for_user(user_id, only_open=True)
    if not games:
        any_games = await db.games_for_user(user_id, only_open=False)
        await message.answer(texts.WISH_ALL_DRAWN if any_games else texts.WISH_NO_GAMES)
        return
    if len(games) == 1:
        status = await db.set_wish(games[0].id, user_id, wish)
        await message.answer(wish_result_text(games[0], status, wish))
        return

    await db.save_pending_wish(user_id, wish)
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=g.group_title or f"Игра #{g.id}", callback_data=f"{WISH_CALLBACK}{g.id}")]
            for g in games
        ]
    )
    await message.answer(texts.WISH_CHOOSE_GAME, reply_markup=keyboard)


@router.callback_query(F.data.startswith(WISH_CALLBACK))
async def on_wish_choice(callback: CallbackQuery, db: Database) -> None:
    try:
        game_id = int(callback.data.removeprefix(WISH_CALLBACK))
    except ValueError:
        await callback.answer()
        return
    game = await db.get_game(game_id)
    wish = await db.pop_pending_wish(callback.from_user.id)
    await callback.answer()
    if game is None or wish is None:
        await callback.message.edit_text(texts.WISH_EXPIRED)
        return
    status = await db.set_wish(game.id, callback.from_user.id, wish)
    await callback.message.edit_text(wish_result_text(game, status, wish))


def wish_result_text(game: Game, status: WishStatus, wish: str) -> str:
    if status is WishStatus.SAVED:
        return texts.wish_saved(game.group_title, wish)
    if status is WishStatus.CLOSED:
        return texts.WISH_CLOSED.format(title=escape(game.group_title))
    return texts.WISH_NOT_PARTICIPANT


@router.message(Command("wish"))
async def on_wish_in_group(message: Message) -> None:
    await message.reply(texts.PRIVATE_ONLY)


# -------------------------------------------------------------------- group
@router.message(Command("stat"), F.chat.type.in_(GROUP_TYPES))
async def on_stat(message: Message, bot: Bot, db: Database) -> None:
    game = await db.get_current_game(message.chat.id)
    if game is None:
        await message.answer(texts.NO_GAME)
        return
    participants = await db.list_participants(game.id)
    if game.is_open:
        await message.answer(
            texts.stat_open(participants), reply_markup=join_keyboard(await game_link(bot, game))
        )
    else:
        await message.answer(texts.stat_drawn(participants, await db.delivery_stats(game.id)))


@router.message(Command("end"), F.chat.type.in_(GROUP_TYPES))
async def on_end(message: Message, bot: Bot, db: Database, delivery: DeliveryService) -> None:
    game = await db.get_current_game(message.chat.id)
    if game is None:
        await message.answer(texts.NO_GAME)
        return
    if message.from_user is None or message.from_user.id != game.organizer_id:
        await message.reply(texts.ONLY_ORGANIZER)
        return
    if not game.is_open:
        await message.answer(texts.already_drawn(await db.delivery_stats(game.id)))
        return

    participants = await db.list_participants(game.id)
    if len(participants) < 2:
        await message.answer(texts.not_enough(len(participants)))
        return

    # Перед жеребьёвкой сверяем @username с Telegram: в назначениях должны быть актуальные имена.
    fetched: dict[int, str | None] = {}
    for p in participants:
        member = await fetch_member(bot, game.group_chat_id, p.telegram_user_id)
        if member is not None:
            fetched[p.telegram_user_id] = member.user.username
    problems = await db.sync_usernames(game.id, fetched)
    if problems:
        await message.answer(texts.username_problems(problems))
        return

    result = await db.draw(game.id)
    if result.status is DrawStatus.NOT_ENOUGH:
        await message.answer(texts.not_enough(result.participants))
        return
    if result.status is not DrawStatus.DRAWN:
        await message.answer(texts.already_drawn(await db.delivery_stats(game.id)))
        return

    stats = await delivery.deliver(game.id)
    await message.answer(texts.draw_finished(stats))


@router.message(Command("retry"), F.chat.type.in_(GROUP_TYPES))
async def on_retry(message: Message, db: Database, delivery: DeliveryService) -> None:
    game = await db.get_current_game(message.chat.id)
    if game is None:
        await message.answer(texts.NO_GAME)
        return
    if message.from_user is None or message.from_user.id != game.organizer_id:
        await message.reply(texts.ONLY_ORGANIZER)
        return
    if game.is_open:
        await message.answer(texts.NOT_DRAWN_YET)
        return
    stats = await delivery.deliver(game.id)
    await message.answer(texts.retry_finished(stats))


@router.message(Command("stat", "end", "retry"))
async def on_group_command_in_private(message: Message) -> None:
    await message.answer(texts.GROUP_ONLY)


# --------------------------------------------------------------- everywhere
@router.message(Command("info"))
async def on_info(message: Message) -> None:
    await message.answer(texts.INFO)


@router.message(Command("help"))
async def on_help(message: Message) -> None:
    await message.answer(texts.HELP)
