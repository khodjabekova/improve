"""Тексты сообщений (HTML)."""
from __future__ import annotations

from html import escape

from .db import Assignment, DeliveryStats, Participant, UsernameProblem

MAX_WISH_LENGTH = 1000


def join_link(bot_username: str, token: str) -> str:
    return f"https://t.me/{bot_username}?start=santa_{token}"


def game_announcement(bot_username: str) -> str:
    return (
        "🎄 <b>Тайный Санта открыт!</b>\n\n"
        "Как участвовать:\n"
        "1. Нажмите кнопку <b>«Участвовать»</b> и затем <b>Start</b> в личке с ботом.\n"
        "2. Для участия нужен @username (Настройки → Имя пользователя).\n"
        "3. По желанию отправьте боту в личку <code>/wish Хочу книгу или чай</code>.\n\n"
        "Когда все соберутся, организатор отправит /end — и каждый получит в личку, "
        "кому дарит подарок.\n"
        "Список участников: /stat"
    )


def game_already_open() -> str:
    return "🎄 Игра в этой группе уже идёт — регистрация по кнопке ниже."


INFO = (
    "🎅 <b>Как играть в Тайного Санту</b>\n\n"
    "1. Нажмите <b>«Участвовать»</b> под сообщением бота в группе и затем <b>Start</b>.\n"
    "2. У вас должен быть @username — по нему Санта поймёт, кому дарить.\n"
    "3. Отправьте боту в личку <code>/wish ваше пожелание</code>. Пожелание одно: новое "
    "заменяет старое. Его увидит только ваш Санта. Пожелание необязательно.\n"
    "4. После жеребьёвки бот пришлёт в личку, кому вы дарите подарок, и его пожелание.\n\n"
    "Не блокируйте бота до жеребьёвки — иначе он не сможет прислать результат."
)

HELP = (
    "<b>Команды</b>\n\n"
    "<b>В группе:</b>\n"
    "/stat — участники и статус игры\n"
    "/end — провести жеребьёвку (только организатор)\n"
    "/retry — повторить рассылку тем, кому не доставлено (только организатор)\n\n"
    "<b>В личке с ботом:</b>\n"
    "/start — регистрация открывается по кнопке «Участвовать» из группы\n"
    "/wish <i>текст</i> — сохранить или заменить пожелание\n\n"
    "<b>Везде:</b>\n"
    "/info — инструкция для участников\n"
    "/help — этот список"
)

START_PLAIN = (
    "👋 Привет! Я провожу игру «Тайный Санта».\n\n"
    "Добавьте меня в группу — я открою регистрацию. Чтобы участвовать в уже "
    "открытой игре, нажмите кнопку <b>«Участвовать»</b> под моим сообщением в группе.\n\n"
    "/info — как играть, /help — команды"
)

GAME_NOT_FOUND = "Эта ссылка недействительна. Возьмите свежую ссылку в группе (/stat)."
REGISTRATION_CLOSED = "Жеребьёвка в этой игре уже прошла — регистрация закрыта."
NOT_A_MEMBER = (
    "Участвовать могут только участники группы «{title}». "
    "Вступите в группу и снова откройте ссылку."
)
NEED_USERNAME = (
    "Для участия нужен @username — по нему Санта найдёт получателя подарка.\n\n"
    "Установите его в Telegram: <b>Настройки → Имя пользователя</b>, "
    "а затем снова откройте ссылку кнопкой ниже."
)
USERNAME_TAKEN = (
    "В игре уже числится участник с именем @{username} — похоже, у него устаревшие данные. "
    "Мы попросили его заново открыть ссылку. Попробуйте ещё раз чуть позже."
)
STALE_USERNAME_NOTICE = (
    "⚠️ В игре «{title}» вы записаны как @{username}, но это имя теперь занято другим "
    "участником. Пожалуйста, откройте ссылку ещё раз, чтобы обновить данные."
)

WISH_EXAMPLE = (
    "Напишите пожелание после команды, например:\n"
    "<code>/wish Хочу книгу или чай</code>"
)
WISH_TOO_LONG = f"Пожелание слишком длинное — не больше {MAX_WISH_LENGTH} символов."
WISH_NO_GAMES = (
    "Вы пока не участвуете ни в одной открытой игре. "
    "Нажмите «Участвовать» под сообщением бота в группе."
)
WISH_ALL_DRAWN = "Жеребьёвка уже прошла — пожелание изменить нельзя."
WISH_CHOOSE_GAME = "Вы участвуете в нескольких играх. Для какой группы сохранить пожелание?"
WISH_EXPIRED = "Не нашёл пожелание — отправьте /wish с текстом ещё раз."
WISH_CLOSED = "В группе «{title}» жеребьёвка уже прошла — пожелание не изменено."
WISH_NOT_PARTICIPANT = "Вы не зарегистрированы в этой игре."

GROUP_ONLY = "Эта команда работает в группе."
PRIVATE_ONLY = "Эта команда работает в личке с ботом — так ваше пожелание останется тайной."
NO_GAME = "В этой группе нет игры. Удалите бота и добавьте снова, чтобы открыть регистрацию."
ONLY_ORGANIZER = "Эту команду может выполнить только организатор игры."
NOT_DRAWN_YET = "Жеребьёвки ещё не было. Организатор запускает её командой /end."
CHECKING = "Проверяю участников…"


def wish_saved(title: str, wish: str) -> str:
    return (
        f"✅ Пожелание для группы «{escape(title)}» сохранено:\n«{escape(wish)}»\n\n"
        "Его увидит только ваш Тайный Санта. Новый /wish заменит это пожелание."
    )


def registered(title: str, created: bool, wish: str | None) -> str:
    head = (
        f"✅ Вы участвуете в Тайном Санте группы «{escape(title)}»!"
        if created
        else f"✅ Данные обновлены, вы по-прежнему в игре группы «{escape(title)}»."
    )
    if wish:
        tail = f"Ваше пожелание: «{escape(wish)}». Чтобы заменить, отправьте /wish <i>текст</i>."
    else:
        tail = "Отправьте пожелание: <code>/wish Хочу книгу или чай</code> (необязательно)."
    return f"{head}\n\n{tail}\n\nКогда организатор проведёт жеребьёвку, я пришлю сюда результат."


def mention(user_id: int, name: str) -> str:
    return f'<a href="tg://user?id={user_id}">{escape(name or str(user_id))}</a>'


def participants_list(participants: list[Participant]) -> str:
    return "\n".join(f"{i}. @{p.username}" for i, p in enumerate(participants, 1))


def stat_open(participants: list[Participant]) -> str:
    if not participants:
        return "🎄 Регистрация открыта. Пока никто не зарегистрировался."
    return (
        f"🎄 Регистрация открыта. Участников: <b>{len(participants)}</b>\n\n"
        f"{participants_list(participants)}"
    )


def stat_drawn(participants: list[Participant], stats: DeliveryStats) -> str:
    return (
        f"🎁 Жеребьёвка проведена. Участников: <b>{len(participants)}</b>\n\n"
        f"{participants_list(participants)}\n\n{delivery_line(stats)}"
    )


def delivery_line(stats: DeliveryStats) -> str:
    text = f"Доставлено {stats.sent} из {stats.total} сообщений."
    if stats.failed_usernames:
        names = ", ".join(f"@{u}" for u in stats.failed_usernames)
        text += (
            f"\n\nНе получили результат: {names}.\n"
            "Откройте личку с ботом и нажмите Start (или разблокируйте бота) — "
            "назначение придёт автоматически. Организатор также может отправить /retry."
        )
    return text


def draw_finished(stats: DeliveryStats) -> str:
    return f"🎅 Жеребьёвка завершена. {delivery_line(stats)}"


def already_drawn(stats: DeliveryStats) -> str:
    return f"Жеребьёвка уже проведена. {delivery_line(stats)}"


def retry_finished(stats: DeliveryStats) -> str:
    return f"🔁 Повторная рассылка завершена. {delivery_line(stats)}"


def not_enough(count: int) -> str:
    return (
        f"Для жеребьёвки нужно минимум 2 участника, сейчас: {count}. "
        "Регистрация остаётся открытой."
    )


def username_problems(problems: list[UsernameProblem]) -> str:
    lines = []
    for problem in problems:
        p = problem.participant
        who = mention(p.telegram_user_id, p.full_name or p.username)
        if problem.reason == "no_username":
            lines.append(f"• {who} (был @{p.username}) — удалил @username")
        else:
            lines.append(f"• {who} — записан как @{p.username}, но это имя уже у другого участника")
    return (
        "⚠️ Жеребьёвка отложена: у некоторых участников устаревшие данные.\n\n"
        + "\n".join(lines)
        + "\n\nПусть они установят @username и снова откроют ссылку «Участвовать», "
        "затем организатор повторит /end. Регистрация остаётся открытой."
    )


def assignment_message(a: Assignment) -> str:
    lines = [f"🎅 Ты — Тайный Санта для @{a.receiver_username}"]
    if a.receiver_wish:
        lines.append(f"🎁 Пожелание: «{escape(a.receiver_wish)}».")
    else:
        lines.append("🎁 Пожелание не указано — придётся проявить фантазию.")
    if a.group_title:
        lines.append(f"\nИгра в группе «{escape(a.group_title)}». Никому не рассказывай! 🤫")
    return "\n".join(lines)
