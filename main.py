import os, asyncio
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters, CallbackQueryHandler
from utils import build_subdomain_list, check_subdomain, check_site_status

load_dotenv()
TOKEN = os.getenv('TELEGRAM_TOKEN')
if not TOKEN:
    raise SystemExit('Set TELEGRAM_TOKEN in .env or environment. See .env.example')

WORKER_COUNT = int(os.getenv('WORKER_COUNT', '6'))

# /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        'Hi — send a domain like example.com and I will show common subdomains you can check with one click.',
        parse_mode='Markdown'
    )

# /status command
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "⚠️ Please provide a website.\nExample: /status example.com",
            parse_mode="Markdown"
        )
        return

    site = context.args[0]
    result = check_site_status(site)  # synchronous, fine for small checks
    await update.message.reply_text(result)

# Handle plain domain messages
async def handle_domain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if ' ' in text or '/' in text:
        await update.message.reply_text(
            'Please send a plain domain (e.g. example.com), without https:// or paths.',
            parse_mode='Markdown'
        )
        return

    domain = text.lower()
    subs = build_subdomain_list(domain)
    keyboard = []
    row = []

    for idx, s in enumerate(subs, start=1):
        row.append(InlineKeyboardButton(s, callback_data=f'check:{s}'))
        if idx % 2 == 0:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)

    keyboard.append([InlineKeyboardButton('🔁 Check all', callback_data=f'checkall:{domain}')])

    await update.message.reply_text(
        f'Subdomains for {domain} — click any to run a quick check:',
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )

# Handle button callbacks
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data.startswith('check:'):
        sub = data.split(':', 1)[1]
        await query.edit_message_text(f'Checking {sub} ...', parse_mode='Markdown')
        res = await check_subdomain(sub)
        await query.edit_message_text(res, parse_mode='Markdown')

    elif data.startswith('checkall:'):
        domain = data.split(':', 1)[1]
        subs = build_subdomain_list(domain)
        await query.edit_message_text(
            f'Starting bulk checks for {domain} — this may take a few seconds.',
            parse_mode='Markdown'
        )

        sem = asyncio.Semaphore(WORKER_COUNT)

        async def sem_check(s):
            async with sem:
                return await check_subdomain(s, one_line=True)

        tasks = [sem_check(s) for s in subs]
        results = await asyncio.gather(*tasks)
        out = '\n'.join(results)
        await query.edit_message_text(f'Bulk results for {domain}:\n\n' + out, parse_mode='Markdown')

    else:
        await query.edit_message_text('Unknown action.')

# Main entry point
def main():
    app = ApplicationBuilder().token(TOKEN).build()

    app.add_handler(CommandHandler('start', start))
    app.add_handler(CommandHandler('status', status_command))  # New command added
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_domain))
    app.add_handler(CallbackQueryHandler(callback_handler))

    print('Bot running...')
    app.run_polling()

if __name__ == '__main__':
    main()