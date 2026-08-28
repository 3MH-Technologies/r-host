# 🐺 White Wolf — Bot Hosting Platform

منصة استضافة بوتات التلجرام | Telegram bot hosting platform with a web panel, file manager, console, and AI assistant.

**القناة/Channel:** [t.me/bshshshkk](https://t.me/bshshshkk) · **التواصل/Contact:** [t.me/j49_c](https://t.me/j49_c)

---

## ✨ Features / المميزات

- **Bot hosting** — تشغيل سكربتات البوتات (Python / PHP) مع إعادة تشغيل تلقائية عند توقف العملية
- **Auto-install** — تثبيت تلقائي لـ `requirements.txt` ولأي مكتبة استيراد ناقصة عند التشغيل
- **Starter system** — تشغيل أي ملف بداية تحدده (افتراضياً `main.py`)
- **Per-bot secrets** — ضع أسرار البوت في ملف `.env` داخل مجلده، تُحمَّل تلقائياً بمعزل تام عن بيئة الهوست
- **Zero-Trust OS isolation** — كل بوت يشتغل كمستخدم Unix مستقل خاص فيه (`bot_<hash>`): بلا صلاحية لأي ملف منصة (`DATA/` 0700، ملفات 0600)، كوبيات للبوت فقط (`server.log`/`meta.json`/upload تُكتب بـ O_NOFOLLOW ضد الروابط الخداعية)، حد ذاكرة/عمليات/ملفات عبر `prlimit`، بيئة معقّمة بلا مفاتيح هوست ولا متغيرات خطيرة (`LD_PRELOAD`/`PYTHONPATH`...)، و`pip` يثبّت داخل مجلد البوت فقط (`--user`)
- **File manager** — مدير ملفات (رفع، تعديل، إنشاء، حذف، إعادة تسمية) مع محرر أكواد مدمج (Ctrl+S للحفظ، TAB للإزاحة)
- **Live console** — لوحة تحكم مباشرة تعرض الـ logs كل ثانيتين
- **AI assistant** — مساعد ذكي مدمج لمساعدة المستخدمين في الأكواد (حد يومي)
- **Admin panel** — لوحة أدمن (إدارة مستخدمين، خطط، حظر، إحصائيات النظام)
- **Plans** — خطط Free / Pro / Enterprise (حدود البوتات، الذاكرة، والمساحة)
- **Keep-alive** — فحص دوري وإعادة تشغيل تلقائية للبوتات المتوقفة
- **Log cleaner** — قص تلقائي للسجلات الكبيرة (2MB)
- **Resource limits** — حد للذاكرة لكل بوت وحد للمساحة لكل حساب (يُرصد دورياً)

---

## 🚀 Quick Start / التشغيل السريع

### المتطلبات
- Python 3.11+
- Docker (اختياري)

### تشغيل محلي

```bash
# متغيرات مطلوبة — بدونها لن يعمل التطبيق (fail closed)
export ADMIN_USER="admin"            # اسم حساب الأدمن
export ADMIN_PASS="ضع-كلمة-مرور-قوية" # كلمة مرور الأدمن

pip install -r requirements.txt
python app.py
```

افتح المتصفح على `http://localhost:7860`.

### Docker

```bash
docker build -t whitewolf .
docker run -p 7860:7860 \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS="ضع-كلمة-مرور-قوية" \
  whitewolf
```

### Hugging Face Space
ضبط **Variables and secrets** في إعدادات الـ Space:
- `ADMIN_USER`
- `ADMIN_PASS`
- (اختياري) `PANEL_SECRET_KEY` — مفتاح توقيع الجلسات

---

## ⚙️ Environment Variables / المتغيرات

| متغير | مطلوب | الافتراضي | الوصف |
|---|---|---|---|
| `ADMIN_USER` | ✅ | — | اسم مستخدم الأدمن (إجباري) |
| `ADMIN_PASS` | ✅ | — | كلمة مرور الأدمن (إجباري) |
| `SERVER_PORT` | ❌ | `7860` | منفذ التشغيل |
| `PANEL_SECRET_KEY` | ❌ | عشوائي | مفتاح توقيع الجلسات (يفضل ضبطه) |
| `SESSION_COOKIE_SECURE` | ❌ | `true` | Secure cookie للجلسات |
| `MAX_PROC_MEM_MB` | ❌ | `512` | الحد الأقصى لذاكرة البوت الواحد |
| `DEVELOPER_URL` | ❌ | — | توجيه صفحة المطور لرابط خارجي |
| `SPACE_ID` | ❌ | — | تعطيل Git auto-sync تلقائياً في Space |

> ⚠️ **أمان:** لا تشغّل التطبيق بدون `ADMIN_USER` و`ADMIN_PASS` — سيرفض الإقلاع عمداً حتى لا يبدأ بكلمة مرور افتراضية معروفة.

---

## 📁 Structure / هيكل المشروع

```
app.py          # Flask backend + API + إدارة العمليات
pinger.py       # Keep-alive منفصل (تُشغَّل كعملية مستقلة)
dns_fix.py      # إصلاح DNS قبل تشغيل سكربتات المستخدمين
Dockerfile      # صورة Docker للإنتاج
index.html      # لوحة التحكم (dashboard)
login.html      # تسجيل الدخول
admin.html      # لوحة الأدمن
landing.html    # الصفحة الرئيسية
DATA/users.json # قاعدة بيانات المستخدمين (تتولّد تلقائياً)
USERS/          # سيرفرات المستخدمين
```

---

## 🛡️ Security Notes / ملاحظات أمنية

- كلمات المرور مشفّرة عبر `werkzeug security` (hash آمن).
- عزل المسارات مضمون (`safe_join_server_path`) — لا يمكن الوصول لملفات خارج مجلد البوت.
- Rate limiting على نقاط الحساسة (تسجيل الدخول، التسجيل، الأوامر).
- جلسات cookies موقّعة بمفتاح سري (و تتم حمايتها عبر Secure/HttpOnly).
- Headers أمنية على كل الردود (CSP, HSTS, X-Frame-Options…).
- بيانات المتغيرات الحساسة تأتي من البيئة فقط — لا توجد بيانات اعتماد مكتوبة في الكود.

---

## 📄 Pages

| المسار | الوصف |
|---|---|
| `/` | الصفحة الرئيسية / لوحة التحكم |
| `/login` | تسجيل الدخول |
| `/admin` | لوحة الأدمن |
| `/docs`, `/features`, `/terms`, `/privacy` | صفحات تعريفية |

---

**© 2026 3MH TECHNOLOGIES** — [3mh.pages.dev](https://3mh.pages.dev/) · جميع الحقوق محفوظة | All rights reserved