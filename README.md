# 🐺 White Wolf — Bot Hosting Platform

منصة استضافة بوتات التلجرام | Telegram bot hosting platform with a web panel, file manager, console, and AI assistant.

**التواصل/Contact:** [t.me/j49_c](https://t.me/j49_c)

---

## ⚖️ Copyright

> (c) **3MH TECHNOLOGIES** — [3mh.pages.dev](https://3mh.pages.dev/) · Developed by **White Wolf** — [t.me/j49_c](https://t.me/j49_c)
>
> جميع الحقوق محفوظة | All rights reserved

---

## ✨ Features / المميزات

- **Bot hosting** — تشغيل سكربتات البوتات (Python / PHP) مع إعادة تشغيل تلقائية عند توقف العملية
- **Auto-install** — تثبيت تلقائي لـ `requirements.txt` ولأي مكتبة استيراد ناقصة عند التشغيل
- **Starter system** — تشغيل أي ملف بداية تحدده (افتراضياً `main.py`)
- **Per-bot secrets** — ضع أسرار البوت في ملف `.env` داخل مجلده، تُحمَّل تلقائياً بمعزل تام عن بيئة الهوست
- **Zero-Trust OS isolation** — كل بوت يشتغل كمستخدم Unix مستقل خاص فيه (`bot_<hash>`) من نطاق UID خاص (30000–59999): بلا صلاحية لأي ملف منصة (`DATA/` 0700، ملفات 0600)، كوبيات للبوت فقط (`server.log`/`meta.json`/upload تُكتب بـ O_NOFOLLOW ضد الروابط الخداعية)، حد ذاكرة/عمليات/ملفات عبر `prlimit`، بيئة معقّمة بلا مفاتيح هوست ولا متغيرات خطيرة (`LD_PRELOAD`/`PYTHONPATH`...)، و`pip` يثبّت داخل مجلد البوت فقط (`--user`)
- **Network isolation (iptables)** — عند الإقلاع تُبنى سلسلة `BOTISOL`: البوتات **ممنوعة من loopback كلياً** (لا يستطيعون الوصول لمنافذ الـ Panel عبر `127.0.0.1` أو IP الحاوية أو المسح المحلي)، إلا DNS الـ container (`127.0.0.11:53`) وما يسمح به `LOOPBACK_ALLOW`، مع بقاء الإنترنت الخارجي مفتوحاً
- **Telegram auto-routing** — تحويل آلي كامل لحركة بوتات `api.telegram.org` إلى **Reverse Proxy 3MH** (`https://tg-proxy.contact-3mh.workers.dev`) عبر relay محلي: حقن `HTTP(S)_PROXY` + `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` + shim لـ certifi، مع فرض iptables (nat REDIRECT) على عناوين تلغرام حتى للعملاء الذين يتجاهلون متغيرات البروكسي (aiogram/PHP). بقية حركة الإنترنت **تمر عبوراً شفافاً بلا MITM**
- **TMP isolation** — `TMPDIR`/`TEMP`/`TMP` تُوجَّه لمجلد `.tmp` خاص داخل مجلد البوت (0700 مملوك له) بدل `/tmp` العام
- **Process masking** — remount لـ `/proc` بـ `hidepid=2` لمنع البوتات من رؤية PIDs/عمليات الـ Panel والبوتات الأخرى (يتطلب `CAP_SYS_ADMIN`)
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
  --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
  whitewolf
```

> ⚠️ **صلاحيات التشغيل (crucial):** عزل الشبكة (`iptables`) يحتاج `NET_ADMIN`، وإخفاء العمليات (`hidepid=2` على `/proc`) يحتاج `SYS_ADMIN`. بدونها لا يتعطل النظام — بل **يحذّر في اللوق ويستمر** (تبقى الحماية بطبقة UID، لكن loopback من البوتات والـ /proc غير مُقيَّدَين). أضف الحرفين أعلاه لتفعيل الطبقتين. (مع `docker-compose` استخدم `cap_add: [NET_ADMIN, SYS_ADMIN]`.)

> ✅ **التوجيه التلقائي لتلغرام:** كل بوت يسؤال `api.telegram.org` يتوجه تلقائياً إلى Reverse Proxy 3MH — البوتات الممكنة تحترم `HTTP(S)_PROXY`/CA تُمرَّر عبر relay، وأي عميل يتجاهل المتغيرات يلتقطه فرض `nat REDIRECT` على عناوين تلغرام. لا حاجة لتغيير أي كود بوت، ولا يُحجب سوى النطاقات الموجّهة للبروكسي؛ بقية حركة الإنترنت عبور شفاف. (الـ 403 المصادفة أعلاه عائدة لطبقة Cloudflare edge وليست منطق الـ relay.)

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
| `BOT_UID_MIN` / `BOT_UID_MAX` | ❌ | `30000` / `59999` | نطاق UIDs المخصص للبوتات (يُطابَق بقاعدة iptables) |
| `LOOPBACK_ALLOW` | ❌ | — | استثناءات loopback مسموحة للبوتات، مثال: `127.0.0.2:8080/tcp,127.0.0.1:53/udp` |
| `BOT_ISOLATION` | ❌ | `1` | تعطيل عزل المستخدمين (`0`) — غير موصى به نهائياً |
| `TG_PROXY_ENABLED` | ❌ | `1` | تعطيل relay تلقائية تلغرام (`0`) |
| `TG_PROXY_URL` | ❌ | `https://tg-proxy.contact-3mh.workers.dev` | عنوان Reverse Proxy 3MH |
| `TG_PROXY_HOSTS` | ❌ | `api.telegram.org,core.telegram.org` | الـ hosts التي تُوجَّه للبروكسي |
| `TG_DIRECT_BLOCK_CIDRS` | ❌ | قائمة عناوين تلغرام | CIDRs التلقين المحظور الوصول المباشر إليها |
| `TG_LOCAL_PROXY_PORT` / `TG_TRANSPARENT_PORT` | ❌ | `7788` / `7443` | منافذ الـ relay (CONNECT / transparent) |
| `DEVELOPER_URL` | ❌ | — | توجيه صفحة المطور لرابط خارجي |
| `SPACE_ID` | ❌ | — | تعطيل Git auto-sync تلقائياً في Space |

> ⚠️ **أمان:** لا تشغّل التطبيق بدون `ADMIN_USER` و`ADMIN_PASS` — سيرفض الإقلاع عمداً حتى لا يبدأ بكلمة مرور افتراضية معروفة.

---

## 📁 Structure / هيكل المشروع

```
app.py          # Flask backend + API + إدارة العمليات
tg_proxy.py     # Telegram relay (CONNECT + transparent) نحو Reverse Proxy 3MH
tgcert/         # مولّد تلقائياً: CA + bundle الثقة للبوتات (لا يُرفع على git)
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