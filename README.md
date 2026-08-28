---
title: hostbot
emoji: 🐳
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# 🐺 White Wolf — Bot Hosting Platform

منصة استضافة بوتات التلجرام | Telegram bot hosting platform with a web panel, file manager, console, and AI assistant.

**القناة/Channel:** [t.me/bshshshkk](https://t.me/bshshshkk) · **التواصل/Contact:** [t.me/j49_c](https://t.me/j49_c)

---

## ✨ Features / المميزات

- **Bot hosting** — تشغيل سكربتات البوتات (Python / PHP) مع إعادة تشغيل تلقائية عند الموت
- **Auto-install** — تثبيت تلقائي لـ `requirements.txt` ومكتبات الاستيراد الناقصة
- **Starter system** — تشغيل `main.py` أو أي ملف بداية تحددّه
- **File manager** — مدير ملفات كامل (رفع، تنزيل، تعديل، إنشاء، حذف، إعادة تسمية)
- **Live console** — لوحة تحكم مباشرة تعرض الـ logs كل ثانيتين
- **AI assistant** — مساعد ذكي مدمج للمساعدة في الأكواد (حد يومي للمستخدمين)
- **Admin panel** — لوحة تحكم كاملة (مستخدمين، خطط، حظر، إحصائيات)
- **Plans** — خطط: Free / Pro / Enterprise (حد البوتات والذاكرة والمساحة)
- **Keep-alive** — فحص تلقائي للعملية وإعادة تشغيلها إذا توقفت
- **Log cleaner** — قص تلقائي للسجلات الكبيرة (2MB)

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
dns_fix.py      # إصلاح DNS قبل تشغيل السكربتات
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

- كلمات المرور مشفّرة بـ `werkzeug` (bcrypt).
- عزل المسارات مضمون (`safe_join_server_path`) — لا يمكن الوصول لملفات خارج مجلد البوت.
- Rate limiting على نقاط الحساسة (تسجيل الدخول، التسجيل، الأفعال).
- جلسات cookies مشفّرة بتوقيع المفتاح السري.
- Headers أمنية على كل الردود (CSP, HSTS, X-Frame-Options…).

---

## 📄 Pages

| المسار | الوصف |
|---|---|
| `/` | الصفحة الرئيسية / لوحة التحكم |
| `/login` | تسجيل الدخول |
| `/admin` | لوحة الأدمن |
| `/docs`, `/features`, `/terms`, `/privacy` | صفحات تعريفية |