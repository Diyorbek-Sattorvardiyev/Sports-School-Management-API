# Sports School Management API

Ushbu loyiha Flask va SQLite asosida ishlab chiqilgan sport maktabini boshqarish tizimining RESTful API backend qismidir. Tizim orqali administrator, murabbiy va o‘quvchi rollari uchun autentifikatsiya, guruhlar, davomat, yangiliklar, mashg‘ulotlar jadvali, sport turlari, musobaqa natijalari va xabarlar kabi funksiyalarni boshqarish mumkin.

---

##  Avtorizatsiya

Har bir foydalanuvchi tizimga `login` endpoint orqali kiradi va JWT token oladi. Barcha so‘rovlar quyidagi sarlavha bilan yuborilishi lozim:

-Authorization: Bearer <token>

---

##  API Bo‘limlari

###  Foydalanuvchilar
- `POST /login` — Tizimga kirish
- `GET /all-users` — Barcha foydalanuvchilar ro‘yxati

### O‘quvchilar (Students)
- `GET /students` — O‘quvchilar ro‘yxati (admin/coach)
- `POST /students` — Yangi o‘quvchi qo‘shish (admin)
- `PUT /students/<id>` — O‘quvchini yangilash (admin)
- `DELETE /students/<id>` — O‘quvchini o‘chirish (admin)
- `GET /students/view` — O‘quvchilarni ko‘rish (admin/coach)

###  Murabbiylar (Coaches)
- `POST /coaches` — Murabbiy qo‘shish (admin)
- `GET /coaches` — Murabbiylar ro‘yxati
- `GET /coaches/view` — O‘quvchilar uchun murabbiylar
- `GET /coaches/<id>` — Murabbiy profili
- `PUT /coaches/<id>` — Murabbiyni yangilash
- `DELETE /coaches/<id>` — Murabbiyni o‘chirish (admin)

###  Guruhlar (Groups)
- `POST /groups` — Guruh yaratish (coach)
- `GET /groups` — Murabbiyning guruhlari
- `GET /groups/<id>/students` — Guruhdagi o‘quvchilar
- `POST /groups/<id>/attendance` — Davomat qo‘shish
- `GET /groups/<id>/attendance-report` — Davomat hisobotlari

###  Yangiliklar (News)
- `GET /news` — Barcha yangiliklar
- `POST /news` — Yangi yangilik qo‘shish (admin)
- `PUT /news/<id>` — Yangilikni yangilash (admin)
- `DELETE /news/<id>` — Yangilikni o‘chirish (admin)

###  Natijalar (Results)
- `GET /results` — Barcha musobaqa natijalari
- `POST /results` — Natija qo‘shish (admin)
- `PUT /results/<id>` — Natijani yangilash (admin)
- `DELETE /results/<id>` — Natijani o‘chirish (admin)

###  Mashg‘ulot jadvali (Training Schedule)
- `GET /training-schedule` — Jadvalni ko‘rish
- `POST /training-schedule` — Jadval yaratish (admin)
- `PUT /training-schedule/<id>` — Jadvalni yangilash (admin)
- `DELETE /training-schedule/<id>` — Jadvalni o‘chirish (admin)

###  Sport turlari (Sport Types)
- `GET /sport-types` — Sport turlari ro‘yxati
- `POST /sport-types` — Sport turi qo‘shish (admin)
- `PUT /sport-types/<id>` — Sport turini yangilash (admin)
- `DELETE /sport-types/<id>` — Sport turini o‘chirish (admin)

###  Xabarlar (Messages)
- `POST /messages` — Yangi xabar yuborish
- `GET /messages` — Xabarlarni olish
- `PUT /messages/<id>/read` — Xabarni o‘qilgan deb belgilash
- `DELETE /messages/<id>` — Xabarni o‘chirish (admin)

###  Profil
- `GET /profile` — Foydalanuvchi profili
- `PUT /profile/update-password` — Parolni yangilash

---

##  Ishga tushirish

### 1. Talablar
- Python 3.7+
- Flask
- Flask-CORS
- PyJWT
- Werkzeug



