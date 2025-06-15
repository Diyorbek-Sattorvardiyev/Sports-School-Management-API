# import sqlite3

# conn = sqlite3.connect("sports_school.db")
# cursor = conn.cursor()



# # # Jadvalni o‘chirish
# # cursor.execute("DROP TABLE IF EXISTS coaches")
# # cursor.execute("DROP TABLE IF EXISTS coaches")

# # conn.commit()
# # conn.close()

# # # Yangi Coaches jadvalini yaratish
# # cursor.execute('''
# #      CREATE TABLE IF NOT EXISTS coaches (
# #             id INTEGER PRIMARY KEY AUTOINCREMENT,
# #             first_name TEXT NOT NULL,
# #             last_name TEXT NOT NULL,
# #             birth_date TEXT,
# #             phone TEXT,
# #             sport_type_id INTEGER,
# #             login TEXT UNIQUE NOT NULL,
# #             password TEXT NOT NULL,
# #             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
# #             FOREIGN KEY (sport_type_id) REFERENCES sport_types(id)
# #         )
# #         ''')

# cursor.execute("ALTER TABLE coaches ADD COLUMN image_coach TEXT;")

# conn.commit()
# conn.close()

# import sqlite3

# conn = sqlite3.connect('sports_school.db')
# cursor = conn.cursor()

# cursor.execute("SELECT * FROM admins")
# rows = cursor.fetchall()

# for row in rows:
#     print(row)

# conn.close()
import sqlite3
from werkzeug.security import generate_password_hash

# Eski login (masalan, o'zgartirmoqchi bo'lgan murabbiy logini)
old_login = 'Diyorbek12'  # Bu yerni o'zgartiriladigan login bilan almashtiring

# Yangi login va parol
new_login = 'Talaba'  # Yangi login
new_password = 'Talaba123'  # Yangi oddiy parol
hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')  # Hashlangan parol

# Ma'lumotlar bazasi fayli
db_path = 'sports_school.db'  # Agar boshqa joyda bo'lsa, to'liq yo'lni yozing

# Ma'lumotlar bazasiga ulanish
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Murabbiy jadvalidagi login va parolni yangilash
cursor.execute('''
    UPDATE students
    SET login = ?, password = ?
    WHERE login = ?
''', (new_login, hashed_password, old_login))

# O'zgarishlarni saqlash
conn.commit()

# Yangilangan yozuvlar sonini tekshirish
if cursor.rowcount > 0:
    print(f"Murabbiy logini '{old_login}' dan '{new_login}' ga va paroli yangilandi.")
else:
    print(f"Eski login '{old_login}' topilmadi.")

# Ulanishni yopish
conn.close()

