import os
from werkzeug.utils import secure_filename
import uuid

def save_file(file, folder, app):  # app parametr sifatida qo‘shildi
    if file and file.filename:
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"  # Fayl nomini noyob qilish
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, unique_filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)  # Papka mavjud bo'lmasa yaratish
        file.save(save_path)
        return f"{folder}/{unique_filename}"
    return None