from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
from werkzeug.utils import secure_filename
import json
from datetime import datetime
import hashlib
import secrets
import re
import logging
from functools import wraps
# from flask_wtf.csrf import CSRFProtect
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address

app = Flask(__name__)
# Güvenli secret key oluştur
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Rate Limiter yapılandırması (geçici olarak devre dışı)
# limiter = Limiter(
#     key_func=get_remote_address,
#     default_limits=["200 per day", "50 per hour"]
# )
# limiter.init_app(app)

# CSRF koruması (geçici olarak devre dışı)
# csrf = CSRFProtect(app)

# Logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security')

# Session güvenlik ayarları
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 saat
app.config['SESSION_COOKIE_SECURE'] = False  # Development için False
app.config['SESSION_COOKIE_HTTPONLY'] = True  # XSS koruması
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF koruması

# Güvenlik headers
@app.after_request
def set_security_headers(response):
    # XSS koruması
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy - Development için esnek
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:"
    
    # HSTS (HTTP Strict Transport Security) - Production'da aktif
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

# Dosya yükleme ayarları
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Veri dosyaları
DATA_FOLDER = 'data'
USERS_FILE = os.path.join(DATA_FOLDER, 'users.json')
ANNOUNCEMENTS_FILE = os.path.join(DATA_FOLDER, 'announcements.json')
EVENTS_FILE = os.path.join(DATA_FOLDER, 'events.json')

# Veri klasörünü oluştur
os.makedirs(DATA_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Güvenlik fonksiyonları
def hash_password(password):
    """Şifreyi güvenli şekilde hashle"""
    salt = secrets.token_hex(32)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}:{password_hash.hex()}"

def verify_password(password, stored_password):
    """Şifreyi doğrula"""
    try:
        salt, password_hash = stored_password.split(':')
        password_hash_bytes = bytes.fromhex(password_hash)
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return secrets.compare_digest(password_hash_bytes, new_hash)
    except:
        return False

def validate_password_strength(password):
    """Şifre gücünü kontrol et"""
    if len(password) < 8:
        return False, "Şifre en az 8 karakter olmalıdır"
    if not re.search(r'[A-Za-z]', password):
        return False, "Şifre en az bir harf içermelidir"
    if not re.search(r'\d', password):
        return False, "Şifre en az bir rakam içermelidir"
    return True, "Şifre güçlü"

def sanitize_input(text):
    """XSS koruması için input temizle"""
    if not text:
        return ""
    # HTML etiketlerini temizle
    text = re.sub(r'<[^>]+>', '', text)
    # Özel karakterleri escape et
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return text.strip()

def validate_file_upload(file):
    """Dosya yükleme güvenliğini kontrol et"""
    if not file or not file.filename:
        return False, "Dosya seçilmedi"
    
    # Dosya boyutu kontrolü (5MB max)
    file.seek(0, 2)  # Dosyanın sonuna git
    file_size = file.tell()
    file.seek(0)  # Başa dön
    if file_size > 5 * 1024 * 1024:  # 5MB
        return False, "Dosya boyutu 5MB'dan büyük olamaz"
    
    # Dosya uzantısı kontrolü
    if not allowed_file(file.filename):
        return False, "Geçersiz dosya türü"
    
    return True, "Dosya güvenli"

def load_data(filename):
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_data(filename, data):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# Ana sayfa
@app.route('/')
def index():
    announcements = load_data(ANNOUNCEMENTS_FILE)
    events = load_data(EVENTS_FILE)
    posts = load_data('data/posts.json')
    posts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return render_template('index.html', announcements=announcements, events=events, posts=posts)

# Bölümler
@app.route('/departments/ai')
def ai_department():
    return render_template('departments/ai.html')

@app.route('/departments/games')
def games_department():
    return render_template('departments/games.html')

@app.route('/departments/security')
def security_department():
    return render_template('departments/security.html')

@app.route('/departments/web')
def web_department():
    return render_template('departments/web.html')

# Duyurular
@app.route('/announcements')
def announcements():
    announcements = load_data(ANNOUNCEMENTS_FILE)
    return render_template('announcements.html', announcements=announcements)

# Etkinlikler
@app.route('/events')
def events():
    events = load_data(EVENTS_FILE)
    return render_template('events.html', events=events)

@app.route('/events_page')
def events_page():
    return redirect(url_for('events'))

# İletişim
@app.route('/contact')
def contact():
    return render_template('contact.html')

# Kullanıcı işlemleri
@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")  # Geçici olarak devre dışı
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        if not username or not password:
            security_logger.warning(f"Boş giriş denemesi - IP: {request.remote_addr}")
            flash('Kullanıcı adı ve şifre gereklidir!', 'error')
            return render_template('login.html')
        
        users = load_data(USERS_FILE)
        user = next((u for u in users if u['username'] == username), None)
        
        if user and verify_password(password, user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user.get('role', 'user')
            session.permanent = True
            
            # Login sayısını artır
            user['login_count'] = user.get('login_count', 0) + 1
            user['last_login'] = datetime.now().isoformat()
            save_data(USERS_FILE, users)
            
            security_logger.info(f"Başarılı giriş - Kullanıcı: {username}, IP: {request.remote_addr}")
            flash('Giriş başarılı!', 'success')
            return redirect(url_for('index'))
        else:
            security_logger.warning(f"Başarısız giriş denemesi - Kullanıcı: {username}, IP: {request.remote_addr}")
            flash('Kullanıcı adı veya şifre hatalı!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
# @limiter.limit("3 per minute")  # Geçici olarak devre dışı
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        
        # Input validasyonu
        if not username or not email or not password:
            flash('Tüm alanlar gereklidir!', 'error')
            return render_template('register.html')
        
        # Kullanıcı adı validasyonu
        if len(username) < 3:
            flash('Kullanıcı adı en az 3 karakter olmalıdır!', 'error')
            return render_template('register.html')
        
        # Email validasyonu
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Geçerli bir email adresi girin!', 'error')
            return render_template('register.html')
        
        # Şifre gücü kontrolü
        is_strong, password_msg = validate_password_strength(password)
        if not is_strong:
            flash(password_msg, 'error')
            return render_template('register.html')
        
        users = load_data(USERS_FILE)
        
        # Kullanıcı adı kontrolü
        if any(u['username'] == username for u in users):
            flash('Bu kullanıcı adı zaten kullanılıyor!', 'error')
            return render_template('register.html')
        
        # Email kontrolü
        if any(u['email'] == email for u in users):
            flash('Bu email adresi zaten kullanılıyor!', 'error')
            return render_template('register.html')
        
        # Güvenli şifre hashleme
        hashed_password = hash_password(password)
        
        new_user = {
            'id': len(users) + 1,
            'username': username,
            'email': email,
            'password': hashed_password,
            'role': 'user',
            'created_at': datetime.now().isoformat(),
            'login_count': 0,
            'last_login': None
        }
        
        users.append(new_user)
        save_data(USERS_FILE, users)
        
        flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash('Başarıyla çıkış yaptınız!', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Giriş yapmanız gerekiyor!', 'error')
        return redirect(url_for('login'))
    
    users = load_data(USERS_FILE)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    
    if not user:
        flash('Kullanıcı bulunamadı!', 'error')
        return redirect(url_for('login'))
    
    return render_template('profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Giriş yapmanız gerekiyor!', 'error')
        return redirect(url_for('login'))
    
    users = load_data(USERS_FILE)
    user = next((u for u in users if u['id'] == session['user_id']), None)
    
    if not user:
        flash('Kullanıcı bulunamadı!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Email değiştirilemez, sadece bio güncellenebilir
        if 'bio' in request.form:
            user['bio'] = request.form['bio']
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"profile_{user['id']}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user['avatar'] = f"uploads/{filename}"
        
        save_data(USERS_FILE, users)
        flash('Profil güncellendi!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=user)

# Admin paneli
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    users = load_data(USERS_FILE)
    announcements = load_data(ANNOUNCEMENTS_FILE)
    events = load_data(EVENTS_FILE)
    
    stats = {
        'total_users': len(users),
        'total_announcements': len(announcements),
        'total_events': len(events),
        'total_posts': 0,
        'total_contacts': 0,
        'admin_users': len([u for u in users if u.get('role') == 'admin']),
        'manager_users': len([u for u in users if u.get('role') == 'manager']),
        'regular_users': len([u for u in users if u.get('role') == 'user'])
    }
    
    recent_users = sorted(users, key=lambda x: x.get('created_at', ''), reverse=True)[:5]
    
    return render_template('admin/dashboard.html', 
                         users=users, 
                         announcements=announcements, 
                         events=events,
                         stats=stats,
                         recent_users=recent_users,
                         recent_posts=[],
                         recent_contacts=[])

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    users = load_data(USERS_FILE)
    return render_template('admin/users.html', users=users)

@app.route('/admin/announcements', methods=['GET', 'POST'])
def admin_announcements():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        announcements = load_data(ANNOUNCEMENTS_FILE)
        new_announcement = {
            'id': len(announcements) + 1,
            'title': title,
            'content': content,
            'author': session['username'],
            'created_at': datetime.now().isoformat()
        }
        
        announcements.append(new_announcement)
        save_data(ANNOUNCEMENTS_FILE, announcements)
        
        flash('Duyuru başarıyla eklendi!', 'success')
        return redirect(url_for('admin_announcements'))
    
    announcements = load_data(ANNOUNCEMENTS_FILE)
    return render_template('admin/announcements.html', items=announcements)

@app.route('/admin/announcements/delete/<int:ann_id>', methods=['POST'])
def delete_announcement(ann_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    announcements = load_data(ANNOUNCEMENTS_FILE)
    announcement = next((a for a in announcements if a['id'] == ann_id), None)
    
    if announcement:
        announcements = [a for a in announcements if a['id'] != ann_id]
        save_data(ANNOUNCEMENTS_FILE, announcements)
        flash(f'"{announcement["title"]}" duyurusu silindi!', 'success')
    else:
        flash('Duyuru bulunamadı!', 'error')
    
    return redirect(url_for('admin_announcements'))

@app.route('/admin/announcements/edit/<int:ann_id>', methods=['GET', 'POST'])
def edit_announcement(ann_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    announcements = load_data(ANNOUNCEMENTS_FILE)
    announcement = next((a for a in announcements if a['id'] == ann_id), None)
    
    if not announcement:
        flash('Duyuru bulunamadı!', 'error')
        return redirect(url_for('admin_announcements'))
    
    if request.method == 'POST':
        announcement['title'] = request.form['title']
        announcement['content'] = request.form['content']
        
        save_data(ANNOUNCEMENTS_FILE, announcements)
        flash('Duyuru güncellendi!', 'success')
        return redirect(url_for('admin_announcements'))
    
    return render_template('admin/announcement_edit.html', announcement=announcement)

# Etkinlik yönetimi - DÜZELTME
@app.route('/admin/events', methods=['GET', 'POST'])
def admin_events():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        date = request.form['date']
        description = request.form['description']
        
        events = load_data(EVENTS_FILE)
        new_event = {
            'id': len(events) + 1,
            'title': title,
            'date': date,
            'description': description,
            'created_at': datetime.now().isoformat()
        }
        
        events.append(new_event)
        save_data(EVENTS_FILE, events)
        
        flash('Etkinlik başarıyla eklendi!', 'success')
        return redirect(url_for('admin_events'))
    
    events = load_data(EVENTS_FILE)
    return render_template('admin/events.html', events=events)

@app.route('/admin/events/delete/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    events = load_data(EVENTS_FILE)
    event = next((e for e in events if e['id'] == event_id), None)
    
    if event:
        events = [e for e in events if e['id'] != event_id]
        save_data(EVENTS_FILE, events)
        flash(f'"{event["title"]}" etkinliği silindi!', 'success')
    else:
        flash('Etkinlik bulunamadı!', 'error')
    
    return redirect(url_for('admin_events'))

# Paylaşım sistemi
@app.route('/add_post', methods=['POST'])
# @limiter.limit("10 per minute")  # Geçici olarak devre dışı
def add_post():
    if 'user_id' not in session:
        flash('Paylaşım yapmak için giriş yapmalısınız!', 'error')
        return redirect(url_for('login'))
    
    post_type = sanitize_input(request.form.get('post_type', 'text'))
    content = sanitize_input(request.form.get('content', ''))
    title = sanitize_input(request.form.get('title', ''))
    
    # Input validasyonu
    if not content:
        flash('Paylaşım içeriği boş olamaz!', 'error')
        return redirect(url_for('index'))
    
    if post_type == 'mixed' and not title:
        flash('Resim + yazı paylaşımları için başlık gereklidir!', 'error')
        return redirect(url_for('index'))
    
    # İçerik uzunluk kontrolü
    if len(content) > 2000:
        flash('Paylaşım içeriği çok uzun! (Max 2000 karakter)', 'error')
        return redirect(url_for('index'))
    
    if len(title) > 100:
        flash('Başlık çok uzun! (Max 100 karakter)', 'error')
        return redirect(url_for('index'))
    
    image_filename = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename:
            is_valid, error_msg = validate_file_upload(file)
            if not is_valid:
                flash(error_msg, 'error')
                return redirect(url_for('index'))
            
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            image_filename = f"{timestamp}-{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    
    post_data = {
        'id': len(load_data('data/posts.json')) + 1,
        'user_id': session['user_id'],
        'username': session.get('username', 'Bilinmeyen'),
        'title': title,
        'content': content,
        'post_type': post_type,
        'image': image_filename,
        'created_at': datetime.now().isoformat(),
        'likes': 0,
        'comments': []
    }
    
    posts = load_data('data/posts.json')
    posts.append(post_data)
    save_data('data/posts.json', posts)
    
    flash('Paylaşımınız başarıyla eklendi!', 'success')
    return redirect(url_for('index'))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        flash('Bu işlem için giriş yapmalısınız!', 'error')
        return redirect(url_for('login'))
    
    posts = load_data('data/posts.json')
    post = next((p for p in posts if p['id'] == post_id), None)
    
    if not post:
        flash('Paylaşım bulunamadı!', 'error')
        return redirect(url_for('index'))
    
    if post['user_id'] != session['user_id'] and session.get('role') != 'admin':
        flash('Bu paylaşımı silme yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    if post.get('image'):
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], post['image'])
        if os.path.exists(image_path):
            os.remove(image_path)
    
    posts = [p for p in posts if p['id'] != post_id]
    save_data('data/posts.json', posts)
    
    flash('Paylaşım başarıyla silindi!', 'success')
    return redirect(url_for('index'))

# Kullanıcı yönetimi
@app.route('/admin/users/change_password/<int:user_id>', methods=['POST'])
def change_user_password(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    new_password = request.form.get('password', '')
    
    # Şifre gücü kontrolü
    is_strong, password_msg = validate_password_strength(new_password)
    if not is_strong:
        flash(password_msg, 'error')
        return redirect(url_for('admin_users'))
    
    users = load_data(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    
    if user:
        # Güvenli şifre hashleme
        user['password'] = hash_password(new_password)
        save_data(USERS_FILE, users)
        flash(f'{user["username"]} kullanıcısının şifresi güncellendi!', 'success')
    else:
        flash('Kullanıcı bulunamadı!', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/change_role/<int:user_id>', methods=['POST'])
def change_user_role(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    new_role = request.form['role']
    users = load_data(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    
    if user:
        user['role'] = new_role
        save_data(USERS_FILE, users)
        flash(f'{user["username"]} kullanıcısının rolü {new_role} olarak güncellendi!', 'success')
    else:
        flash('Kullanıcı bulunamadı!', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    users = load_data(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    
    if user:
        if user['role'] == 'admin':
            admin_count = len([u for u in users if u['role'] == 'admin'])
            if admin_count <= 1:
                flash('Son admin kullanıcısını silemezsiniz!', 'error')
                return redirect(url_for('admin_users'))
        
        users = [u for u in users if u['id'] != user_id]
        save_data(USERS_FILE, users)
        flash(f'{user["username"]} kullanıcısı silindi!', 'success')
    else:
        flash('Kullanıcı bulunamadı!', 'error')
    
    return redirect(url_for('admin_users'))

# Manager paneli
@app.route('/manager')
def manager_panel():
    if 'user_id' not in session or session.get('role') not in ['admin', 'manager']:
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))
    
    return render_template('manager/panel.html')

# 404 hatası
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

# Mevcut kullanıcıların şifrelerini güvenli hale getir
def migrate_passwords():
    """Mevcut düz metin şifreleri hashle"""
    users = load_data(USERS_FILE)
    updated = False
    
    for user in users:
        # Eğer şifre hashlenmemişse (düz metinse)
        if ':' not in user.get('password', ''):
            old_password = user['password']
            user['password'] = hash_password(old_password)
            updated = True
            print(f"Kullanıcı {user['username']} şifresi güvenli hale getirildi")
    
    # Test için bilinen şifreler ekle
    test_users = [
        {'username': 'mert', 'password': '313131'},
        {'username': 'admin', 'password': 'admin123'}
    ]
    
    for test_user in test_users:
        user = next((u for u in users if u['username'] == test_user['username']), None)
        if user:
            user['password'] = hash_password(test_user['password'])
            updated = True
            print(f"Test kullanıcısı {test_user['username']} şifresi güncellendi")
    
    if updated:
        save_data(USERS_FILE, users)
        print("Tüm şifreler güvenli hale getirildi!")

# Uygulama başlatıldığında migration çalıştır
if __name__ == '__main__':
    migrate_passwords()
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
