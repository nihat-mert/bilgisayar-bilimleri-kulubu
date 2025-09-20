from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
from werkzeug.utils import secure_filename
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

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
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_data(USERS_FILE)
        user = next((u for u in users if u['username'] == username and u['password'] == password), None)
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user.get('role', 'user')
            flash('Giriş başarılı!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Kullanıcı adı veya şifre hatalı!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        users = load_data(USERS_FILE)
        
        if any(u['username'] == username for u in users):
            flash('Bu kullanıcı adı zaten kullanılıyor!', 'error')
            return render_template('register.html')
        
        new_user = {
            'id': len(users) + 1,
            'username': username,
            'email': email,
            'password': password,
            'role': 'user',
            'created_at': datetime.now().isoformat()
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
def add_post():
    if 'user_id' not in session:
        flash('Paylaşım yapmak için giriş yapmalısınız!', 'error')
        return redirect(url_for('login'))
    
    post_type = request.form.get('post_type', 'text')
    content = request.form.get('content', '').strip()
    title = request.form.get('title', '').strip()
    
    if not content:
        flash('Paylaşım içeriği boş olamaz!', 'error')
        return redirect(url_for('index'))
    
    if post_type == 'mixed' and not title:
        flash('Resim + yazı paylaşımları için başlık gereklidir!', 'error')
        return redirect(url_for('index'))
    
    image_filename = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename and allowed_file(file.filename):
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
    
    new_password = request.form['password']
    if len(new_password) < 6:
        flash('Şifre en az 6 karakter olmalıdır!', 'error')
        return redirect(url_for('admin_users'))
    
    users = load_data(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    
    if user:
        user['password'] = new_password
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
