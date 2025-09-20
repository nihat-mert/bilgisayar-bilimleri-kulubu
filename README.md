
Tarayıcı: `http://127.0.0.1:5000`

## Özellikler
- Ana sayfa: Fotoğraf yükleme (zaman damgalı) + thumbnail üretimi, yazı ekleme
- Duyurular sayfası ve admin paneli (ekle/düzenle/sil): `/admin/duyurular`
- Etkinlik yönetimi (admin) ve herkese açık liste: `/admin/etkinlikler` / `/etkinlikler`
- İletişim formu (mesajlar veritabanına kaydedilir)
- Bölümler: Açılır menü ile 4 alt sayfa
- Koyu/Açık tema anahtarı (tercih localStorage'da saklanır)
- Mobil hamburger menü

## Veritabanı
- SQLite (dosya: `app.db`). Uygulama ilk çalıştığında tablolar otomatik oluşturulur.

## Görseller
- Asıl dosyalar `static/uploads` içine, küçük resimler `thumb-*.ext` olarak aynı klasöre yazılır.
- Galeri, küçük resimleri gösterir; tıklanınca orijinal resmi yeni sekmede açar.

## Notlar
- Yüklenen görsellerin yolları DB'de saklanır; iki placeholder SVG başlangıç için eklenir.
- Quill ile duyuru içerikleri HTML olarak saklanır.
