document.addEventListener('DOMContentLoaded', () => {
  // Mobil algılama
  const isMobile = window.innerWidth <= 768 || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
  
  if (isMobile) {
    document.body.classList.add('mobile-device');
    initMobileUI();
  }
  
  const flashWrapper = document.querySelector('.flash-wrapper');
  if (flashWrapper) {
    setTimeout(() => flashWrapper.classList.add('fade-out'), 3500);
  }

  // Tema anahtarı
  const root = document.documentElement;
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') root.classList.add('light');
  const toggleBtn = document.getElementById('theme-toggle');
  if (toggleBtn) {
    // Tema butonunun metnini güncelle
    updateThemeButtonText();
    
    toggleBtn.addEventListener('click', () => {
      root.classList.toggle('light');
      const isLight = root.classList.contains('light');
      localStorage.setItem('theme', isLight ? 'light' : 'dark');
      updateThemeButtonText();
    });
  }

  // Mobil menü
  const navToggle = document.getElementById('nav-toggle');
  const navMenu = document.getElementById('nav-menu');
  if (navToggle && navMenu) {
    navToggle.addEventListener('click', () => {
      const open = navMenu.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  // Avatar preview
  const avatarInput = document.getElementById('avatar');
  if (avatarInput) {
    avatarInput.addEventListener('change', function(e) {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
          const currentAvatar = document.querySelector('.current-avatar');
          const placeholder = document.querySelector('.avatar-placeholder');
          
          if (currentAvatar) {
            currentAvatar.src = e.target.result;
          } else if (placeholder) {
            placeholder.innerHTML = '';
            placeholder.style.backgroundImage = `url(${e.target.result})`;
            placeholder.style.backgroundSize = 'cover';
            placeholder.style.backgroundPosition = 'center';
          }
        };
        reader.readAsDataURL(file);
      }
    });
  }
});

function updateThemeButtonText() {
  const toggleBtn = document.getElementById('theme-toggle');
  const root = document.documentElement;
  if (toggleBtn) {
    const isLight = root.classList.contains('light');
    toggleBtn.textContent = isLight ? '🌙 Dark' : '☀️ Light';
  }
}

// Mobil UI başlatma
function initMobileUI() {
  // Bottom navigation oluştur
  createBottomNavigation();
  
  // Mobil menü oluştur
  createMobileMenu();
  
  // Touch events ekle
  addTouchEvents();
}

// Bottom navigation oluştur
function createBottomNavigation() {
  const bottomNav = document.createElement('div');
  bottomNav.className = 'mobile-bottom-nav';
  bottomNav.innerHTML = `
    <a href="/" class="nav-item active">
      <i class="icon">🏠</i>
      <span>Ana Sayfa</span>
    </a>
    <a href="/announcements" class="nav-item">
      <i class="icon">📢</i>
      <span>Duyurular</span>
    </a>
    <a href="/events" class="nav-item">
      <i class="icon">📅</i>
      <span>Etkinlikler</span>
    </a>
    <a href="/profile" class="nav-item">
      <i class="icon">👤</i>
      <span>Profil</span>
    </a>
  `;
  
  document.body.appendChild(bottomNav);
}

// Mobil menü oluştur
function createMobileMenu() {
  const mobileMenu = document.createElement('div');
  mobileMenu.className = 'mobile-menu';
  mobileMenu.innerHTML = `
    <div class="mobile-menu-header">
      <h3>Bilgisayar Bilimleri Kulübü</h3>
      <button class="mobile-menu-close">✕</button>
    </div>
    <div class="mobile-menu-content">
      <a href="/" class="mobile-menu-item">
        <i class="icon">🏠</i>
        <span>Ana Sayfa</span>
      </a>
      <a href="/announcements" class="mobile-menu-item">
        <i class="icon">📢</i>
        <span>Duyurular</span>
      </a>
      <a href="/events" class="mobile-menu-item">
        <i class="icon">📅</i>
        <span>Etkinlikler</span>
      </a>
      <a href="/contact" class="mobile-menu-item">
        <i class="icon">📞</i>
        <span>İletişim</span>
      </a>
      <a href="/login" class="mobile-menu-item">
        <i class="icon">🔐</i>
        <span>Giriş Yap</span>
      </a>
    </div>
  `;
  
  document.body.appendChild(mobileMenu);
  
  // Menü toggle
  const menuToggle = document.createElement('button');
  menuToggle.className = 'mobile-menu-toggle';
  menuToggle.innerHTML = '☰';
  const header = document.querySelector('.site-header');
  if (header) {
    header.appendChild(menuToggle);
  }
  
  menuToggle.addEventListener('click', () => {
    mobileMenu.classList.toggle('active');
  });
  
  const closeBtn = mobileMenu.querySelector('.mobile-menu-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      mobileMenu.classList.remove('active');
    });
  }
}

// Touch events ekle
function addTouchEvents() {
  // Swipe gestures
  let startX, startY, endX, endY;
  
  document.addEventListener('touchstart', (e) => {
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
  });
  
  document.addEventListener('touchend', (e) => {
    endX = e.changedTouches[0].clientX;
    endY = e.changedTouches[0].clientY;
    
    const diffX = startX - endX;
    const diffY = startY - endY;
    
    // Yatay swipe
    if (Math.abs(diffX) > Math.abs(diffY) && Math.abs(diffX) > 50) {
      if (diffX > 0) {
        // Sol swipe - menü aç
        const mobileMenu = document.querySelector('.mobile-menu');
        if (mobileMenu) {
          mobileMenu.classList.add('active');
        }
      } else {
        // Sağ swipe - menü kapat
        const mobileMenu = document.querySelector('.mobile-menu');
        if (mobileMenu) {
          mobileMenu.classList.remove('active');
        }
      }
    }
  });
}


