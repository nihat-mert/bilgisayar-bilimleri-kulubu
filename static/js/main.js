document.addEventListener('DOMContentLoaded', () => {
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


