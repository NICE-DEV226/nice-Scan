/* ====================================================
   NICE_SCAN — Landing Page Interactions
   ==================================================== */

document.addEventListener('DOMContentLoaded', () => {

  /* ─── Mobile Nav Toggle ─── */
  const navToggle = document.querySelector('.nav-toggle');
  const navLinks = document.querySelector('.nav-links');
  if (navToggle) {
    navToggle.addEventListener('click', () => {
      navLinks.classList.toggle('open');
    });
  }

  /* ─── Close mobile nav on link click ─── */
  document.querySelectorAll('.nav-links a').forEach(link => {
    link.addEventListener('click', () => navLinks.classList.remove('open'));
  });

  /* ─── Install Method Tabs ─── */
  const installCards = document.querySelectorAll('.install-card');
  const codeTabs = document.querySelectorAll('.code-tab');
  const codeBlocks = {
    scoop: document.getElementById('code-scoop'),
    winget: document.getElementById('code-winget'),
    go: document.getElementById('code-go'),
    manual: document.getElementById('code-manual'),
  };

  function activateInstallMethod(method) {
    // Update cards
    installCards.forEach(c => c.classList.remove('active'));
    document.querySelector(`.install-card[data-method="${method}"]`).classList.add('active');
    // Update code tabs
    codeTabs.forEach(t => t.classList.remove('active'));
    document.querySelector(`.code-tab[data-tab="${method}"]`).classList.add('active');
    // Show code block
    Object.values(codeBlocks).forEach(b => b.classList.add('hidden'));
    codeBlocks[method].classList.remove('hidden');
  }

  installCards.forEach(card => {
    card.addEventListener('click', () => {
      activateInstallMethod(card.dataset.method);
    });
  });

  codeTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      activateInstallMethod(tab.dataset.tab);
    });
  });

  /* ─── Copy Buttons ─── */
  const toast = document.getElementById('toast');

  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const cmd = btn.dataset.cmd;
      if (!cmd) return;
      try {
        await navigator.clipboard.writeText(cmd);
        showToast('Copied to clipboard');
      } catch {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = cmd;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copied to clipboard');
      }
    });
  });

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove('show'), 2000);
  }

  /* ─── Counter Animation ─── */
  const statNumbers = document.querySelectorAll('.stat-num');
  let countersAnimated = false;

  function animateCounters() {
    if (countersAnimated) return;
    countersAnimated = true;

    statNumbers.forEach(el => {
      const target = parseInt(el.dataset.target) || 0;
      const duration = 1500;
      const start = performance.now();

      function update(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const current = Math.floor(eased * target);
        el.textContent = current;
        if (progress < 1) requestAnimationFrame(update);
        else el.textContent = target;
      }
      requestAnimationFrame(update);
    });
  }

  /* ─── Intersection Observer for counters ─── */
  const statsSection = document.querySelector('.section-stats');
  if (statsSection && 'IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          animateCounters();
          observer.disconnect();
        }
      });
    }, { threshold: 0.3 });
    observer.observe(statsSection);
  } else {
    // Fallback: animate on load
    animateCounters();
  }

  /* ─── Smooth scroll for anchor links ─── */
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      const target = document.querySelector(anchor.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  /* ─── Feature cards reveal on scroll ─── */
  const featureCards = document.querySelectorAll('.feature-card');
  if (featureCards.length && 'IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    featureCards.forEach(card => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(20px)';
      card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      observer.observe(card);
    });
  }

  /* ─── Navbar scroll effect ─── */
  const navbar = document.querySelector('.navbar');
  let lastScroll = 0;

  window.addEventListener('scroll', () => {
    const currentScroll = window.pageYOffset;
    if (currentScroll > 80) {
      navbar.style.background = 'rgba(15,17,23,0.95)';
    } else {
      navbar.style.background = 'rgba(15,17,23,0.8)';
    }
    lastScroll = currentScroll;
  });
});
