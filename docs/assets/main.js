/* ========================================================================
   Rikune — Shared JavaScript
   ======================================================================== */

/* --- Particle Canvas --- */
function initParticles() {
  const c = document.getElementById('particles');
  if (!c) return;
  const ctx = c.getContext('2d');
  let w, h, particles = [];
  function resize() { w = c.width = innerWidth; h = c.height = innerHeight; }
  resize(); addEventListener('resize', resize);
  class P {
    constructor() { this.reset(); }
    reset() {
      this.x = Math.random() * w; this.y = Math.random() * h;
      this.vx = (Math.random() - .5) * .4; this.vy = (Math.random() - .5) * .4;
      this.r = Math.random() * 1.5 + .5; this.o = Math.random() * .4 + .1;
    }
    update() {
      this.x += this.vx; this.y += this.vy;
      if (this.x < 0 || this.x > w || this.y < 0 || this.y > h) this.reset();
    }
    draw() {
      ctx.beginPath(); ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(56,189,248,${this.o})`; ctx.fill();
    }
  }
  for (let i = 0; i < 60; i++) particles.push(new P());
  (function loop() {
    ctx.clearRect(0, 0, w, h);
    particles.forEach(p => { p.update(); p.draw(); });
    for (let i = 0; i < particles.length; i++)
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y;
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d < 150) {
          ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(56,189,248,${.06 * (1 - d / 150)})`;
          ctx.stroke();
        }
      }
    requestAnimationFrame(loop);
  })();
}

/* --- Scroll Reveal --- */
function initReveal() {
  const obs = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); obs.unobserve(e.target); } });
  }, { threshold: .15 });
  document.querySelectorAll('.reveal').forEach(el => obs.observe(el));
}

/* --- Nav scroll shadow --- */
function initNavScroll() {
  const nav = document.querySelector('.nav');
  if (!nav) return;
  addEventListener('scroll', () => nav.classList.toggle('scrolled', scrollY > 20));
}

/* --- Hamburger menu --- */
function initHamburger() {
  const btn = document.querySelector('.nav__hamburger');
  const links = document.querySelector('.nav__links');
  if (!btn || !links) return;
  btn.addEventListener('click', () => links.classList.toggle('open'));
  links.querySelectorAll('a').forEach(a => a.addEventListener('click', () => links.classList.remove('open')));
}

/* --- Copy buttons --- */
function initCopy() {
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-copy');
      const el = document.querySelector(target);
      if (!el) return;
      navigator.clipboard.writeText(el.textContent.trim());
      const orig = btn.textContent;
      btn.textContent = '✓ Copied';
      setTimeout(() => btn.textContent = orig, 1500);
    });
  });
  document.querySelectorAll('.code-block__copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const pre = btn.closest('.code-block').querySelector('pre');
      if (!pre) return;
      navigator.clipboard.writeText(pre.textContent.trim());
      const orig = btn.textContent;
      btn.textContent = '✓ Copied';
      setTimeout(() => btn.textContent = orig, 1500);
    });
  });
}

/* --- Tab switching --- */
function initTabs() {
  document.querySelectorAll('.tab-group').forEach(group => {
    const btns = group.querySelectorAll('.tab-btn');
    const panels = group.querySelectorAll('.tab-panel');
    btns.forEach(btn => {
      btn.addEventListener('click', () => {
        const t = btn.getAttribute('data-tab');
        btns.forEach(b => b.classList.toggle('active', b === btn));
        panels.forEach(p => p.classList.toggle('active', p.getAttribute('data-tab') === t));
      });
    });
  });
}

/* --- Counter animation --- */
function animateCounters() {
  document.querySelectorAll('[data-count]').forEach(el => {
    const target = parseInt(el.getAttribute('data-count'));
    const suffix = el.getAttribute('data-suffix') || '';
    let cur = 0;
    const step = Math.max(1, Math.ceil(target / 60));
    const interval = setInterval(() => {
      cur = Math.min(cur + step, target);
      el.textContent = cur + suffix;
      if (cur >= target) clearInterval(interval);
    }, 25);
  });
}

/* --- FAQ accordion --- */
function initFAQ() {
  document.querySelectorAll('.faq-item__q').forEach(q => {
    q.addEventListener('click', () => {
      const item = q.closest('.faq-item');
      item.classList.toggle('open');
    });
  });
}

/* --- i18n language toggle --- */
function initI18n() {
  const saved = localStorage.getItem('rikune-lang') || 'en';
  document.documentElement.lang = saved;
  const btn = document.getElementById('lang-toggle');
  if (!btn) return;
  btn.textContent = saved === 'en' ? '中文' : 'EN';
  btn.addEventListener('click', () => {
    const cur = document.documentElement.lang;
    const next = cur === 'en' ? 'zh' : 'en';
    document.documentElement.lang = next;
    localStorage.setItem('rikune-lang', next);
    btn.textContent = next === 'en' ? '中文' : 'EN';
  });
}

/* --- Init --- */
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  initReveal();
  initNavScroll();
  initHamburger();
  initCopy();
  initTabs();
  initFAQ();
  initI18n();
});
