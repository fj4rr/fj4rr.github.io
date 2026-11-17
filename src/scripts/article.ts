// Reading features for write-ups: progress bar, TOC tracking, copy buttons,
// long-code collapsing, lightbox and lazy mermaid rendering.
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------- reading progress ---------- */
const bar = document.querySelector<HTMLElement>('[data-progress]');
const article = document.querySelector<HTMLElement>('[data-article]');
if (bar && article) {
  let ticking = false;
  const update = () => {
    const r = article.getBoundingClientRect();
    const total = r.height - innerHeight * 0.6;
    const p = Math.min(1, Math.max(0, -r.top / Math.max(1, total)));
    bar.style.transform = `scaleX(${p})`;
    ticking = false;
  };
  addEventListener('scroll', () => { if (!ticking) { ticking = true; requestAnimationFrame(update); } }, { passive: true });
  update();
}

/* ---------- TOC active section ---------- */
const toc = document.querySelector<HTMLElement>('[data-toc]');
if (toc) {
  const links = [...toc.querySelectorAll<HTMLAnchorElement>('a[href^="#"]')];
  const map = new Map<string, HTMLAnchorElement>();
  links.forEach((a) => map.set(decodeURIComponent(a.hash.slice(1)), a));
  const heads = [...document.querySelectorAll<HTMLElement>('.prose h2[id], .prose h3[id]')].filter((h) => map.has(h.id));
  let current = '';
  const setActive = (id: string) => {
    if (id === current) return;
    current = id;
    links.forEach((a) => a.classList.remove('is-active'));
    const a = map.get(id);
    if (!a) return;
    a.classList.add('is-active');
    // keep the parent h2 highlighted while inside one of its h3s
    a.closest('li.has-children')?.querySelector(':scope > a')?.classList.add('is-active');
    const box = toc.querySelector<HTMLElement>('[data-toc-scroll]');
    if (box) {
      const ar = a.getBoundingClientRect(), br = box.getBoundingClientRect();
      if (ar.top < br.top + 40 || ar.bottom > br.bottom - 40) box.scrollTo({ top: a.offsetTop - box.clientHeight / 2, behavior: reduce ? 'auto' : 'smooth' });
    }
  };
  const onScroll = () => {
    const y = innerHeight * 0.22;
    let id = heads[0]?.id ?? '';
    for (const h of heads) { if (h.getBoundingClientRect().top - y <= 0) id = h.id; else break; }
    setActive(id);
  };
  let t = false;
  addEventListener('scroll', () => { if (!t) { t = true; requestAnimationFrame(() => { onScroll(); t = false; }); } }, { passive: true });
  onScroll();

  // mobile TOC toggle
  const tg = document.querySelector<HTMLButtonElement>('[data-toc-toggle]');
  tg?.addEventListener('click', () => {
    const open = tg.getAttribute('aria-expanded') === 'true';
    tg.setAttribute('aria-expanded', String(!open));
    toc.classList.toggle('is-open', !open);
  });
  links.forEach((a) => a.addEventListener('click', () => {
    if (tg && getComputedStyle(tg).display !== 'none') { tg.setAttribute('aria-expanded', 'false'); toc.classList.remove('is-open'); }
  }));
}

/* ---------- code blocks: copy + collapse ---------- */
document.querySelectorAll<HTMLPreElement>('.prose pre:not(.mermaid-src)').forEach((pre) => {
  const frame = document.createElement('div');
  frame.className = 'code-frame';
  frame.dataset.lang = (pre.dataset.language || 'text').toLowerCase();
  pre.parentNode?.insertBefore(frame, pre);
  frame.appendChild(pre);

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'copy-btn';
  btn.textContent = 'copy';
  btn.setAttribute('aria-label', 'Copy code to clipboard');
  btn.addEventListener('click', async () => {
    const text = pre.querySelector('code')?.innerText ?? pre.innerText;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = 'copied ✓';
      btn.classList.add('is-done');
    } catch {
      btn.textContent = 'press ctrl+c';
      const range = document.createRange(); range.selectNodeContents(pre);
      const sel = getSelection(); sel?.removeAllRanges(); sel?.addRange(range);
    }
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('is-done'); }, 1800);
  });
  frame.appendChild(btn);

  const lines = (pre.querySelector('code')?.innerText ?? '').split('\n').length;
  if (lines > 28) {
    frame.classList.add('is-collapsed');
    const more = document.createElement('button');
    more.type = 'button';
    more.className = 'expand-btn';
    more.textContent = `expand ${lines} lines ↓`;
    more.setAttribute('aria-expanded', 'false');
    more.addEventListener('click', () => {
      const collapsed = frame.classList.toggle('is-collapsed');
      more.textContent = collapsed ? `expand ${lines} lines ↓` : 'collapse ↑';
      more.setAttribute('aria-expanded', String(!collapsed));
    });
    frame.after(more);
  }
});

/* wide tables get a min width so columns stay readable when scrolling */
document.querySelectorAll<HTMLElement>('.prose .table-wrap').forEach((w) => {
  const cols = w.querySelectorAll('thead th').length;
  if (cols >= 4) w.classList.add('is-wide');
  if (w.querySelector('code.hash')) w.classList.add('has-hash');
});

/* ---------- lightbox ---------- */
const lb = document.querySelector<HTMLDialogElement>('[data-lightbox]');
if (lb) {
  const body = lb.querySelector<HTMLElement>('[data-lightbox-body]')!;
  const cap = lb.querySelector<HTMLElement>('[data-lightbox-caption]')!;
  const open = (node: Node, caption: string) => {
    body.replaceChildren(node);
    cap.textContent = caption;
    lb.showModal();
    requestAnimationFrame(() => lb.classList.add('is-open'));
  };
  const close = () => { lb.classList.remove('is-open'); setTimeout(() => lb.close(), reduce ? 0 : 220); };
  lb.addEventListener('click', (e) => { if (e.target === lb || (e.target as HTMLElement).closest('[data-lightbox-close]')) close(); });
  lb.addEventListener('cancel', (e) => { e.preventDefault(); close(); });
  document.addEventListener('click', (e) => {
    const t = e.target as HTMLElement;
    const img = t.closest<HTMLImageElement>('img[data-zoom], .prose img');
    if (img) {
      e.preventDefault();
      const big = new Image(); big.src = img.currentSrc || img.src; big.alt = img.alt;
      open(big, img.alt || img.closest('figure')?.querySelector('figcaption')?.textContent || '');
      return;
    }
    const mer = t.closest<HTMLElement>('.mermaid-src.is-rendered');
    if (mer) {
      const svg = mer.querySelector('svg');
      if (svg) open(svg.cloneNode(true), 'Diagram');
    }
  });
}

/* ---------- mermaid (loaded only when a diagram exists) ---------- */
const diagrams = [...document.querySelectorAll<HTMLElement>('.prose pre.mermaid-src')];
if (diagrams.length) {
  const sources = diagrams.map((d) => (d.querySelector('code')?.textContent ?? d.textContent ?? '').trim());
  diagrams.forEach((d) => (d.textContent = 'rendering diagram…'));
  const render = async () => {
    const { default: mermaid } = await import('mermaid');
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'base',
      fontFamily: 'JetBrains Mono, ui-monospace, monospace',
      themeVariables: {
        darkMode: true,
        background: '#0B1017',
        primaryColor: '#111821',
        primaryBorderColor: '#28A9FF',
        primaryTextColor: '#F1F5F9',
        secondaryColor: '#10151D',
        tertiaryColor: '#10151D',
        lineColor: '#4C7CA8',
        textColor: '#CBD5E1',
        edgeLabelBackground: '#0B1017',
        clusterBkg: '#0E141C',
        clusterBorder: '#263445',
        fontSize: '13px',
      },
      flowchart: { curve: 'basis', htmlLabels: true, padding: 12 },
    });
    for (let i = 0; i < diagrams.length; i++) {
      try {
        const { svg } = await mermaid.render(`mmd-${i}`, sources[i]);
        diagrams[i].innerHTML = svg;
        diagrams[i].classList.add('is-rendered');
        diagrams[i].setAttribute('role', 'img');
        diagrams[i].setAttribute('aria-label', 'Diagram (click to enlarge)');
      } catch (err) {
        const pre = document.createElement('code');
        pre.textContent = sources[i];
        diagrams[i].replaceChildren(pre);
        console.warn('mermaid render failed', err);
      }
    }
  };
  const io = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) { io.disconnect(); render(); }
  }, { rootMargin: '600px 0px' });
  diagrams.forEach((d) => io.observe(d));
}
