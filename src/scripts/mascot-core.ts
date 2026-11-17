// fj4rr_ mascot — strict 1-bit pixel engine.
// Palette: 0 = background #080808, 1 = pixel #FFFFFF, 2 = secondary #888888. Nothing else.
// The scene is drawn on a 120×64 grid and scaled up with nearest-neighbour only.
// This module has no DOM access so it can also be run in Node to export sprite sheets.

export const W = 120;
export const H = 64;
export const PALETTE = ['#080808', '#FFFFFF', '#888888'] as const;

type Buf = Uint8Array;

// ---------------------------------------------------------------- primitives
const inb = (x: number, y: number) => x >= 0 && y >= 0 && x < W && y < H;
function px(b: Buf, x: number, y: number, c: number) { x |= 0; y |= 0; if (inb(x, y)) b[y * W + x] = c; }
function hline(b: Buf, x0: number, x1: number, y: number, c: number) { for (let x = x0; x <= x1; x++) px(b, x, y, c); }
function line(b: Buf, x0: number, y0: number, x1: number, y1: number, c: number) {
  const dx = Math.abs(x1 - x0), sx = x0 < x1 ? 1 : -1, dy = -Math.abs(y1 - y0), sy = y0 < y1 ? 1 : -1;
  let err = dx + dy;
  for (;;) {
    px(b, x0, y0, c);
    if (x0 === x1 && y0 === y1) break;
    const e2 = 2 * err;
    if (e2 >= dy) { err += dy; x0 += sx; }
    if (e2 <= dx) { err += dx; y0 += sy; }
  }
}
function fillRect(b: Buf, x: number, y: number, w: number, h: number, c: number) { for (let j = 0; j < h; j++) hline(b, x, x + w - 1, y + j, c); }
function rect(b: Buf, x: number, y: number, w: number, h: number, c: number) {
  hline(b, x, x + w - 1, y, c); hline(b, x, x + w - 1, y + h - 1, c);
  for (let j = 0; j < h; j++) { px(b, x, y + j, c); px(b, x + w - 1, y + j, c); }
}

/** A boolean mask on the scene grid, used to outline unions of shapes with a clean 1px stroke. */
class Mask {
  m = new Uint8Array(W * H);
  set(x: number, y: number) { if (inb(x, y)) this.m[y * W + x] = 1; }
  has(x: number, y: number) { return inb(x, y) && this.m[y * W + x] === 1; }
  ellipse(cx: number, cy: number, rx: number, ry: number) {
    for (let y = Math.floor(cy - ry); y <= Math.ceil(cy + ry); y++)
      for (let x = Math.floor(cx - rx); x <= Math.ceil(cx + rx); x++) {
        const nx = (x - cx) / rx, ny = (y - cy) / ry;
        if (nx * nx + ny * ny <= 1) this.set(x, y);
      }
    return this;
  }
  rows(y0: number, y1: number, fn: (y: number) => [number, number]) {
    for (let y = y0; y <= y1; y++) { const [a, b] = fn(y); for (let x = Math.round(a); x <= Math.round(b); x++) this.set(x, y); }
    return this;
  }
  /** fill interior with `fill`, outline with `stroke` (4-neighbour edge). */
  paint(b: Buf, fill: number, stroke: number) {
    for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
      if (!this.has(x, y)) continue;
      const edge = !this.has(x - 1, y) || !this.has(x + 1, y) || !this.has(x, y - 1) || !this.has(x, y + 1);
      b[y * W + x] = edge ? stroke : fill;
    }
  }
  fill(b: Buf, c: number) { for (let i = 0; i < this.m.length; i++) if (this.m[i]) b[i] = c; }
}

/** Sprite strings: '.' transparent, '#' white, '+' grey, 'k' opaque background (erases). */
function blit(b: Buf, rows: string[], x: number, y: number, flip = false) {
  const w = Math.max(...rows.map((r) => r.length));
  rows.forEach((r, j) => {
    for (let i = 0; i < r.length; i++) {
      const ch = r[i];
      if (ch === '.' || ch === ' ') continue;
      const c = ch === '#' ? 1 : ch === '+' ? 2 : 0;
      px(b, flip ? x + (w - 1 - i) : x + i, y + j, c);
    }
  });
}

// ---------------------------------------------------------------- glyphs
const G: Record<string, string[]> = {
  Z3: ['###', '..#', '.#.', '#..', '###'],
  Z4: ['####', '...#', '..#.', '.#..', '#...', '####'],
  Z5: ['#####', '....#', '...#.', '..#..', '.#...', '#....', '#####'],
  bang: ['##', '##', '##', '##', '..', '##'],
  q: ['.###.', '#...#', '...#.', '..#..', '.....', '..#..'],
  dots: ['#.#.#'],
  prompt: ['#...', '.#..', '..#.', '.#..', '#...', '....', '..##'],
  heart: ['.#.#.', '#####', '#####', '.###.', '..#..'],
  mug: [
    '#######...',
    '#kkkkk#...',
    '#k###k####',
    '#kkkkk#kk#',
    '#k###k#kk#',
    '#kkkkk####',
    '#kkkkk#...',
    '.#####....',
  ],
  zero: ['.#.', '#.#', '#.#', '#.#', '.#.'],
  one: ['.#.', '##.', '.#.', '.#.', '###'],
  brace: ['.#', '#.', '##', '#.', '.#'],
  hash: ['.#.#.', '#####', '.#.#.', '#####', '.#.#.'],
};

// ---------------------------------------------------------------- the analyst
export type Eyes = 'open' | 'half' | 'closed' | 'wide' | 'happy' | 'lookL' | 'lookR';
export type Pose = {
  dy: number;                 // head offset (droop / bounce)
  tilt?: number;              // head x shift
  eyes: Eyes;
  mouth?: 'none' | 'o' | 'flat' | 'smile';
  hands: 'type0' | 'type1' | 'rest' | 'mug';
  mugY?: number;              // mug height when drinking
  fx?: Array<{ g: keyof typeof G | 'steam'; x: number; y: number; c?: number }>;
  lidCursor?: boolean;
};

const CX = 36;

function drawAnalyst(b: Buf, p: Pose, t: number) {
  const dy = p.dy, tx = p.tilt ?? 0;
  const hx = CX + tx;

  // body + hood as one silhouette so the outline stays a single 1px stroke
  const sil = new Mask();
  sil.rows(37, 59, (y) => { const hw = 10.4 + (y - 37) * 0.46; return [CX - hw, CX + hw]; });
  sil.ellipse(hx, 27 + dy, 14, 14.5);
  // pointed peak of the hood
  sil.rows(10 + dy, 13 + dy, (y) => { const hw = (y - (10 + dy)) * 1.6; return [hx - hw, hx + hw]; });
  sil.paint(b, 0, 1);

  // hood fold: grey seam from the peak down the back of the hood
  for (let y = 15 + dy; y < 20 + dy; y++) px(b, hx + 6 + Math.floor((y - 15 - dy) / 2), y, 2);

  // face opening (inner rim) and shading ring
  const hole = new Mask().ellipse(hx, 30 + dy, 9.5, 8.5);
  hole.paint(b, 0, 1);
  const ring = new Mask().ellipse(hx, 30 + dy, 8.5, 7.5);
  ring.paint(b, 0, 2);

  // face: white skin under dark hair
  const face = new Mask().ellipse(hx, 32 + dy, 7, 5.5);
  face.fill(b, 1);
  // hair block with zig-zag fringe
  for (let x = hx - 8; x <= hx + 8; x++) {
    const depth = 27 + dy + ((x - hx + 16) % 3 === 0 ? 2 : (x - hx + 16) % 3 === 1 ? 1 : 0);
    for (let y = 22 + dy; y <= depth; y++) if (face.has(x, y) || ring.has(x, y)) px(b, x, y, 0);
  }

  // eyes
  const ey = 31 + dy;
  const lx = hx - 4, rx = hx + 3;
  const eye = (x: number) => {
    switch (p.eyes) {
      case 'open': fillRect(b, x, ey, 2, 2, 0); break;
      case 'lookL': fillRect(b, x - 1, ey, 2, 2, 0); break;
      case 'lookR': fillRect(b, x + 1, ey, 2, 2, 0); break;
      case 'half': hline(b, x - 1, x + 2, ey + 1, 0); px(b, x, ey + 2, 0); px(b, x + 1, ey + 2, 0); break;
      case 'closed': hline(b, x - 1, x + 2, ey + 1, 0); break;
      case 'happy': px(b, x - 1, ey + 1, 0); px(b, x, ey, 0); px(b, x + 1, ey, 0); px(b, x + 2, ey + 1, 0); break;
      case 'wide': fillRect(b, x, ey - 1, 2, 3, 0); break;
    }
  };
  eye(lx); eye(rx);
  // mouth
  const my = 35 + dy;
  switch (p.mouth) {
    case 'o': fillRect(b, hx - 1, my - 1, 2, 2, 0); break;
    case 'flat': hline(b, hx - 1, hx, my, 0); break;
    case 'smile': px(b, hx - 1, my, 0); px(b, hx, my, 0); px(b, hx - 2, my - 1, 0); px(b, hx + 1, my - 1, 0); break;
    default: break;
  }

  // laptop lid (back side faces us) with a >_ mark
  fillRect(b, 23, 43, 27, 16, 0);
  rect(b, 23, 43, 27, 16, 1);
  hline(b, 24, 48, 57, 2); // hinge shade
  blit(b, G.prompt.slice(0, 5), 33, 47);
  if (p.lidCursor !== false) hline(b, 37, 39, 52, 1);
  // keyboard deck
  hline(b, 18, 54, 59, 1);

  // hands
  const hand = (x: number, up: boolean) => { fillRect(b, x, up ? 55 : 56, 3, 2, 1); px(b, x + 1, up ? 57 : 58, 1); };
  if (p.hands === 'type0') { hand(19, true); hand(51, false); }
  else if (p.hands === 'type1') { hand(19, false); hand(51, true); }
  else if (p.hands === 'rest') { hand(19, false); hand(51, false); }
  else if (p.hands === 'mug') {
    hand(19, false);
    const my2 = p.mugY ?? 40;
    // arm from shoulder to mug
    line(b, 47, 46, hx + 6, my2 + 8, 1);
    blit(b, G.mug, hx - 3, my2);
    fillRect(b, hx + 3, my2 + 5, 3, 3, 1);
  }

  // effects
  (p.fx ?? []).forEach((f) => {
    if (f.g === 'steam') {
      for (let i = 0; i < 3; i++) {
        const yy = f.y - i * 2 - (Math.floor(t / 180) % 2);
        const xx = f.x + ((Math.floor(t / 240) + i) % 2);
        px(b, xx, yy, 2);
        px(b, xx + 3, yy - 1, 2);
      }
      return;
    }
    const g = G[f.g];
    if (!g) return;
    if (f.c === 2) blit(b, g.map((r) => r.replace(/#/g, '+')), f.x, f.y);
    else blit(b, g, f.x, f.y);
  });
}

// ---------------------------------------------------------------- desk
function drawDesk(b: Buf) {
  hline(b, 2, W - 3, 60, 1);
  for (let x = 4; x < W - 4; x += 2) px(b, x, 62, 2);
  for (let x = 7; x < W - 6; x += 6) px(b, x, 63, 2);
}

// ---------------------------------------------------------------- the cat
// Each frame faces left; flipped when walking right. Bottom row sits on the desk (y = 59).
const CAT: Record<string, string[]> = {
  sit: [
    '.#...#.........',
    '.##.##.........',
    '#kkkkk#........',
    '#k#k#k#........',
    '#kk+kk#........',
    '.#kkk#####.....',
    '.#kkkkkkkk#....',
    '#kkkkkkkkkk#...',
    '#kkkkkkkkkk#...',
    '#kkkkkkkkkk#.#.',
    '#k#kkkkkkk#..#.',
    '#k#kkkkkkk#.#..',
    '.##########....',
  ],
  sitBlink: [
    '.#...#.........',
    '.##.##.........',
    '#kkkkk#........',
    '#kkkkk#........',
    '###+##k........',
    '.#kkk#####.....',
    '.#kkkkkkkk#....',
    '#kkkkkkkkkk#...',
    '#kkkkkkkkkk#...',
    '#kkkkkkkkkk#.#.',
    '#k#kkkkkkk#..#.',
    '#k#kkkkkkk#.#..',
    '.##########....',
  ],
  sitTail: [
    '.#...#.........',
    '.##.##.........',
    '#kkkkk#........',
    '#k#k#k#........',
    '#kk+kk#........',
    '.#kkk#####.....',
    '.#kkkkkkkk#..#.',
    '#kkkkkkkkkk#.#.',
    '#kkkkkkkkkk#.#.',
    '#kkkkkkkkkk##..',
    '#k#kkkkkkk#....',
    '#k#kkkkkkk#....',
    '.##########....',
  ],
  sitUp: [
    '.#...#.........',
    '.##.##.........',
    '#kkkkk#........',
    '#k#k#k#........',
    '#k#k#k#........',
    '.#k+k#####.....',
    '.#kkkkkkkk#....',
    '#kkkkkkkkkk#...',
    '#kkkkkkkkkk#...',
    '#kkkkkkkkkk#.#.',
    '#k#kkkkkkk#..#.',
    '#k#kkkkkkk#.#..',
    '.##########....',
  ],
  walk0: [
    '.#...#............',
    '.##.##.........#..',
    '#kkkkk#.......#...',
    '#k#k#k#.......#...',
    '#kk+kk#########...',
    '.#kkkkkkkkkkkkk#..',
    '..#kkkkkkkkkkkk#..',
    '..#kkkkkkkkkkk#...',
    '..#k#########k#...',
    '..#k#.......#k#...',
    '.#k#.......#k#....',
    '.##........##.....',
  ],
  walk1: [
    '.#...#............',
    '.##.##..........#.',
    '#kkkkk#........#..',
    '#k#k#k#........#..',
    '#kk+kk#########...',
    '.#kkkkkkkkkkkkk#..',
    '..#kkkkkkkkkkkk#..',
    '..#kkkkkkkkkkk#...',
    '..#k#########k#...',
    '...#k#.......#k#..',
    '...#k#.......#k#..',
    '....##........##..',
  ],
  stretch: [
    '...............#..',
    '..............#...',
    '.............#....',
    '........######....',
    '.......#kkkkkk#...',
    '.#...##kkkkkkk#...',
    '.##.#kkkkkkkk#....',
    '#kkk#kkkk###k#....',
    '#k#k#kk##..#k#....',
    '#kk+k##....#k#....',
    '.#kkk#.....#k#....',
    '########...##.....',
  ],
  loaf: [
    '..#...#..........',
    '..##.##..........',
    '.#kkkkk#####.....',
    '.#kkkkkkkkkk##...',
    '#k##k##kkkkkkk#..',
    '#kk+kkkkkkkkkkk#.',
    '#kkkkkkkkkkkkkk#.',
    '.###############.',
  ],
  loafBreath: [
    '.................',
    '..#...#..........',
    '..##.##.#####....',
    '.#kkkkk#kkkkk##..',
    '#k##k##kkkkkkkk#.',
    '#kk+kkkkkkkkkkk#.',
    '#kkkkkkkkkkkkkk#.',
    '.###############.',
  ],
  clean: [
    '.#...#.........',
    '.##.##.........',
    '#kkkkk#........',
    '#k#k#k#........',
    '##++kk#........',
    '#k#k#####......',
    '.#k#kkkkk#.....',
    '#kk#kkkkkk#....',
    '#kkkkkkkkkk#...',
    '#kkkkkkkkkk#.#.',
    '#k#kkkkkkk#..#.',
    '#k#kkkkkkk#.#..',
    '.##########....',
  ],
};

export type CatState = { frame: keyof typeof CAT; x: number; flip: boolean; zzz?: number; bang?: boolean; love?: number };

function drawCat(b: Buf, c: CatState, t: number) {
  const spr = CAT[c.frame];
  blit(b, spr, Math.round(c.x), 60 - spr.length, c.flip);
  if (c.zzz !== undefined) {
    const k = c.zzz;
    blit(b, G.Z3.map((r) => r.replace(/#/g, k % 2 ? '+' : '#')), Math.round(c.x) + 8, 60 - spr.length - 6 - (k % 3));
  }
  if (c.bang) blit(b, G.bang, Math.round(c.x) + 2, 60 - spr.length - 8);
  if (c.love !== undefined) {
    // hearts float up from the cat's head and fade from white to grey
    const top = 60 - spr.length;
    const hx = Math.round(c.x) + (c.flip ? 9 : 1);
    [0, 420, 840].forEach((delay, i) => {
      const e = c.love! - delay;
      if (e < 0 || e > 1300) return;
      const rise = Math.floor(e / 90);
      const sway = Math.floor(e / 260) % 2 ? 1 : 0;
      const g = e > 750 ? G.heart.map((r) => r.replace(/#/g, '+')) : G.heart;
      blit(b, g, hx + (i % 2 ? 5 : -1) + sway, top - 6 - rise);
    });
  }
}

// ---------------------------------------------------------------- the 20 s analyst sequence
export const SEQUENCE = [
  { name: 'Working', from: 0, to: 5 },
  { name: 'Getting sleepy', from: 5, to: 8 },
  { name: 'Sleeping', from: 8, to: 11 },
  { name: 'Waking up', from: 11, to: 14 },
  { name: 'Drinking coffee', from: 14, to: 17 },
  { name: 'Back to work', from: 17, to: 20 },
] as const;
export const LOOP_MS = 20000;

const floaters = ['zero', 'one', 'brace', 'zero', 'hash', 'one'] as const;

export function analystPose(ms: number): { pose: Pose; phase: number } {
  const t = ms % LOOP_MS;
  const s = t / 1000;
  const step = Math.floor(t / 160); // typing tempo
  const phase = SEQUENCE.findIndex((p) => s >= p.from && s < p.to);
  const blink = (k: number) => (t % k) < 140;

  if (phase === 0) {
    // working: steady typing, occasional blink, floating terminal symbols
    const fx: Pose['fx'] = [];
    const f = Math.floor(t / 900) % floaters.length;
    const ft = (t % 900) / 900;
    if (ft < 0.85) fx.push({ g: floaters[f], x: 56 + (f % 3) * 4, y: Math.round(26 - ft * 14), c: ft > 0.5 ? 2 : 1 });
    const look = s > 3.2 && s < 3.9 ? 'lookR' : blink(2300) ? 'closed' : 'open';
    return { phase, pose: { dy: 0, eyes: look as Eyes, mouth: 'none', hands: step % 2 ? 'type0' : 'type1', fx } };
  }
  if (phase === 1) {
    // getting sleepy: half-closed eyes, a yawn, typing slows, head starts to droop
    const k = s - 5;
    const yawn = k > 1.0 && k < 1.9;
    const slow = Math.floor(t / 420) % 2;
    const dots = k > 2.0 ? [{ g: 'dots' as const, x: 54, y: 18 }] : [];
    return { phase, pose: { dy: k > 2.2 ? 1 : 0, eyes: yawn ? 'closed' : blink(900) ? 'closed' : 'half', mouth: yawn ? 'o' : 'none', hands: k > 2.3 ? 'rest' : slow ? 'type0' : 'type1', fx: dots } };
  }
  if (phase === 2) {
    // sleeping: head down, Zzz rising
    const k = (t % 1500) / 1500;
    const fx: Pose['fx'] = [
      { g: 'Z3', x: 52, y: 22 - Math.round(k * 3), c: 2 },
      { g: 'Z4', x: 56, y: 15 - Math.round(k * 3), c: k > 0.5 ? 1 : 2 },
      { g: 'Z5', x: 61, y: 7 - Math.round(k * 3) },
    ];
    const breathe = Math.floor(t / 750) % 2;
    return { phase, pose: { dy: 4 + breathe, eyes: 'closed', mouth: 'none', hands: 'rest', fx, lidCursor: false } };
  }
  if (phase === 3) {
    // waking up: jolt, wide eyes, "!", look around
    const k = s - 11;
    const jolt = k < 0.25 ? -2 : 0;
    const eyes: Eyes = k < 1.2 ? 'wide' : k < 1.8 ? 'lookL' : k < 2.4 ? 'lookR' : 'open';
    const fx: Pose['fx'] = k < 1.6 ? [{ g: 'bang', x: 54, y: 10 + (k < 0.25 ? -1 : 0) }] : k > 2.2 ? [{ g: 'q', x: 53, y: 11 }] : [];
    return { phase, pose: { dy: jolt, eyes, mouth: k < 1.2 ? 'o' : 'flat', hands: 'rest', fx } };
  }
  if (phase === 4) {
    // drinking coffee: mug rises, sip with happy eyes, steam
    const k = s - 14;
    const mugY = k < 0.5 ? 44 - Math.round(k * 20) : k > 2.5 ? 34 + Math.round((k - 2.5) * 20) : 34;
    const sip = k > 0.7 && k < 2.2;
    const fx: Pose['fx'] = [{ g: 'steam', x: 33, y: mugY - 2 }];
    if (k > 1.4 && k < 2.6) fx.push({ g: 'heart', x: 54, y: 12, c: 1 });
    return { phase, pose: { dy: 0, eyes: sip ? 'happy' : 'open', mouth: 'none', hands: 'mug', mugY, fx } };
  }
  // back to work: fast typing, motion ticks
  const fast = Math.floor(t / 90) % 2;
  const tick = Math.floor(t / 300) % 2;
  const fx: Pose['fx'] = tick ? [{ g: 'dots', x: 54, y: 20, c: 2 }] : [];
  return { phase, pose: { dy: 0, eyes: blink(1700) ? 'closed' : 'open', mouth: 'smile', hands: fast ? 'type0' : 'type1', fx } };
}

// ---------------------------------------------------------------- cat brain (independent of the analyst)
export type CatMode = 'sit' | 'blink' | 'tail' | 'walk' | 'stretch' | 'sleep' | 'clean' | 'lookUp' | 'love';
export const CAT_MODES: { mode: CatMode; label: string }[] = [
  { mode: 'sleep', label: 'Sleeping' },
  { mode: 'blink', label: 'Blinking' },
  { mode: 'stretch', label: 'Stretching' },
  { mode: 'sit', label: 'Sitting' },
  { mode: 'walk', label: 'Walking' },
  { mode: 'tail', label: 'Tail movement' },
];

export class CatBrain {
  x = 82;
  flip = false;
  mode: CatMode = 'sit';
  until = 0;
  target = 82;
  started = 0;
  rnd: () => number;
  constructor(seed = 7) {
    let s = seed >>> 0;
    this.rnd = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
  }
  private pick(now: number) {
    const r = this.rnd();
    const prev = this.mode;
    let next: CatMode;
    if (prev === 'walk') next = r < 0.5 ? 'sit' : r < 0.75 ? 'stretch' : 'clean';
    else if (prev === 'stretch') next = r < 0.5 ? 'sleep' : 'walk';
    else if (prev === 'sleep') next = r < 0.6 ? 'stretch' : 'sit';
    else next = r < 0.32 ? 'walk' : r < 0.52 ? 'tail' : r < 0.66 ? 'sleep' : r < 0.8 ? 'clean' : r < 0.9 ? 'blink' : 'stretch';
    this.set(next, now);
  }
  /** tapped: the cat stops what it is doing and sends hearts */
  love(now: number) {
    if (this.mode === 'walk') this.flip = false;
    this.set('love', now);
  }
  set(mode: CatMode, now: number) {
    this.mode = mode;
    this.started = now;
    const dur: Record<CatMode, [number, number]> = {
      sit: [2500, 4500], blink: [1600, 2400], tail: [2600, 4200], walk: [0, 0], stretch: [1600, 1900],
      sleep: [5000, 8000], clean: [2000, 3200], lookUp: [1400, 1400], love: [2300, 2300],
    };
    const [a, b] = dur[mode];
    this.until = now + a + this.rnd() * (b - a);
    if (mode === 'walk') {
      let tgt = 66 + Math.round(this.rnd() * 36);
      if (Math.abs(tgt - this.x) < 10) tgt = this.x > 84 ? 68 : 100;
      this.target = tgt;
      this.flip = tgt > this.x;
      this.until = Infinity;
    }
  }
  /** returns the frame to draw */
  update(now: number, dt: number): CatState {
    if (this.mode === 'walk') {
      const dir = Math.sign(this.target - this.x);
      this.x += dir * dt * 0.012;
      if ((dir > 0 && this.x >= this.target) || (dir < 0 && this.x <= this.target) || dir === 0) {
        this.x = this.target; this.flip = false; this.pick(now);
      }
    } else if (now >= this.until) this.pick(now);

    const e = now - this.started;
    const x = this.x, flip = this.flip;
    switch (this.mode) {
      case 'walk': return { frame: Math.floor(e / 220) % 2 ? 'walk1' : 'walk0', x, flip };
      case 'stretch': return { frame: e < 1300 ? 'stretch' : 'sit', x, flip };
      case 'sleep': return { frame: Math.floor(e / 1200) % 2 ? 'loafBreath' : 'loaf', x, flip, zzz: Math.floor(e / 600) };
      case 'tail': return { frame: Math.floor(e / 380) % 3 === 1 ? 'sitTail' : Math.floor(e / 380) % 3 === 2 ? 'sitUp' : 'sit', x, flip };
      case 'blink': return { frame: (e % 800) < 160 ? 'sitBlink' : 'sit', x, flip };
      case 'clean': return { frame: Math.floor(e / 260) % 2 ? 'clean' : 'sit', x, flip };
      case 'lookUp': return { frame: 'sitUp', x, flip, bang: e < 700 };
      case 'love': return { frame: Math.floor(e / 380) % 3 === 1 ? 'sitTail' : 'sitBlink', x, flip, love: e };
      default: return { frame: (e % 2600) < 150 ? 'sitBlink' : 'sit', x, flip };
    }
  }
}

// ---------------------------------------------------------------- full frame
export function renderScene(buf: Buf, ms: number, cat: CatState) {
  buf.fill(0);
  drawDesk(buf);
  const { pose } = analystPose(ms);
  drawAnalyst(buf, pose, ms);
  drawCat(buf, cat, ms);
}

/** Single analyst frame without the cat — used for previews and the static fallback. */
export function renderAnalystOnly(buf: Buf, ms: number) {
  buf.fill(0);
  drawDesk(buf);
  drawAnalyst(buf, analystPose(ms).pose, ms);
}

export function renderCatOnly(buf: Buf, cat: CatState) {
  buf.fill(0);
  drawDesk(buf);
  drawCat(buf, cat, 0);
}
