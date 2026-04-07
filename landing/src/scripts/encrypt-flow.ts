/**
 * Animated encryption flow canvas.
 * Shows: File -> Generate Key -> AES-256-GCM -> ECIES Wrap -> IPFS Upload -> IPNS Publish
 */

const GREEN = '#00D084';
const GREEN_DIM = '#006644';
const GREEN_DARK = '#003322';
const GREEN_GLOW = 'rgba(0, 208, 132, 0.4)';
const BLACK = '#000000';
const FONT = '"JetBrains Mono", monospace';

interface FlowNode {
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  sublabel: string;
  progress: number;
}

interface Particle {
  fromIdx: number;
  toIdx: number;
  t: number;
  speed: number;
}

export function initEncryptFlow(canvas: HTMLCanvasElement): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  let animationId = 0;
  let running = false;
  let startTime = 0;
  const particles: Particle[] = [];

  const nodeLabels = [
    { label: 'FILE', sublabel: 'Plaintext' },
    { label: 'KEYGEN', sublabel: 'fileKey (32B) + IV (12B)' },
    { label: 'AES-256-GCM', sublabel: 'Encrypt + Auth Tag' },
    { label: 'ECIES WRAP', sublabel: 'secp256k1 Public Key' },
    { label: 'IPFS UPLOAD', sublabel: 'Content-Addressed' },
    { label: 'IPNS PUBLISH', sublabel: 'Signed Ed25519 Record' },
  ];

  let nodes: FlowNode[] = [];

  function layoutNodes() {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);

    const w = rect.width;
    const h = rect.height;
    const isMobile = w < 600;
    const nodeW = isMobile ? 130 : 160;
    const nodeH = isMobile ? 50 : 56;
    const cols = isMobile ? 2 : 3;
    const rows = Math.ceil(nodeLabels.length / cols);
    const gapX = (w - cols * nodeW) / (cols + 1);
    const gapY = (h - rows * nodeH) / (rows + 1);

    nodes = nodeLabels.map((n, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      return {
        x: gapX + col * (nodeW + gapX),
        y: gapY + row * (nodeH + gapY),
        w: nodeW,
        h: nodeH,
        label: n.label,
        sublabel: n.sublabel,
        progress: 0,
      };
    });
  }

  function spawnParticle() {
    if (nodes.length < 2) return;
    const fromIdx = Math.floor(Math.random() * (nodes.length - 1));
    particles.push({
      fromIdx,
      toIdx: fromIdx + 1,
      t: 0,
      speed: 0.008 + Math.random() * 0.008,
    });
  }

  function drawNode(node: FlowNode, alpha: number) {
    const c = ctx!;
    c.globalAlpha = alpha;

    // Box
    c.strokeStyle = GREEN;
    c.lineWidth = 1;
    c.shadowColor = GREEN_GLOW;
    c.shadowBlur = 8;
    c.strokeRect(node.x, node.y, node.w, node.h);
    c.shadowBlur = 0;

    // Background
    c.fillStyle = 'rgba(0, 17, 8, 0.9)';
    c.fillRect(node.x + 1, node.y + 1, node.w - 2, node.h - 2);

    // Label
    c.fillStyle = GREEN;
    c.font = `bold 11px ${FONT}`;
    c.textAlign = 'center';
    c.textBaseline = 'middle';
    c.fillText(node.label, node.x + node.w / 2, node.y + node.h / 2 - 8);

    // Sublabel
    c.fillStyle = GREEN_DIM;
    c.font = `9px ${FONT}`;
    c.fillText(node.sublabel, node.x + node.w / 2, node.y + node.h / 2 + 10, node.w - 10);

    c.globalAlpha = 1;
  }

  function drawConnection(from: FlowNode, to: FlowNode) {
    const c = ctx!;
    const fromX = from.x + from.w;
    const fromY = from.y + from.h / 2;
    let toX = to.x;
    let toY = to.y + to.h / 2;

    // If wrapping to next row
    if (to.x <= from.x) {
      const midY = from.y + from.h + (to.y - from.y - from.h) / 2;
      c.strokeStyle = GREEN_DARK;
      c.lineWidth = 1;
      c.beginPath();
      c.moveTo(from.x + from.w / 2, from.y + from.h);
      c.lineTo(from.x + from.w / 2, midY);
      c.lineTo(to.x + to.w / 2, midY);
      c.lineTo(to.x + to.w / 2, to.y);
      c.stroke();

      // Arrow
      c.fillStyle = GREEN_DIM;
      c.beginPath();
      c.moveTo(to.x + to.w / 2 - 4, to.y - 2);
      c.lineTo(to.x + to.w / 2 + 4, to.y - 2);
      c.lineTo(to.x + to.w / 2, to.y + 4);
      c.closePath();
      c.fill();
      return;
    }

    c.strokeStyle = GREEN_DARK;
    c.lineWidth = 1;
    c.beginPath();
    c.moveTo(fromX, fromY);
    c.lineTo(toX, toY);
    c.stroke();

    // Arrow
    c.fillStyle = GREEN_DIM;
    c.beginPath();
    c.moveTo(toX, toY - 4);
    c.lineTo(toX, toY + 4);
    c.lineTo(toX - 6, toY);
    c.closePath();
    c.fill();
  }

  function drawParticle(p: Particle) {
    const from = nodes[p.fromIdx];
    const to = nodes[p.toIdx];
    if (!from || !to) return;

    const c = ctx!;
    let px: number, py: number;

    if (to.x <= from.x) {
      // Wrapping row - travel down then across then down
      const midY = from.y + from.h + (to.y - from.y - from.h) / 2;
      if (p.t < 0.33) {
        const lt = p.t / 0.33;
        px = from.x + from.w / 2;
        py = from.y + from.h + (midY - from.y - from.h) * lt;
      } else if (p.t < 0.66) {
        const lt = (p.t - 0.33) / 0.33;
        px = from.x + from.w / 2 + (to.x + to.w / 2 - from.x - from.w / 2) * lt;
        py = midY;
      } else {
        const lt = (p.t - 0.66) / 0.34;
        px = to.x + to.w / 2;
        py = midY + (to.y - midY) * lt;
      }
    } else {
      px = from.x + from.w + (to.x - from.x - from.w) * p.t;
      py = from.y + from.h / 2 + (to.y + to.h / 2 - from.y - from.h / 2) * p.t;
    }

    c.shadowColor = GREEN_GLOW;
    c.shadowBlur = 12;
    c.fillStyle = GREEN;
    c.beginPath();
    c.arc(px, py, 3, 0, Math.PI * 2);
    c.fill();
    c.shadowBlur = 0;
  }

  function draw() {
    if (!running) return;
    const c = ctx!;
    const rect = canvas.getBoundingClientRect();
    const elapsed = (performance.now() - startTime) / 1000;

    c.clearRect(0, 0, rect.width, rect.height);

    // Draw connections
    for (let i = 0; i < nodes.length - 1; i++) {
      drawConnection(nodes[i], nodes[i + 1]);
    }

    // Draw nodes with staggered fade-in
    for (let i = 0; i < nodes.length; i++) {
      const delay = i * 0.3;
      const alpha = Math.min(1, Math.max(0, (elapsed - delay) / 0.5));
      drawNode(nodes[i], alpha);
    }

    // Spawn particles periodically
    if (Math.random() < 0.04 && particles.length < 8) {
      spawnParticle();
    }

    // Update and draw particles
    for (let i = particles.length - 1; i >= 0; i--) {
      particles[i].t += particles[i].speed;
      if (particles[i].t >= 1) {
        particles.splice(i, 1);
      } else {
        drawParticle(particles[i]);
      }
    }

    animationId = requestAnimationFrame(draw);
  }

  function start() {
    if (running) return;
    running = true;
    startTime = performance.now();
    particles.length = 0;
    layoutNodes();
    animationId = requestAnimationFrame(draw);
  }

  function stop() {
    running = false;
    cancelAnimationFrame(animationId);
  }

  const onResize = () => {
    if (running) layoutNodes();
  };

  canvas.addEventListener('canvas:enter', start);
  canvas.addEventListener('canvas:leave', stop);
  window.addEventListener('resize', onResize);

  // Auto-start if visible
  if (canvas.dataset.visible === 'true') {
    start();
  }

  return () => {
    stop();
    canvas.removeEventListener('canvas:enter', start);
    canvas.removeEventListener('canvas:leave', stop);
    window.removeEventListener('resize', onResize);
  };
}
