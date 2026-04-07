/**
 * Animated decryption flow canvas.
 * Shows: Resolve IPNS -> Fetch Metadata -> ECIES Unwrap -> Fetch Blob -> Decrypt -> Plaintext
 * Includes a branch for CTR streaming mode.
 */

const GREEN = '#00D084';
const GREEN_DIM = '#006644';
const GREEN_DARK = '#003322';
const GREEN_GLOW = 'rgba(0, 208, 132, 0.4)';
const CYAN = '#00BCD4';
const FONT = '"JetBrains Mono", monospace';

interface FlowNode {
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  sublabel: string;
  color: string;
}

interface Particle {
  path: number[];
  segment: number;
  t: number;
  speed: number;
  color: string;
}

export function initDecryptFlow(canvas: HTMLCanvasElement): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  let animationId = 0;
  let running = false;
  let startTime = 0;
  const particles: Particle[] = [];

  const nodeLabels = [
    { label: 'RESOLVE IPNS', sublabel: 'k51... Name Lookup', color: GREEN },
    { label: 'FETCH METADATA', sublabel: 'Encrypted JSON Blob', color: GREEN },
    { label: 'ECIES UNWRAP', sublabel: 'Recover fileKey', color: GREEN },
    { label: 'FETCH BLOB', sublabel: 'Encrypted File from IPFS', color: GREEN },
    { label: 'AES-256-GCM', sublabel: 'Decrypt + Verify Tag', color: GREEN },
    { label: 'PLAINTEXT', sublabel: 'Decrypted File', color: GREEN },
  ];

  // Branch node for streaming
  const streamNode = { label: 'AES-256-CTR', sublabel: 'Streaming Byte Ranges', color: CYAN };
  const streamOutNode = { label: 'MEDIA PLAYER', sublabel: 'Seekable Playback', color: CYAN };

  let nodes: FlowNode[] = [];
  let streamNodes: FlowNode[] = [];

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
    const mainH = h * 0.65;
    const gapX = (w - cols * nodeW) / (cols + 1);
    const gapY = (mainH - rows * nodeH) / (rows + 1);

    nodes = nodeLabels.map((n, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      return {
        x: gapX + col * (nodeW + gapX),
        y: gapY + row * (nodeH + gapY),
        w: nodeW,
        h: nodeH,
        ...n,
      };
    });

    // Stream branch: fork from node 3 (FETCH BLOB)
    const forkNode = nodes[3];
    if (forkNode) {
      const branchY = mainH + 10;
      streamNodes = [
        {
          ...streamNode,
          x: forkNode.x + forkNode.w + gapX * 0.5,
          y: branchY,
          w: nodeW,
          h: nodeH,
        },
        {
          ...streamOutNode,
          x: forkNode.x + forkNode.w + gapX * 0.5 + nodeW + gapX,
          y: branchY,
          w: nodeW,
          h: nodeH,
        },
      ];
    }
  }

  function drawNode(node: FlowNode, alpha: number) {
    const c = ctx!;
    c.globalAlpha = alpha;

    const color = node.color;
    const dimColor = color === CYAN ? '#00838F' : GREEN_DIM;
    const glowColor = color === CYAN ? 'rgba(0, 188, 212, 0.4)' : GREEN_GLOW;

    c.strokeStyle = color;
    c.lineWidth = 1;
    c.shadowColor = glowColor;
    c.shadowBlur = 8;
    c.strokeRect(node.x, node.y, node.w, node.h);
    c.shadowBlur = 0;

    c.fillStyle = 'rgba(0, 17, 8, 0.9)';
    c.fillRect(node.x + 1, node.y + 1, node.w - 2, node.h - 2);

    c.fillStyle = color;
    c.font = `bold 11px ${FONT}`;
    c.textAlign = 'center';
    c.textBaseline = 'middle';
    c.fillText(node.label, node.x + node.w / 2, node.y + node.h / 2 - 8);

    c.fillStyle = dimColor;
    c.font = `9px ${FONT}`;
    c.fillText(node.sublabel, node.x + node.w / 2, node.y + node.h / 2 + 10, node.w - 10);

    c.globalAlpha = 1;
  }

  function drawArrow(
    fromX: number,
    fromY: number,
    toX: number,
    toY: number,
    color: string
  ) {
    const c = ctx!;
    c.strokeStyle = color === CYAN ? '#00838F' : GREEN_DARK;
    c.lineWidth = 1;
    c.beginPath();
    c.moveTo(fromX, fromY);
    c.lineTo(toX, toY);
    c.stroke();

    const angle = Math.atan2(toY - fromY, toX - fromX);
    c.fillStyle = color === CYAN ? '#00838F' : GREEN_DIM;
    c.beginPath();
    c.moveTo(toX, toY);
    c.lineTo(
      toX - 8 * Math.cos(angle - 0.3),
      toY - 8 * Math.sin(angle - 0.3)
    );
    c.lineTo(
      toX - 8 * Math.cos(angle + 0.3),
      toY - 8 * Math.sin(angle + 0.3)
    );
    c.closePath();
    c.fill();
  }

  function drawConnection(from: FlowNode, to: FlowNode) {
    if (to.x <= from.x) {
      const midY = from.y + from.h + (to.y - from.y - from.h) / 2;
      const c = ctx!;
      c.strokeStyle = GREEN_DARK;
      c.lineWidth = 1;
      c.beginPath();
      c.moveTo(from.x + from.w / 2, from.y + from.h);
      c.lineTo(from.x + from.w / 2, midY);
      c.lineTo(to.x + to.w / 2, midY);
      c.lineTo(to.x + to.w / 2, to.y);
      c.stroke();
      return;
    }
    drawArrow(from.x + from.w, from.y + from.h / 2, to.x, to.y + to.h / 2, from.color);
  }

  function drawParticle(p: Particle) {
    const allNodes = [...nodes, ...streamNodes];
    const fromIdx = p.path[p.segment];
    const toIdx = p.path[p.segment + 1];
    if (fromIdx == null || toIdx == null) return;

    const from = fromIdx < nodes.length ? nodes[fromIdx] : streamNodes[fromIdx - nodes.length];
    const to = toIdx < nodes.length ? nodes[toIdx] : streamNodes[toIdx - nodes.length];
    if (!from || !to) return;

    let px: number, py: number;

    if (to.x <= from.x && to.y > from.y) {
      const midY = from.y + from.h + (to.y - from.y - from.h) / 2;
      if (p.t < 0.33) {
        px = from.x + from.w / 2;
        py = from.y + from.h + (midY - from.y - from.h) * (p.t / 0.33);
      } else if (p.t < 0.66) {
        px = from.x + from.w / 2 + (to.x + to.w / 2 - from.x - from.w / 2) * ((p.t - 0.33) / 0.33);
        py = midY;
      } else {
        px = to.x + to.w / 2;
        py = midY + (to.y - midY) * ((p.t - 0.66) / 0.34);
      }
    } else {
      const fx = from.x + from.w;
      const fy = from.y + from.h / 2;
      const tx = to.x;
      const ty = to.y + to.h / 2;
      px = fx + (tx - fx) * p.t;
      py = fy + (ty - fy) * p.t;
    }

    const c = ctx!;
    const glowColor = p.color === CYAN ? 'rgba(0, 188, 212, 0.5)' : GREEN_GLOW;
    c.shadowColor = glowColor;
    c.shadowBlur = 12;
    c.fillStyle = p.color;
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

    // Main flow connections
    for (let i = 0; i < nodes.length - 1; i++) {
      drawConnection(nodes[i], nodes[i + 1]);
    }

    // Stream branch connection (from node 3 down to stream nodes)
    if (streamNodes.length >= 2 && nodes[3]) {
      const fork = nodes[3];
      drawArrow(
        fork.x + fork.w / 2, fork.y + fork.h,
        streamNodes[0].x + streamNodes[0].w / 2, streamNodes[0].y,
        CYAN
      );
      drawArrow(
        streamNodes[0].x + streamNodes[0].w,
        streamNodes[0].y + streamNodes[0].h / 2,
        streamNodes[1].x,
        streamNodes[1].y + streamNodes[1].h / 2,
        CYAN
      );

      // Branch label
      c.fillStyle = CYAN;
      c.font = `9px ${FONT}`;
      c.textAlign = 'left';
      c.fillText('// streaming media', fork.x + fork.w / 2 + 8, fork.y + fork.h + 14);
    }

    // Draw main nodes
    for (let i = 0; i < nodes.length; i++) {
      const delay = i * 0.3;
      const alpha = Math.min(1, Math.max(0, (elapsed - delay) / 0.5));
      drawNode(nodes[i], alpha);
    }

    // Draw stream nodes
    for (let i = 0; i < streamNodes.length; i++) {
      const delay = (nodes.length + i) * 0.3;
      const alpha = Math.min(1, Math.max(0, (elapsed - delay) / 0.5));
      drawNode(streamNodes[i], alpha);
    }

    // Spawn particles
    if (Math.random() < 0.03 && particles.length < 6) {
      // Main path
      particles.push({
        path: [0, 1, 2, 3, 4, 5],
        segment: 0,
        t: 0,
        speed: 0.01 + Math.random() * 0.006,
        color: GREEN,
      });
    }
    if (Math.random() < 0.015 && particles.length < 8) {
      // Stream branch path: 0..3 then branch
      particles.push({
        path: [3, nodes.length, nodes.length + 1],
        segment: 0,
        t: 0,
        speed: 0.01 + Math.random() * 0.006,
        color: CYAN,
      });
    }

    // Update particles
    for (let i = particles.length - 1; i >= 0; i--) {
      particles[i].t += particles[i].speed;
      if (particles[i].t >= 1) {
        particles[i].t = 0;
        particles[i].segment++;
        if (particles[i].segment >= particles[i].path.length - 1) {
          particles.splice(i, 1);
          continue;
        }
      }
      drawParticle(particles[i]);
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

  canvas.addEventListener('canvas:enter', start);
  canvas.addEventListener('canvas:leave', stop);
  window.addEventListener('resize', () => {
    if (running) layoutNodes();
  });

  if (canvas.dataset.visible === 'true') start();

  return () => {
    stop();
    canvas.removeEventListener('canvas:enter', start);
    canvas.removeEventListener('canvas:leave', stop);
  };
}
