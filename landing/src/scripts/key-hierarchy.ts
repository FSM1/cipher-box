/**
 * Animated key hierarchy canvas.
 * Shows the VaultKey derivation tree with color-coded key types.
 */

import {
  GREEN,
  GREEN_DIM,
  GREEN_DARK,
  GREEN_GLOW,
  CYAN,
  CYAN_GLOW,
  AMBER,
  AMBER_DIM,
  AMBER_GLOW,
  FONT,
  NODE_BG,
  setupCanvasDPR,
} from './canvas-theme';

interface TreeNode {
  label: string;
  sublabel: string;
  color: string;
  x: number;
  y: number;
  w: number;
  h: number;
  children: number[];
  parentIdx: number;
}

export function initKeyHierarchy(canvas: HTMLCanvasElement): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  let animationId = 0;
  let running = false;
  let startTime = 0;

  const treeDef = [
    { label: 'VaultKey', sublabel: 'secp256k1 Keypair', color: GREEN, children: [1, 2, 3, 6, 7], parent: -1 },
    { label: 'rootFolderKey', sublabel: 'Random 32B, ECIES-wrapped', color: AMBER, children: [4, 5], parent: 0 },
    { label: 'rootIpnsKey', sublabel: 'HKDF-derived Ed25519', color: CYAN, children: [], parent: 0 },
    { label: 'Per-Folder Keys', sublabel: 'Random, ECIES-wrapped', color: AMBER, children: [8], parent: 0 },
    { label: 'Folder Metadata', sublabel: 'AES-256-GCM Encrypted', color: GREEN, children: [], parent: 1 },
    { label: 'File Pointers', sublabel: 'Encrypted Names + CIDs', color: GREEN, children: [], parent: 1 },
    { label: 'Device Registry', sublabel: 'HKDF-derived IPNS Key', color: CYAN, children: [], parent: 0 },
    { label: 'Vault Settings', sublabel: 'HKDF-derived IPNS Key', color: CYAN, children: [], parent: 0 },
    { label: 'Per-File Keys', sublabel: 'Random 32B per file', color: AMBER, children: [], parent: 3 },
  ];

  let treeNodes: TreeNode[] = [];
  let canvasW = 0;
  let canvasH = 0;

  function layoutTree() {
    const { width, height } = setupCanvasDPR(canvas, ctx!);
    canvasW = width;
    canvasH = height;

    const w = width;
    const h = height;
    const isMobile = w < 600;
    const nodeW = isMobile ? 120 : 150;
    const nodeH = isMobile ? 44 : 50;

    // BFS level assignment
    const levels: number[][] = [];
    const visited = new Set<number>();
    const queue: [number, number][] = [[0, 0]];
    visited.add(0);

    while (queue.length > 0) {
      const [idx, level] = queue.shift()!;
      if (!levels[level]) levels[level] = [];
      levels[level].push(idx);
      for (const childIdx of treeDef[idx].children) {
        if (!visited.has(childIdx)) {
          visited.add(childIdx);
          queue.push([childIdx, level + 1]);
        }
      }
    }

    const levelH = h / (levels.length + 0.5);

    treeNodes = treeDef.map((def) => ({
      label: def.label,
      sublabel: def.sublabel,
      color: def.color,
      x: 0,
      y: 0,
      w: nodeW,
      h: nodeH,
      children: def.children,
      parentIdx: def.parent,
    }));

    // Position nodes level by level
    for (let lvl = 0; lvl < levels.length; lvl++) {
      const nodesInLevel = levels[lvl];
      const totalW = nodesInLevel.length * nodeW + (nodesInLevel.length - 1) * 16;
      const startX = (w - totalW) / 2;

      for (let i = 0; i < nodesInLevel.length; i++) {
        const idx = nodesInLevel[i];
        treeNodes[idx].x = startX + i * (nodeW + 16);
        treeNodes[idx].y = lvl * levelH + 20;
      }
    }
  }

  function drawNode(node: TreeNode, alpha: number) {
    const c = ctx!;
    c.globalAlpha = alpha;

    const glowColor =
      node.color === CYAN ? CYAN_GLOW :
      node.color === AMBER ? AMBER_GLOW :
      GREEN_GLOW;

    c.strokeStyle = node.color;
    c.lineWidth = 1;
    c.shadowColor = glowColor;
    c.shadowBlur = 6;
    c.strokeRect(node.x, node.y, node.w, node.h);
    c.shadowBlur = 0;

    c.fillStyle = NODE_BG;
    c.fillRect(node.x + 1, node.y + 1, node.w - 2, node.h - 2);

    c.fillStyle = node.color;
    c.font = `bold 10px ${FONT}`;
    c.textAlign = 'center';
    c.textBaseline = 'middle';
    c.fillText(node.label, node.x + node.w / 2, node.y + node.h / 2 - 7, node.w - 8);

    const dimColor =
      node.color === CYAN ? CYAN_GLOW :
      node.color === AMBER ? AMBER_DIM :
      GREEN_DIM;
    c.fillStyle = dimColor;
    c.font = `8px ${FONT}`;
    c.fillText(node.sublabel, node.x + node.w / 2, node.y + node.h / 2 + 9, node.w - 8);

    c.globalAlpha = 1;
  }

  function drawEdge(parent: TreeNode, child: TreeNode, alpha: number) {
    const c = ctx!;
    c.globalAlpha = alpha * 0.6;

    const fromX = parent.x + parent.w / 2;
    const fromY = parent.y + parent.h;
    const toX = child.x + child.w / 2;
    const toY = child.y;

    c.strokeStyle = GREEN_DARK;
    c.lineWidth = 1;
    c.beginPath();
    c.moveTo(fromX, fromY);
    c.bezierCurveTo(fromX, fromY + 20, toX, toY - 20, toX, toY);
    c.stroke();

    c.globalAlpha = 1;
  }

  function draw() {
    if (!running) return;
    const c = ctx!;
    const elapsed = (performance.now() - startTime) / 1000;

    c.clearRect(0, 0, canvasW, canvasH);

    // Draw edges first (behind nodes)
    for (let i = 0; i < treeNodes.length; i++) {
      const node = treeNodes[i];
      const nodeDelay = i * 0.2;
      const alpha = Math.min(1, Math.max(0, (elapsed - nodeDelay) / 0.4));
      for (const childIdx of node.children) {
        const childDelay = childIdx * 0.2;
        const childAlpha = Math.min(1, Math.max(0, (elapsed - childDelay) / 0.4));
        drawEdge(node, treeNodes[childIdx], Math.min(alpha, childAlpha));
      }
    }

    // Draw nodes
    for (let i = 0; i < treeNodes.length; i++) {
      const delay = i * 0.2;
      const alpha = Math.min(1, Math.max(0, (elapsed - delay) / 0.4));
      drawNode(treeNodes[i], alpha);
    }

    // Legend
    const legendY = canvasH - 30;
    c.font = `9px ${FONT}`;
    c.textAlign = 'left';

    const legends = [
      { color: GREEN, label: 'Encrypted Data' },
      { color: CYAN, label: 'HKDF-Derived' },
      { color: AMBER, label: 'Random / ECIES-Wrapped' },
    ];

    let lx = 20;
    for (const l of legends) {
      c.fillStyle = l.color;
      c.fillRect(lx, legendY, 10, 10);
      c.fillText(l.label, lx + 14, legendY + 9);
      lx += c.measureText(l.label).width + 30;
    }

    // Stop rAF once all nodes have fully faded in (no ongoing animation)
    const maxDelay = (treeNodes.length - 1) * 0.2 + 0.4;
    if (elapsed < maxDelay) {
      animationId = requestAnimationFrame(draw);
    }
  }

  function start() {
    if (running) return;
    running = true;
    startTime = performance.now();
    layoutTree();
    animationId = requestAnimationFrame(draw);
  }

  function stop() {
    running = false;
    cancelAnimationFrame(animationId);
  }

  const onResize = () => {
    if (running) layoutTree();
  };

  canvas.addEventListener('canvas:enter', start);
  canvas.addEventListener('canvas:leave', stop);
  window.addEventListener('resize', onResize);

  if (canvas.dataset.visible === 'true') start();

  return () => {
    stop();
    canvas.removeEventListener('canvas:enter', start);
    canvas.removeEventListener('canvas:leave', stop);
    window.removeEventListener('resize', onResize);
  };
}
