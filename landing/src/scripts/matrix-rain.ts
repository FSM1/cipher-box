/**
 * Matrix rain background effect - ported from apps/web MatrixBackground.tsx.
 * Canvas-based animation with falling binary characters.
 */
export function initMatrixRain(canvas: HTMLCanvasElement): () => void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return () => {};

  const FONT_SIZE = 14;
  const COLUMN_WIDTH = 20;
  const FRAME_INTERVAL = 50;
  const CHARACTERS = '01';
  const PRIMARY_COLOR = '#00D084';
  const DIM_COLOR = '#006644';

  let columns: number[] = [];
  let lastFrameTime = 0;
  let animationId = 0;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const columnCount = Math.floor(canvas.width / COLUMN_WIDTH);
    columns = Array(columnCount)
      .fill(0)
      .map(() => Math.random() * -100);
  }

  function draw(timestamp: number) {
    if (timestamp - lastFrameTime < FRAME_INTERVAL) {
      animationId = requestAnimationFrame(draw);
      return;
    }
    lastFrameTime = timestamp;

    ctx!.fillStyle = 'rgba(0, 0, 0, 0.05)';
    ctx!.fillRect(0, 0, canvas.width, canvas.height);

    ctx!.font = `${FONT_SIZE}px "JetBrains Mono", monospace`;

    for (let i = 0; i < columns.length; i++) {
      const y = columns[i] * FONT_SIZE;
      const char = CHARACTERS[Math.floor(Math.random() * CHARACTERS.length)];

      ctx!.fillStyle = PRIMARY_COLOR;
      ctx!.fillText(char, i * COLUMN_WIDTH, y);

      if (Math.random() > 0.98) {
        ctx!.fillStyle = DIM_COLOR;
        ctx!.fillText(char, i * COLUMN_WIDTH, y - FONT_SIZE);
      }

      columns[i]++;

      if (y > canvas.height && Math.random() > 0.975) {
        columns[i] = 0;
      }
    }

    animationId = requestAnimationFrame(draw);
  }

  function onVisibilityChange() {
    if (document.hidden) {
      cancelAnimationFrame(animationId);
    } else {
      lastFrameTime = 0;
      animationId = requestAnimationFrame(draw);
    }
  }

  resize();
  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', onVisibilityChange);
  animationId = requestAnimationFrame(draw);

  return () => {
    window.removeEventListener('resize', resize);
    document.removeEventListener('visibilitychange', onVisibilityChange);
    cancelAnimationFrame(animationId);
  };
}
