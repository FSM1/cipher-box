export const GREEN = '#00D084';
export const GREEN_DIM = '#006644';
export const GREEN_DARK = '#003322';
export const GREEN_GLOW = 'rgba(0, 208, 132, 0.4)';
export const CYAN = '#00BCD4';
export const CYAN_DIM = '#00838F';
export const CYAN_GLOW = 'rgba(0, 188, 212, 0.4)';
export const AMBER = '#F59E0B';
export const AMBER_DIM = '#92400E';
export const AMBER_GLOW = 'rgba(245, 158, 11, 0.4)';
export const FONT = '"JetBrains Mono", monospace';
export const NODE_BG = 'rgba(0, 17, 8, 0.9)';

/**
 * Set up a canvas for HiDPI rendering. Returns CSS pixel dimensions.
 */
export function setupCanvasDPR(
  canvas: HTMLCanvasElement,
  ctx: CanvasRenderingContext2D
): { width: number; height: number } {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { width: rect.width, height: rect.height };
}
