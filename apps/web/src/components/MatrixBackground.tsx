import { useEffect, useRef } from 'react';

interface MatrixBackgroundProps {
  /** Canvas opacity. Default 0.5 */
  opacity?: number;
  /** Additional CSS class name */
  className?: string;
  /** Pause the animation loop */
  paused?: boolean;
}

/**
 * Matrix rain background effect.
 * Canvas-based animation with falling binary/hex characters.
 * Performance-optimized: 60fps, configurable opacity, resize handling.
 * Supports pause/resume for coordination with modal overlays.
 */
export function MatrixBackground({
  opacity = 0.5,
  className,
  paused = false,
}: MatrixBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);
  const pausedRef = useRef(paused);

  // Keep pausedRef in sync without restarting the effect
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const targetCanvas: HTMLCanvasElement = canvas;
    const context: CanvasRenderingContext2D = ctx;

    // Configuration
    const FONT_SIZE = 14;
    const COLUMN_WIDTH = 20;
    const FRAME_INTERVAL = 16; // ~60fps
    const CHARACTERS = '01';
    const PRIMARY_COLOR = '#00D084';
    const DIM_COLOR = '#006644';

    // State
    let columns: number[] = [];
    let lastFrameTime = 0;

    // Resize handler
    function resize() {
      targetCanvas.width = window.innerWidth;
      targetCanvas.height = window.innerHeight;

      // Initialize/reset columns
      const columnCount = Math.floor(targetCanvas.width / COLUMN_WIDTH);
      columns = Array(columnCount)
        .fill(0)
        .map(
          () => Math.random() * -100 // Start at random positions above viewport
        );
    }

    // Draw frame
    function draw(timestamp: number) {
      if (pausedRef.current) {
        // Keep requesting frames so we resume instantly when unpaused
        animationRef.current = requestAnimationFrame(draw);
        return;
      }

      // Throttle to ~60fps
      if (timestamp - lastFrameTime < FRAME_INTERVAL) {
        animationRef.current = requestAnimationFrame(draw);
        return;
      }
      lastFrameTime = timestamp;

      // Fade previous frame (creates trail effect)
      context.fillStyle = 'rgba(0, 0, 0, 0.05)';
      context.fillRect(0, 0, targetCanvas.width, targetCanvas.height);

      // Draw characters
      context.font = `${FONT_SIZE}px "JetBrains Mono", monospace`;

      for (let i = 0; i < columns.length; i++) {
        const y = columns[i] * FONT_SIZE;

        // Random character
        const char = CHARACTERS[Math.floor(Math.random() * CHARACTERS.length)];

        // Leading character is brighter
        context.fillStyle = PRIMARY_COLOR;
        context.fillText(char, i * COLUMN_WIDTH, y);

        // Trail characters are dimmer
        if (Math.random() > 0.98) {
          context.fillStyle = DIM_COLOR;
          context.fillText(char, i * COLUMN_WIDTH, y - FONT_SIZE);
        }

        // Move column down
        columns[i]++;

        // Reset when reaching bottom (with random chance for variation)
        if (y > targetCanvas.height && Math.random() > 0.975) {
          columns[i] = 0;
        }
      }

      animationRef.current = requestAnimationFrame(draw);
    }

    // Initialize
    resize();
    window.addEventListener('resize', resize);
    animationRef.current = requestAnimationFrame(draw);

    // Cleanup
    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationRef.current);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className={`matrix-canvas${className ? ` ${className}` : ''}`}
      aria-hidden="true"
      style={{
        opacity,
        pointerEvents: 'none',
      }}
    />
  );
}
