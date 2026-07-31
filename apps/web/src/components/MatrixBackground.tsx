import { useEffect, useRef } from 'react';

interface MatrixBackgroundProps {
  /** Canvas opacity. */
  opacity?: number;
  /** Frame interval in ms; 16 is ~60fps. */
  frameInterval?: number;
}

const FONT_SIZE = 14;
const COLUMN_WIDTH = 20;
const CHARACTERS = '01';
const PRIMARY_COLOR = '#00D084';
const DIM_COLOR = '#006644';

/** Decorative falling-bits canvas behind the login panel. */
export function MatrixBackground({ opacity = 0.5, frameInterval = 16 }: MatrixBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext('2d');
    if (!canvas || !context) return;

    let columns: number[] = [];
    let lastFrameTime = 0;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      // Stagger the starts above the viewport so columns do not fall in lockstep.
      columns = Array.from({ length: Math.floor(canvas.width / COLUMN_WIDTH) }, () =>
        Math.floor(Math.random() * -100)
      );
    };

    const draw = (timestamp: number) => {
      animationRef.current = requestAnimationFrame(draw);
      if (timestamp - lastFrameTime < frameInterval) return;
      lastFrameTime = timestamp;

      // Fade the previous frame rather than clearing it: that is the trail.
      context.fillStyle = 'rgba(0, 0, 0, 0.05)';
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.font = `${FONT_SIZE}px "JetBrains Mono", monospace`;

      for (let i = 0; i < columns.length; i++) {
        const y = columns[i] * FONT_SIZE;
        const char = CHARACTERS[Math.floor(Math.random() * CHARACTERS.length)];

        context.fillStyle = PRIMARY_COLOR;
        context.fillText(char, i * COLUMN_WIDTH, y);
        if (Math.random() > 0.98) {
          context.fillStyle = DIM_COLOR;
          context.fillText(char, i * COLUMN_WIDTH, y - FONT_SIZE);
        }

        columns[i]++;
        if (y > canvas.height && Math.random() > 0.975) columns[i] = 0;
      }
    };

    resize();
    window.addEventListener('resize', resize);
    animationRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationRef.current);
    };
  }, [frameInterval]);

  return (
    <canvas ref={canvasRef} className="matrix-canvas" aria-hidden="true" style={{ opacity }} />
  );
}
