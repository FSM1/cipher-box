import { useEffect, useRef } from 'react';

const FONT_SIZE = 14;
const COLUMN_WIDTH = 20;
const FRAME_INTERVAL_MS = 50;
const OPACITY = 0.3;
const CHARACTERS = '01';
const PRIMARY_COLOR = '#00D084';
const DIM_COLOR = '#006644';

/** Decorative falling-bits canvas behind the login panel. */
export function MatrixBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext('2d');
    if (!canvas || !context) return;

    let columns: number[] = [];
    let lastFrameTime = 0;
    let pendingResize = 0;

    const resize = () => {
      pendingResize = 0;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      // Assigning width resets the 2D state, so the font is set here, not per frame.
      context.font = `${FONT_SIZE}px "JetBrains Mono", monospace`;
      // Stagger the starts above the viewport so columns do not fall in lockstep.
      columns = Array.from({ length: Math.floor(canvas.width / COLUMN_WIDTH) }, () =>
        Math.floor(Math.random() * -100)
      );
    };

    // A drag fires resize events far faster than frames; collapse them to one.
    const onResize = () => {
      pendingResize ||= requestAnimationFrame(resize);
    };

    const draw = (timestamp: number) => {
      animationRef.current = requestAnimationFrame(draw);
      if (timestamp - lastFrameTime < FRAME_INTERVAL_MS) return;
      lastFrameTime = timestamp;

      // Fade the previous frame rather than clearing it: that is the trail.
      context.fillStyle = 'rgba(0, 0, 0, 0.05)';
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.fillStyle = PRIMARY_COLOR;

      for (let i = 0; i < columns.length; i++) {
        const y = columns[i]++ * FONT_SIZE;
        if (y > canvas.height) {
          if (Math.random() > 0.975) columns[i] = 0;
          continue;
        }

        const char = CHARACTERS[Math.floor(Math.random() * CHARACTERS.length)];
        context.fillText(char, i * COLUMN_WIDTH, y);
        if (Math.random() > 0.98) {
          context.fillStyle = DIM_COLOR;
          context.fillText(char, i * COLUMN_WIDTH, y - FONT_SIZE);
          context.fillStyle = PRIMARY_COLOR;
        }
      }
    };

    resize();
    window.addEventListener('resize', onResize);
    animationRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener('resize', onResize);
      cancelAnimationFrame(pendingResize);
      cancelAnimationFrame(animationRef.current);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="matrix-canvas"
      aria-hidden="true"
      style={{ opacity: OPACITY }}
    />
  );
}
