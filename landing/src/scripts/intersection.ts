/**
 * Observe elements and trigger canvas animations when they scroll into view.
 * Returns a cleanup function.
 */
export function observeCanvasAnimations(): () => void {
  const canvases = document.querySelectorAll<HTMLCanvasElement>('[data-animate-canvas]');
  const activeAnimations = new Map<HTMLCanvasElement, number>();

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        const canvas = entry.target as HTMLCanvasElement;
        if (entry.isIntersecting) {
          canvas.dataset.visible = 'true';
          canvas.dispatchEvent(new CustomEvent('canvas:enter'));
        } else {
          canvas.dataset.visible = 'false';
          canvas.dispatchEvent(new CustomEvent('canvas:leave'));
        }
      }
    },
    { threshold: 0.15 }
  );

  canvases.forEach((canvas) => observer.observe(canvas));

  return () => {
    observer.disconnect();
    activeAnimations.forEach((id) => cancelAnimationFrame(id));
  };
}
