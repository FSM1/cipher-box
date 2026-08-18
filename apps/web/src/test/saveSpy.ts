/**
 * Records how a save left the tab. The two routes are kept apart because which
 * one a ticket takes is what a save turns on: a link's request never reaches
 * the Service Worker, so a ticket handed to one fetches the app shell.
 */
export interface SaveSpy {
  /** Every link the hook clicked, in order. */
  readonly clicked: { href: string | null; download: string }[];
  /** Every frame it navigated, by `src`. */
  readonly navigated: (string | null)[];
  /** The frames themselves, for a test that watches when one is dropped. */
  readonly frames: HTMLIFrameElement[];
  restore(): void;
}

export function trackSaves(): SaveSpy {
  const clicked: { href: string | null; download: string }[] = [];
  const navigated: (string | null)[] = [];
  const frames: HTMLIFrameElement[] = [];
  const originalClick = HTMLAnchorElement.prototype.click;
  const originalAppend = HTMLElement.prototype.append;

  HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
    clicked.push({ href: this.getAttribute('href'), download: this.download });
  };
  HTMLElement.prototype.append = function append(this: HTMLElement, ...nodes: unknown[]) {
    for (const node of nodes) {
      if (node instanceof HTMLIFrameElement) {
        navigated.push(node.getAttribute('src'));
        frames.push(node);
      }
    }
    return originalAppend.apply(this, nodes as Parameters<typeof originalAppend>);
  } as typeof HTMLElement.prototype.append;

  return {
    clicked,
    navigated,
    frames,
    restore() {
      HTMLAnchorElement.prototype.click = originalClick;
      HTMLElement.prototype.append = originalAppend;
    },
  };
}
