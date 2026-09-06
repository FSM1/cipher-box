/**
 * Whether the shell's window is wanted, and the one call that says so.
 *
 * This shell is a menu-bar app (blueprint/desktop.md, "Lifecycle"): the window
 * is chrome shown while the session needs the member, not the app itself.
 */

import { invoke } from '@tauri-apps/api/core';
import type { ShellModel } from './frontDoor';

/** What the session asks of the window. */
export type WindowIntent = 'show' | 'hide';

/**
 * `null` is the absence of an answer rather than a third state: the window is
 * left as it stands, which is what keeps a resumed session from painting one
 * and a window opened from the tray from closing under the member.
 */
export function windowIntent(model: ShellModel): WindowIntent | null {
  // A restore has not yet said whether this device has a session, and the
  // phase it passes through on the way is not an answer about the window.
  if (model.step === 'restore') return null;
  switch (model.phase) {
    case 'signedOut':
    case 'recovery':
      return 'show';
    case 'signedIn':
      switch (model.vault?.mount.state) {
        // A refusal never fails the login, so the window is where it is read.
        case 'refused':
          return 'show';
        case 'mounted':
          return 'hide';
        default:
          return null;
      }
    case 'starting':
      return null;
  }
}

/** Shows or hides the main window; `src-tauri/src/main.rs` holds the handle. */
export function setWindowVisible(visible: boolean): void {
  void invoke('set_main_window_visible', { visible }).catch((failure: unknown) => {
    console.error('the shell could not reach its window', failure);
  });
}
