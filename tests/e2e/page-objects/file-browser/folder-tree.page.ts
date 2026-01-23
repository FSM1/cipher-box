import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for FolderTree sidebar component interactions.
 *
 * Encapsulates folder tree navigation, expansion, and interaction.
 * Uses semantic selectors for maintainability.
 */
export class FolderTreePage {
  constructor(private readonly page: Page) {}

  /**
   * Get the folder tree container.
   */
  treeContainer(): Locator {
    return this.page.locator('.folder-tree');
  }

  /**
   * Get all folder node items in the tree.
   */
  folderNodes(): Locator {
    return this.page.locator('.folder-tree-item');
  }

  /**
   * Get a specific folder by name.
   * Uses the folder name text to locate.
   */
  getFolder(name: string): Locator {
    return this.page.locator('.folder-tree-item', { hasText: name }).filter({
      has: this.page.locator('.folder-tree-name', { hasText: name }),
    });
  }

  /**
   * Click a folder to navigate to it.
   */
  async clickFolder(name: string): Promise<void> {
    await this.getFolder(name).click();
  }

  /**
   * Expand a collapsed folder to reveal children.
   */
  async expandFolder(name: string): Promise<void> {
    const folder = this.getFolder(name);
    const toggle = folder.locator('.folder-tree-toggle');

    // Check if folder has children (toggle visible)
    const hasToggle = await toggle.isVisible();
    if (!hasToggle) {
      return; // No children, nothing to expand
    }

    // Check if already expanded (toggle shows ▼)
    const toggleText = await toggle.textContent();
    if (toggleText?.includes('▼')) {
      return; // Already expanded
    }

    // Click toggle to expand
    await toggle.click();
  }

  /**
   * Collapse an expanded folder to hide children.
   */
  async collapseFolder(name: string): Promise<void> {
    const folder = this.getFolder(name);
    const toggle = folder.locator('.folder-tree-toggle');

    // Check if folder has children (toggle visible)
    const hasToggle = await toggle.isVisible();
    if (!hasToggle) {
      return; // No children, nothing to collapse
    }

    // Check if already collapsed (toggle shows ▶)
    const toggleText = await toggle.textContent();
    if (toggleText?.includes('▶')) {
      return; // Already collapsed
    }

    // Click toggle to collapse
    await toggle.click();
  }

  /**
   * Check if a folder is expanded.
   */
  async isFolderExpanded(name: string): Promise<boolean> {
    const folder = this.getFolder(name);
    const toggle = folder.locator('.folder-tree-toggle');

    // If no toggle, folder has no children
    const hasToggle = await toggle.isVisible();
    if (!hasToggle) {
      return false;
    }

    const toggleText = await toggle.textContent();
    return toggleText?.includes('▼') ?? false;
  }

  /**
   * Check if a folder is currently selected/active.
   */
  async isFolderSelected(name: string): Promise<boolean> {
    const folder = this.getFolder(name);
    const className = await folder.getAttribute('class');
    return className?.includes('folder-tree-item--active') ?? false;
  }

  /**
   * Get all visible folder names in the tree.
   * Only returns folders that are currently visible (expanded parents).
   */
  async getVisibleFolderNames(): Promise<string[]> {
    const folders = this.folderNodes();
    const count = await folders.count();
    const names: string[] = [];

    for (let i = 0; i < count; i++) {
      const folderItem = folders.nth(i);
      const isVisible = await folderItem.isVisible();

      if (isVisible) {
        const nameText = await folderItem.locator('.folder-tree-name').textContent();
        if (nameText) {
          names.push(nameText);
        }
      }
    }

    return names;
  }

  /**
   * Wait for a folder to appear in the tree.
   * Useful after folder creation or parent expansion.
   */
  async waitForFolderToAppear(name: string, options?: { timeout?: number }): Promise<void> {
    await this.getFolder(name).waitFor({ state: 'visible', ...options });
  }

  /**
   * Check if the tree is showing the "Vault not initialized" placeholder.
   */
  async isVaultNotInitialized(): Promise<boolean> {
    return await this.page
      .locator('.folder-tree-placeholder', { hasText: 'Vault not initialized' })
      .isVisible();
  }

  /**
   * Check if the tree is showing the "Loading folders..." placeholder.
   */
  async isLoading(): Promise<boolean> {
    return await this.page
      .locator('.folder-tree-placeholder', { hasText: 'Loading folders...' })
      .isVisible();
  }

  /**
   * Get the drop target element for a folder.
   * Used for drag-drop operations.
   */
  getDropTarget(name: string): import('@playwright/test').Locator {
    return this.getFolder(name);
  }

  /**
   * Simulate dropping an item onto a folder in the tree.
   * This is used for move operations via drag-drop.
   *
   * @param targetFolderName - Name of the folder to drop onto
   * @param dragData - JSON data representing the dragged item
   */
  async dropOnFolder(
    targetFolderName: string,
    dragData: { id: string; type: 'file' | 'folder'; parentId: string }
  ): Promise<void> {
    const targetFolder = this.getDropTarget(targetFolderName);

    // Ensure target is visible
    await targetFolder.waitFor({ state: 'visible' });

    // Get bounding box for drop location
    const box = await targetFolder.boundingBox();
    if (!box) throw new Error(`Could not get bounding box for folder ${targetFolderName}`);

    // Calculate center of target
    const centerX = box.x + box.width / 2;
    const centerY = box.y + box.height / 2;

    // Dispatch all drag events inside page.evaluate to avoid DataTransfer construction issues
    // Playwright's dispatchEvent doesn't fully support DataTransfer objects
    await this.page.evaluate(
      ({ folderName, data, x, y }) => {
        // Find the folder by looking for the name element with matching text
        const nameElements = document.querySelectorAll('.folder-tree-name');
        let target: Element | null = null;

        for (const nameEl of nameElements) {
          if (nameEl.textContent?.trim() === folderName) {
            // Get the parent folder-tree-item
            target = nameEl.closest('.folder-tree-item');
            break;
          }
        }

        if (!target) throw new Error(`Drop target folder "${folderName}" not found`);

        // Create mock dataTransfer object
        const mockDataTransfer = {
          getData: (type: string) => (type === 'application/json' ? JSON.stringify(data) : ''),
          types: ['application/json'],
          effectAllowed: 'move',
          dropEffect: 'move',
        };

        // Helper to create drag event with mock dataTransfer
        const createDragEvent = (type: string) => {
          const event = new DragEvent(type, {
            bubbles: true,
            cancelable: true,
            clientX: x,
            clientY: y,
          });
          Object.defineProperty(event, 'dataTransfer', { value: mockDataTransfer });
          return event;
        };

        // Dispatch dragenter, dragover, and drop events
        target.dispatchEvent(createDragEvent('dragenter'));
        target.dispatchEvent(createDragEvent('dragover'));
        target.dispatchEvent(createDragEvent('drop'));
      },
      {
        folderName: targetFolderName,
        data: dragData,
        x: centerX,
        y: centerY,
      }
    );

    // Wait a bit for the move operation to complete
    await this.page.waitForTimeout(500);
  }
}
