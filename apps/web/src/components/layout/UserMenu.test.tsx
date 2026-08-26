import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';
import { UserMenu } from './UserMenu';
import { authStore } from '../../stores/auth.store';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../../test/authFakes';

/** A tab whose Core Kit session outlived the page, as a reload leaves one. */
function renderMenu({
  enrolled = false,
  email = 'user@example.test',
}: { enrolled?: boolean; email?: string | null } = {}) {
  const Providers = pageWrapper(
    fakeEngineClient().client,
    fakeCoreKitSession({ loggedIn: true, enrolled, email: () => email }).session
  );
  return render(
    <Providers>
      <MemoryRouter>
        <UserMenu />
      </MemoryRouter>
    </Providers>
  );
}

afterEach(() => authStore.signedOut());

describe('UserMenu', () => {
  it('closes on Escape pressed inside the dropdown, not just on the trigger', () => {
    renderMenu();

    fireEvent.click(screen.getByRole('button', { expanded: false }));
    const logout = screen.getByTestId('logout-button');

    fireEvent.keyDown(logout, { key: 'Escape' });

    expect(screen.queryByTestId('logout-button')).toBeNull();
  });

  it('sends the account surfaces to the settings route rather than hosting them', () => {
    renderMenu();

    fireEvent.click(screen.getByRole('button', { expanded: false }));

    expect(screen.getByTestId('user-menu-settings').getAttribute('href')).toBe('/settings');
  });

  it('names a session that carries no email, as a wallet login does', () => {
    renderMenu({ email: null });

    expect(screen.getByTestId('user-menu').textContent).toContain('[an0n]');
  });
});
