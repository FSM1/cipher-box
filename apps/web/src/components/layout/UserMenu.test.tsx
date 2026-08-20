import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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

  it('offers the recovery phrase while the account carries no factor policy', async () => {
    renderMenu();
    // The policy is read off the signed-in account, so the session lands first.
    await screen.findByText('user@example.test');

    fireEvent.click(screen.getByRole('button', { expanded: false }));

    expect(screen.getByTestId('recovery-setup-open')).not.toBeNull();
    expect(screen.queryByTestId('recovery-enrolled')).toBeNull();
  });

  it('stops offering it once the account carries one', async () => {
    renderMenu({ enrolled: true });
    await screen.findByText('user@example.test');

    fireEvent.click(screen.getByRole('button', { expanded: false }));

    await waitFor(() => expect(screen.getByTestId('recovery-enrolled')).not.toBeNull());
    // Offering it again would enroll a second time over a live policy.
    expect(screen.queryByTestId('recovery-setup-open')).toBeNull();
  });

  it('names a session that carries no email, as a wallet login does', () => {
    renderMenu({ email: null });

    expect(screen.getByTestId('user-menu').textContent).toContain('[an0n]');
  });
});
