import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';
import { UserMenu } from './UserMenu';
import { authStore } from '../../stores/auth.store';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../../test/authFakes';

function renderMenu() {
  const Providers = pageWrapper(fakeEngineClient().client, fakeCoreKitSession().session);
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
    authStore.signedIn('google', 'user@example.test');
    renderMenu();

    fireEvent.click(screen.getByRole('button', { expanded: false }));
    const logout = screen.getByTestId('logout-button');

    fireEvent.keyDown(logout, { key: 'Escape' });

    expect(screen.queryByTestId('logout-button')).toBeNull();
  });

  it('names a wallet login that carries no email', () => {
    authStore.signedIn('wallet', null);
    renderMenu();

    expect(screen.getByTestId('user-menu').textContent).toContain('[an0n]');
  });
});
