/**
 * PROTOTYPE — throwaway, for the share-dialog UI question. An in-memory stand-in for the sharing state
 * of one folder under the link-first model: many links, many people, no
 * approve step, conversion in the owner's background. No engine, no facade.
 */
import { useReducer } from 'react';

export type ProtoPermission = 'read' | 'write';
export type ProtoLifetime = '1 day' | '7 days' | '30 days' | 'never';
export const PROTO_LIFETIMES: ProtoLifetime[] = ['1 day', '7 days', '30 days', 'never'];

const DAY = 86_400_000;
const LIFETIME_DAYS: Record<ProtoLifetime, number | null> = {
  '1 day': 1,
  '7 days': 7,
  '30 days': 30,
  never: null,
};

export interface ProtoLink {
  id: string;
  label: string;
  permission: ProtoPermission;
  createdAt: number;
  expiresAt: number | null;
  expired: boolean;
}

export interface ProtoPerson {
  id: string;
  /** A display name the person chose, or a short key fingerprint. */
  label: string;
  via: 'link' | 'contact';
  /** The link that admitted them, for `via: 'link'`. */
  linkId: string | null;
  permission: ProtoPermission;
  joinedAt: number;
  /** Claimed, and the owner engine has not yet written their personal grant. */
  converting: boolean;
}

export interface ProtoContact {
  id: string;
  label: string;
}

export type ProtoConfirm = { kind: 'person' | 'link'; id: string } | null;

export interface ProtoState {
  links: ProtoLink[];
  people: ProtoPerson[];
  /** Imported contacts not yet granted on this folder. */
  contacts: ProtoContact[];
  ownContactCode: string;
  /** The just-created link; shown once, gone when hidden or the dialog closes. */
  fresh: { linkId: string; url: string } | null;
  /** A transient "someone joined" notice. */
  notice: string | null;
  confirm: ProtoConfirm;
  /** The last action, surfaced by the state panel. */
  last: string;
}

const OWN_CODE =
  'cbc1-7f3a9e2d41c08b5566e1f0a4d93b27c8e05f1a6b9d2c4e8f7a1b3c5d6e7f8091a2b3c4d5e6f7089';

let counter = 0;
const nextId = (prefix: string) => `${prefix}${++counter}`;
const fakeUrl = () =>
  `${window.location.origin}/invite#${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;

const JOINER_NAMES = ['dana', 'kofi', 'mira', 'teo', 'ines', 'jun', 'lars', 'noor'];

function makeLink(
  permission: ProtoPermission,
  lifetime: ProtoLifetime,
  now: number,
  number = 1
): ProtoLink {
  const days = LIFETIME_DAYS[lifetime];
  return {
    id: nextId('link-'),
    label: `link ${number}`,
    permission,
    createdAt: now,
    expiresAt: days === null ? null : now + days * DAY,
    expired: false,
  };
}

const EMPTY: ProtoState = {
  links: [],
  people: [],
  contacts: [{ id: 'contact-sam', label: 'sam (contact, 0x3fa1…c29e)' }],
  ownContactCode: OWN_CODE,
  fresh: null,
  notice: null,
  confirm: null,
  last: 'reset: never shared',
};

export type ProtoPreset =
  | 'empty'
  | 'one-read-link'
  | 'link-and-two-people'
  | 'just-joined'
  | 'expired-link'
  | 'confirm-revoke-person'
  | 'confirm-revoke-link'
  | 'write-link';

export const PROTO_PRESETS: { key: ProtoPreset; label: string }[] = [
  { key: 'empty', label: 'never shared' },
  { key: 'one-read-link', label: '1 read link, nobody joined' },
  { key: 'link-and-two-people', label: 'link + 2 people' },
  { key: 'just-joined', label: 'person just joined' },
  { key: 'expired-link', label: 'expired link' },
  { key: 'confirm-revoke-person', label: 'confirm revoke person' },
  { key: 'confirm-revoke-link', label: 'confirm revoke link' },
  { key: 'write-link', label: 'write link' },
];

function preset(key: ProtoPreset, now: number): ProtoState {
  const base: ProtoState = { ...EMPTY, last: `preset: ${key}` };
  switch (key) {
    case 'empty':
      return base;
    case 'one-read-link': {
      const link = makeLink('read', '7 days', now - 2 * 3_600_000);
      return { ...base, links: [link] };
    }
    case 'link-and-two-people':
    case 'confirm-revoke-person':
    case 'confirm-revoke-link':
    case 'just-joined': {
      const link = makeLink('read', '7 days', now - 2 * DAY);
      const people: ProtoPerson[] = [
        {
          id: nextId('p-'),
          label: 'dana',
          via: 'link',
          linkId: link.id,
          permission: 'read',
          joinedAt: now - DAY,
          converting: false,
        },
        {
          id: nextId('p-'),
          label: 'sam',
          via: 'contact',
          linkId: null,
          permission: 'write',
          joinedAt: now - 5 * DAY,
          converting: false,
        },
      ];
      if (key === 'just-joined') {
        people.unshift({
          id: nextId('p-'),
          label: 'kofi',
          via: 'link',
          linkId: link.id,
          permission: 'read',
          joinedAt: now,
          converting: true,
        });
      }
      const state = { ...base, links: [link], people, contacts: [] };
      if (key === 'just-joined') return { ...state, notice: `kofi joined through ${link.label}` };
      if (key === 'confirm-revoke-person')
        return { ...state, confirm: { kind: 'person', id: people[0].id } };
      if (key === 'confirm-revoke-link')
        return { ...state, confirm: { kind: 'link', id: link.id } };
      return state;
    }
    case 'expired-link': {
      const link = { ...makeLink('read', '1 day', now - 3 * DAY), expired: true };
      return {
        ...base,
        links: [link],
        people: [
          {
            id: nextId('p-'),
            label: 'dana',
            via: 'link',
            linkId: link.id,
            permission: 'read',
            joinedAt: now - 2.5 * DAY,
            converting: false,
          },
        ],
      };
    }
    case 'write-link': {
      const link = makeLink('write', '1 day', now);
      return { ...base, links: [link], fresh: { linkId: link.id, url: fakeUrl() } };
    }
  }
}

export type ProtoAction =
  | { type: 'preset'; key: ProtoPreset }
  | { type: 'create-link'; permission: ProtoPermission; lifetime: ProtoLifetime }
  | { type: 'hide-fresh' }
  | { type: 'simulate-join'; linkId?: string }
  | { type: 'ask-revoke'; kind: 'person' | 'link'; id?: string }
  | { type: 'cancel-revoke' }
  | { type: 'confirm-revoke' }
  | { type: 'expire-link'; id?: string }
  | { type: 'dismiss-notice' }
  | { type: 'import-contact'; code: string }
  | { type: 'grant-contact'; contactId: string; permission: ProtoPermission };

function live(state: ProtoState): ProtoLink[] {
  return state.links.filter((link) => !link.expired);
}

function reduce(state: ProtoState, action: ProtoAction): ProtoState {
  const now = Date.now();
  switch (action.type) {
    case 'preset':
      return preset(action.key, now);

    case 'create-link': {
      const number = state.links.length === 0 ? 1 : Number(state.links.at(-1)?.label.slice(5)) + 1;
      const link = makeLink(action.permission, action.lifetime, now, number);
      return {
        ...state,
        links: [...state.links, link],
        fresh: { linkId: link.id, url: fakeUrl() },
        last: `create link: ${link.label}, ${action.permission}, ${action.lifetime}`,
      };
    }

    case 'hide-fresh':
      return { ...state, fresh: null, last: 'hide link (it cannot be shown again)' };

    case 'simulate-join': {
      const link =
        state.links.find((entry) => entry.id === action.linkId && !entry.expired) ??
        live(state).at(-1);
      if (link === undefined) return { ...state, last: 'simulate join: no live link — nothing' };
      const taken = new Set(state.people.map((person) => person.label));
      const name = JOINER_NAMES.find((entry) => !taken.has(entry)) ?? nextId('guest-');
      // Conversion is the owner's background tick; the prototype settles
      // any earlier joiner the moment a new one arrives.
      const settled = state.people.map((person) => ({ ...person, converting: false }));
      return {
        ...state,
        people: [
          {
            id: nextId('p-'),
            label: name,
            via: 'link',
            linkId: link.id,
            permission: link.permission,
            joinedAt: now,
            converting: true,
          },
          ...settled,
        ],
        notice: `${name} joined through ${link.label}`,
        last: `simulate join: ${name} via ${link.label}`,
      };
    }

    case 'ask-revoke': {
      const id =
        action.id ??
        (action.kind === 'person'
          ? state.people[0]?.id
          : (live(state)[0]?.id ?? state.links[0]?.id));
      if (id === undefined) return { ...state, last: `revoke ${action.kind}: nothing to revoke` };
      return { ...state, confirm: { kind: action.kind, id }, last: `ask revoke ${action.kind}` };
    }

    case 'cancel-revoke':
      return { ...state, confirm: null, last: 'cancel revoke' };

    case 'confirm-revoke': {
      const confirm = state.confirm;
      if (confirm === null) return state;
      if (confirm.kind === 'link') {
        return {
          ...state,
          links: state.links.filter((link) => link.id !== confirm.id),
          fresh: state.fresh?.linkId === confirm.id ? null : state.fresh,
          confirm: null,
          last: `revoke link ${confirm.id}; people who joined keep access`,
        };
      }
      const person = state.people.find((entry) => entry.id === confirm.id);
      // Decided rule: revoking a link-admitted person also revokes that link.
      const linkGone = person?.linkId ?? null;
      return {
        ...state,
        people: state.people.filter((entry) => entry.id !== confirm.id),
        links: linkGone === null ? state.links : state.links.filter((link) => link.id !== linkGone),
        fresh: linkGone !== null && state.fresh?.linkId === linkGone ? null : state.fresh,
        confirm: null,
        last: `revoke ${person?.label ?? 'person'}${linkGone === null ? '' : ` and ${linkGone}`}`,
      };
    }

    case 'expire-link': {
      const target = state.links.find((link) => link.id === action.id) ?? live(state)[0];
      if (target === undefined) return { ...state, last: 'expire link: no live link' };
      return {
        ...state,
        links: state.links.map((link) =>
          link.id === target.id ? { ...link, expired: true, expiresAt: now } : link
        ),
        fresh: state.fresh?.linkId === target.id ? null : state.fresh,
        last: `expire ${target.label}`,
      };
    }

    case 'dismiss-notice':
      return { ...state, notice: null, last: 'dismiss notice' };

    case 'import-contact': {
      const trimmed = action.code.trim();
      if (trimmed === '') return { ...state, last: 'import contact: empty code' };
      const contact = { id: nextId('contact-'), label: `contact ${trimmed.slice(0, 10)}…` };
      return {
        ...state,
        contacts: [...state.contacts, contact],
        last: `import contact: ${contact.label}`,
      };
    }

    case 'grant-contact': {
      const contact = state.contacts.find((entry) => entry.id === action.contactId);
      if (contact === undefined) return state;
      return {
        ...state,
        contacts: state.contacts.filter((entry) => entry.id !== contact.id),
        people: [
          {
            id: nextId('p-'),
            label: contact.label.split(' (')[0],
            via: 'contact',
            linkId: null,
            permission: action.permission,
            joinedAt: now,
            converting: false,
          },
          ...state.people,
        ],
        last: `grant ${action.permission} to ${contact.label}`,
      };
    }
  }
}

export function useSharePrototypeStore() {
  return useReducer(reduce, undefined, () => preset('empty', Date.now()));
}

export function protoAgo(at: number): string {
  const minutes = Math.round((Date.now() - at) / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}

export function protoExpiry(link: ProtoLink): string {
  if (link.expired) return 'expired';
  if (link.expiresAt === null) return 'never expires';
  const days = Math.ceil((link.expiresAt - Date.now()) / DAY);
  return days <= 1 ? 'expires in < 1 day' : `expires in ${days} d`;
}

export function protoLinkLabel(state: ProtoState, linkId: string | null): string {
  return state.links.find((link) => link.id === linkId)?.label ?? 'a revoked link';
}

/** Who a person revoke would also cut off, for the confirm copy. */
export function protoRevokeImpact(state: ProtoState, confirm: NonNullable<ProtoConfirm>) {
  if (confirm.kind === 'link') {
    const link = state.links.find((entry) => entry.id === confirm.id);
    const joined = state.people.filter((person) => person.linkId === confirm.id);
    return {
      title: `revoke ${link?.label ?? 'link'}?`,
      lines: [
        'nobody new can join with this link.',
        joined.length === 0
          ? 'nobody joined through it.'
          : `${joined.map((person) => person.label).join(', ')} joined through it and keep access.`,
      ],
    };
  }
  const person = state.people.find((entry) => entry.id === confirm.id);
  const link = state.links.find((entry) => entry.id === person?.linkId);
  const others = state.people.filter(
    (entry) => entry.linkId !== null && entry.linkId === person?.linkId && entry.id !== person?.id
  );
  const lines = [`${person?.label ?? 'this person'} loses access to this folder.`];
  if (link !== undefined) {
    lines.push(`${link.label} admitted them, so ${link.label} is revoked too.`);
    lines.push(
      others.length === 0
        ? 'nobody else joined through it.'
        : `${others.map((entry) => entry.label).join(', ')} joined through it and keep access.`
    );
  }
  return { title: `revoke ${person?.label ?? 'person'}?`, lines };
}

export type ProtoDispatch = (action: ProtoAction) => void;
