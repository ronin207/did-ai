import { describe, it, expect } from 'vitest';
import { makeDisclosure, digestDisclosure, parseDisclosure } from '../src/sdjwt';

describe('SD-JWT helpers', () => {
  it('creates and parses disclosure', () => {
    const disc = makeDisclosure('scope', 'calendar.read:public');
    const parsed = parseDisclosure(disc);
    expect(parsed.name).toBe('scope');
    expect(parsed.value).toBe('calendar.read:public');
  });

  it('produces stable digests for same disclosure', () => {
    const d = makeDisclosure('aud', 'https://api.example', Buffer.alloc(16, 7));
    const h1 = digestDisclosure(d);
    const h2 = digestDisclosure(d);
    expect(h1).toBe(h2);
  });
});
