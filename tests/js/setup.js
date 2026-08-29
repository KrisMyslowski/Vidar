/* Node 26 ships its own experimental `localStorage` global, which shadows the
 * one jsdom provides and stays undefined unless node is started with
 * --localstorage-file. Install a minimal in-memory Storage so the column-picker
 * tests exercise the real persistence path rather than the module's
 * storage-unavailable fallback. */
if (typeof window !== 'undefined' && !window.localStorage) {
  const store = new Map();
  const storage = {
    getItem: (k) => (store.has(String(k)) ? store.get(String(k)) : null),
    setItem: (k, v) => store.set(String(k), String(v)),
    removeItem: (k) => store.delete(String(k)),
    clear: () => store.clear(),
    key: (i) => [...store.keys()][i] ?? null,
    get length() {
      return store.size;
    },
  };
  // Both spellings: the module under test says `localStorage`, which resolves
  // to the global, and the tests address `window.localStorage`.
  Object.defineProperty(window, 'localStorage', { value: storage, configurable: true });
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true });
}
