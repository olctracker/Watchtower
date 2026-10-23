// Watchtower — sites being monitored.
// Publishable keys are safe to be public. Never put a secret key here.
// To watch another site later, add another entry to `sites` (its Supabase
// project needs the same setup.sql run on it).
window.WATCH_CONFIG = {
  version: "1.1.0",
  sites: [
    {
      id: "olc",
      name: "OLC Database",
      supabaseUrl: "https://unypqibobllpxsbmzcin.supabase.co",
      supabaseKey: "sb_publishable_whz02drJkVIc6fAXXj8Mew_3QHmjOaf",
      // Watchtower's own accounts (separate from OLC Database's)
      emailFor: (u) => `${u.trim().toLowerCase()}@watch.olcdatabase.app`,
      pwFor: (pin) => `watch#${pin}#pin`
    }
  ]
};
