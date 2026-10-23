# Watchtower

Login traffic monitor for OLC Database. Shows who signed in, failed and locked-out attempts, each member's IPs and signed-in devices, and an IP location lookup. Its own accounts (10-digit PIN); the first account is Admin and approves everyone else.

Setup: run the files in `sql/` in order in the Supabase SQL Editor, then publish with GitHub Pages. To watch another site later, add it to `config.js` and run the `sql/` files on its project.
