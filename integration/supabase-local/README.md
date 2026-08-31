# Full Supabase local proof

This fixture starts the complete local Supabase development stack on dedicated ports.
It runs the NDABI bundle integration test against Supabase PostgreSQL and forced row-level security.

Run `python3 integration/supabase-local/prove.py` from the repository root.
The script preserves an existing stack. It stops only the stack that it starts.
The test uses local development credentials only.
