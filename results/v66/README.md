# NDABI Supabase user-session performance v6.6 results

`validation_suite_v66.py` writes formal JSON evidence here.

The campaign uses ephemeral ES256 keys, equal user claims, and forced PostgreSQL row-level security.
It compares one admitted NDABI session with persistent local PostgREST requests.
The runner records the installed `cryptography` version and binds its pinned requirement file.
