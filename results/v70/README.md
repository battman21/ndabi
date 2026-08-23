# NDABI Supabase batch-session performance v7.0 results

`validation_suite_v70.py` writes formal JSON evidence here.

The campaign compares one NDABI batch instruction with repeated PostgREST requests.
It executes one prepared PostgreSQL query per NDABI batch.
It retains ES256 admission, forced RLS, exactness, replay, receipt, and repeatability gates.
