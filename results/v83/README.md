# NDABI Supabase cumulative CPU campaign v8.3

No v8.3 performance result is accepted.

The candidate adds an exact fixed-buffer encoder for complete indexed results.
It retains the previous small-write encoder as a direct control.
It measures client process CPU and cumulative container CPU during the measured interval.

Functional smoke `20260824T231018Z` passed exact results and all seventeen security checks.
Its three samples per worker do not qualify for a performance claim.

The first duration-qualified smoke produced no benchmark result.
The host did not reach the frozen 80% idle threshold within five minutes.
Cargo and Rust compiler processes were active after the refusal.
Do not lower the gate or interpret the functional timings as performance evidence.
