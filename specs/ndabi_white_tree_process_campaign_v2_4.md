# NDABI White Tree process campaign v2.4

**Status:** FROZEN before the first v2.4 result. **Date:** 2026-08-22.

The v2.2 and v2.3 campaigns remain failed and immutable.
Both campaigns repeated a large SQL-layer cost but failed one fast-path p95 distance gate.

## 1. Fixed campaign

Run the archived v2.3 release binary in five independent processes.
Use binary SHA-256 `954e828ed9e20f03f04fe52e714ccdbeddd76f6a17ea35a03e38022dd15aae36`.

Store each complete JSON result before aggregation.
Require one source fingerprint, database root, canonical response digest, and response length.

The v2.3 binary can exit with status one when its local performance gate fails.
Accept that status only when the complete JSON result exists and every correctness gate passed.

## 2. Aggregate method

Take the median of the five process p95 values for each arm.
Calculate campaign ratios from those arm medians.
Report every process ratio and its population coefficient of variation.

## 3. Hard gates

- All five processes must pass literal semantic equality and every frame refusal.
- All five processes must bind one database root and canonical response digest.
- Governed SQL must be at least 2.5 times slower than session NDABI.
- Session NDABI must be no more than 10% slower than native typed.
- Full NDABI must be no more than 50% slower than session NDABI.
- Native typed and direct-repeat must remain within 10%.
- The five session-native ratios must have a coefficient of variation below 20%.

## 4. Boundary

This campaign measures process repeatability on macOS.
It does not replace the required physical Linux campaigns.
