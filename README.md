# NDABI showdown

This prototype compares four database bindings and four application-state bindings.
It separates readable interfaces, tuned JSON, NDABI wire and NDABI local work.

The separate v0.6 executable tests a prepared transition kernel, canonical event receipts, and
stateful control frames. It does not change the frozen v0.5 executable or result schema.

The v0.7 campaign removes the mutable v0.5 performance baseline. Its default-scheduler run failed.
The final v0.8 QoS campaign also failed. The v0.9 paired campaign passed all local gates.

The v1.0 scale campaign passed 12 registered cases from 512 to 1,000,000 records. It covered point,
filter, aggregate, and temporal queries with result budgets through 1 MiB.

The v1.1 campaign equalised CBOR and NDABI frame integrity. It failed measurement calibration and
was not rerun. The corrected v1.2 campaign passed all 12 cases with the unchanged v1.1 binary.

The v1.2 result does not prove that a custom NDABI frame is the best encoding. Protected CBOR used
fewer bytes. NDABI was faster on small point queries and approximately equal on large scans.

The frozen v1.3 Docker campaign ran 36 Linux ARM64 containers. It failed because five point-query
processes exceeded the one-percent calibration limit. Every registered speed and repeatability
check passed, but the failed calibration prevents an accepted performance claim.

The corrected v1.4 campaign passed all 36 process, calibration, and complete-path speed gates.
NDABI measured 8.21 to 8.62 times faster than stateless JSON on point queries. The campaign still
failed because eight secondary causal ratios exceeded its ten-percent repeatability gate.

The v1.5 diagnostic located the remaining framing costs. The v1.6 and v1.7 fused-view campaigns
passed their speed targets but missed the strict point-distance gate.

The v1.8 campaign passed its implemented gate, but its cross-arm payload proof compared hashes.
The v1.9 campaign corrected this defect and compared complete payload vectors.

The v1.9 session-bound campaign passed every frozen gate across nine Linux ARM64 processes.
It measured 12.42 times JSON speed and 1.51 times full-NDABI speed for the point case.
It measured 1.24 to 1.26 times full-NDABI speed for large results.

The v2.1 stress campaign passed 90 Linux ARM64 protocol processes.
The v2.4 signed White Tree campaign passed five independent macOS processes.
Session NDABI measured 307.38 times governed SQL and remained 6.12% from native typed execution.

The v2.6 PostgreSQL campaign failed its speed gates.
Simple SQL was only 2.12% slower than session NDABI.
The result prevents a general database-speed claim.

The v3.2 PostgreSQL column-batch campaign passed every frozen aggregate gate across five processes.
Batch-32 p95 measured 24.35 times sequential prepared execution and 2.25% above native set execution.
Batch-128 p95 measured 71.11 times sequential prepared execution and 0.58% above native set execution.
The borrowed decoder recorded zero allocations, and every result and receipt remained byte-identical.

The v4.5 White Tree campaign uses one backend-neutral session for White Tree and PostgreSQL.
It passed five processes with 41.09% request compression and 8.79% lower median p95 than equal-security JSON.

The v4.6 persistent TLS 1.3 campaign passed five processes.
NDABI loopback p95 was 2.93% to 34.91% lower than JSON.
Both surfaces converged near 7.6 milliseconds after a controlled five-millisecond server delay.

The v4.7 MongoDB 8.0 campaign failed because the engine refused Docker Desktop's Linux kernel.
The v4.8 repair failed because rotating identifiers changed result identities.
The corrected v4.9 MongoDB 6.0.26 campaign passed five processes with 73.97% request compression.

The v5.3 MongoDB fused-batch campaign failed its native-distance and raw-BSON allocation gates.
The audits rejected v5.4 to v5.6 because their evidence or harness closure was incomplete.
The v5.7 final harness passed every frozen gate with one million documents and five processes.
Request compression measured 78.10% to 78.41% against equal-security JSON.
Batch-32 p95 measured 22.65 times sequential JSON and 1.142 times native set execution.
Batch-128 p95 measured 55.20 times sequential JSON and 0.979 times native set execution.
The batch-128 typed path allocated 0.47% more bytes than native set execution.
Every process compared complete bytes twice and observed one `find` with zero `getMore` commands.
Every process passed eight refusals, and the harness removed its temporary container.
The batch-one result was approximately equal, so operation fusion produced the large gain.

The v5.0 Supabase-compatible binding passed five processes.
It proved trusted NDABI PostgreSQL reads and PostgREST JWT row scope.
The v5.8 canonical binding passed five processes with stronger protocol and database identity controls.
It used a least-privilege read-only service role and forced row-level security.
Valid user identities returned only their rows.
Absent, changed, expired, and unsigned tokens refused.
The v6.0 canonical MongoDB binding passed five fresh processes against digest-pinned MongoDB 6.0.26.
Each process returned 128 exact rows through one `find`, zero `getMore`, and three early refusals.
The dedicated application user had read-only database authority.
The v6.3 canonical PostgreSQL batch campaign passed five fresh processes.
Median p95 speedup measured 25.75 times for 32 operations and 73.99 times for 128 operations.
Request bytes fell 84.38% and 86.72%.
Median CPU speedup measured 21.54 times and 47.47 times.
Minimum allocation reductions measured 88.61% and 90.77%.
The v5.2 write campaign passed five processes after binding backend access class to authority class.

The v0.1 RFC candidate freezes the implemented single and homogeneous-batch read frames.
The committed public vectors include valid frames, invalid frames, receipts, and replay sequences.
An independent Go decoder decodes both valid frames and rejects every single-bit mutation.
This agreement establishes cross-language wire interoperability, not production readiness.

The frozen v0.9 contract is [`../../specs/ndabi_poc_preregistration_v0_9.md`](../../specs/ndabi_poc_preregistration_v0_9.md).
The frozen v1.0 contracts are [`../../specs/ndabi_poc_preregistration_v1_0.md`](../../specs/ndabi_poc_preregistration_v1_0.md)
and [`../../specs/ndabi_poc_scale_campaign_v1_0.md`](../../specs/ndabi_poc_scale_campaign_v1_0.md).
The failed v1.1 contract is [`../../specs/ndabi_poc_measurement_campaign_v1_1.md`](../../specs/ndabi_poc_measurement_campaign_v1_1.md).
The corrected v1.2 contract is [`../../specs/ndabi_poc_measurement_campaign_v1_2.md`](../../specs/ndabi_poc_measurement_campaign_v1_2.md).
The failed v1.3 Docker contract is [`../../specs/ndabi_poc_docker_campaign_v1_3.md`](../../specs/ndabi_poc_docker_campaign_v1_3.md).
The next test sequence and rubric are [`../../specs/ndabi_performance_plan_v0_1.md`](../../specs/ndabi_performance_plan_v0_1.md).
The failed v1.4 contract is [`../../specs/ndabi_poc_stack_campaign_v1_4.md`](../../specs/ndabi_poc_stack_campaign_v1_4.md).
The failed v1.5 diagnostic is [`../../specs/ndabi_poc_phase_profile_v1_5.md`](../../specs/ndabi_poc_phase_profile_v1_5.md).
The failed v1.6 and v1.7 contracts are [`../../specs/ndabi_poc_fused_view_campaign_v1_6.md`](../../specs/ndabi_poc_fused_view_campaign_v1_6.md)
and [`../../specs/ndabi_poc_fixed_frame_campaign_v1_7.md`](../../specs/ndabi_poc_fixed_frame_campaign_v1_7.md).
The invalidated v1.8 contract is [`../../specs/ndabi_poc_session_bound_campaign_v1_8.md`](../../specs/ndabi_poc_session_bound_campaign_v1_8.md).
The accepted v1.9 contract is [`../../specs/ndabi_poc_literal_lossless_campaign_v1_9.md`](../../specs/ndabi_poc_literal_lossless_campaign_v1_9.md).
The stack analysis is [`../../specs/ndabi_stack_compression_research_v0_1.md`](../../specs/ndabi_stack_compression_research_v0_1.md).
The implemented core contracts are [`../../specs/ndabi_core_protocol_v0_2.md`](../../specs/ndabi_core_protocol_v0_2.md)
and [`../../specs/ndabi_column_batch_profile_v0_1.md`](../../specs/ndabi_column_batch_profile_v0_1.md).
The accepted PostgreSQL batch contract is [`../../specs/ndabi_postgresql_column_batch_campaign_v3_2.md`](../../specs/ndabi_postgresql_column_batch_campaign_v3_2.md).
The failed MongoDB fusion contract is [`../../specs/ndabi_mongodb_fused_batch_campaign_v5_3.md`](../../specs/ndabi_mongodb_fused_batch_campaign_v5_3.md).
The diagnostic MongoDB single-batch contract is [`../../specs/ndabi_mongodb_single_batch_campaign_v5_4.md`](../../specs/ndabi_mongodb_single_batch_campaign_v5_4.md).
The accepted closed MongoDB contract is [`../../specs/ndabi_mongodb_final_harness_campaign_v5_7.md`](../../specs/ndabi_mongodb_final_harness_campaign_v5_7.md).
The replay contract is [`../../specs/ndabi_replay_state_profile_v0_1.md`](../../specs/ndabi_replay_state_profile_v0_1.md).
The frozen v0.8 contract is [`../../specs/ndabi_poc_preregistration_v0_8.md`](../../specs/ndabi_poc_preregistration_v0_8.md).
The frozen v0.7 contract is [`../../specs/ndabi_poc_preregistration_v0_7.md`](../../specs/ndabi_poc_preregistration_v0_7.md).
The frozen v0.6 contract is [`../../specs/ndabi_poc_preregistration_v0_6.md`](../../specs/ndabi_poc_preregistration_v0_6.md).
The frozen v0.5 contract is [`../../specs/ndabi_poc_preregistration_v0_5.md`](../../specs/ndabi_poc_preregistration_v0_5.md).
The [v0.4 contract](../../specs/ndabi_poc_preregistration_v0_4.md) remains frozen.
The [v0.3 contract](../../specs/ndabi_poc_preregistration_v0_3.md) remains frozen.
The [v0.2 contract](../../specs/ndabi_poc_preregistration_v0_2.md) remains frozen.
The original v0.1 result remains governed by its [frozen contract](../../specs/ndabi_showdown_preregistration_v0_1.md).

## Run the visual laboratory

```sh
./run.sh
```

Open the printed loopback URL. Select a fixture size and iteration count. Then select **Run showdown**.
The laboratory stores the latest complete result in `results/latest.json`.
Select **Download JSON** to save a named copy.

The interface displays confidence intervals, wall latency, thread CPU, memory attribution, and receipt ablation.
It also displays the v0.6 architectural showdown and its separate evidence boundaries.

## Run the deterministic parser mutation campaign

```sh
cargo run --release --bin ndabi_fuzz_v01 -- --cases 100000 --seed 5639704201831827034
```

The default campaign exercises the core v1.0, core v1.1, and column v1.2 parsers.
It tests random frames, mutations of authenticated frames, replay, expiry, and monotonic nonce transitions.
It does not replace coverage-guided fuzzing or a sustained sanitiser campaign.

## Run the optional model canary

```sh
python3 token_canary.py --provider all
```

The canary uses installed subscription CLIs for Claude, Codex, and Grok.
It never uses an API key.
It stores provider-reported evidence in `results/token-canary.json`.
The loopback server reads this file but cannot invoke a model.

## Run the repeatability suite

```sh
python3 validation_suite.py
python3 validation_suite_v06.py
python3 validation_suite_v07.py
python3 validation_suite_v08.py
python3 validation_suite_v09.py
python3 validation_suite_v12.py
python3 validation_suite_v13.py
python3 validation_suite_v14.py
python3 validation_suite_v15.py
python3 validation_suite_v16.py
python3 validation_suite_v17.py
python3 validation_suite_v18.py
python3 validation_suite_v19.py
python3 validation_suite_v20.py
python3 validation_suite_v21.py
python3 validation_suite_v24.py
python3 validation_suite_v26.py
python3 validation_suite_v33.py
python3 validation_suite_v34.py
python3 validation_suite_v35.py
```

The legacy suites run four default measurements. Each suite refuses a source change during its run.
The v0.7 and v0.8 campaigns run 30 independent processes and store immutable raw evidence.
The v1.2 campaign runs 12 bounded scale cases and stores each raw result exclusively.
The v1.3 campaign runs three contained Linux processes for each v1.2 case.
The v1.4 campaign uses the corrected timer control and complete-path speed gates.
The v1.5 campaign profiles individual phases.
The v1.6 to v1.9 campaigns test fused local result views, prepared sessions, and literal losslessness.
The v2.0 and v2.1 campaigns stress the frozen v1.9 image across 90 processes.
The v2.4 campaign tests signed White Tree databases.
The v2.6 campaign starts and removes an ephemeral PostgreSQL container.

Build its local Docker image before the first run:

```sh
docker build --file docker/Dockerfile.v13 --tag ndabi-showdown:v1.3-local ../..
python3 validation_suite_v13.py
docker build --file docker/Dockerfile.v14 --tag ndabi-showdown:v1.4-local ../..
python3 validation_suite_v14.py
docker build --file docker/Dockerfile.v19 --tag ndabi-showdown:v1.9-local ../..
python3 validation_suite_v19.py
docker build --file docker/Dockerfile.v33 --tag ndabi-showdown:v3.3-local ../..
python3 validation_suite_v33.py
docker build --file docker/Dockerfile.v34 --tag ndabi-showdown:v3.4-local ../..
python3 validation_suite_v34.py
docker build --file docker/Dockerfile.v35 --tag ndabi-showdown:v3.5-local ../..
python3 validation_suite_v35.py
```

## Run without the browser

```sh
cargo run --release -- --rows 4096 --iterations 2000 --warmup 100 > result.json
cargo run --release --bin ndabi-v06 -- --iterations 2000 --warmup 100 > v06-result.json
cargo run --release --bin ndabi-v08 -- --iterations 10000 --warmup 500 > v08-result.json
cargo run --release --bin ndabi-v09 -- --iterations 10000 --warmup 500 > v09-result.json
cargo run --release --bin ndabi_v11 -- --records 1000000 --workload point \
  --result-bytes 64 --batches 24 --operations-per-batch 2000 --warmup-batches 2
```

## Verify

```sh
cargo test
python3 -m unittest discover -s tests
python3 verify_evidence.py
node --check web/app.js
```

## Run the isolated Linux measurement

```sh
NDABI_CPU=2 ./linux_benchmark.sh
```

The Linux runner pins one CPU and records `perf stat` counters beside the JSON result.
It reports the current CPU governor. It does not change host power settings.

## Boundaries

This is a local POC over several recorded engine profiles and a reference application kernel.
The v0.1 RFC candidate specifies only the implemented read-only wire subset.
It is not a public standard or a production claim.
The runner repeats four balanced orders for ten cycles. It reports deterministic bootstrap intervals.
The token canary is a separate decoding and accounting test with one sample per form.
The v0.9 paired comparison does not pin a core. Linux affinity, durable custody, shared-state concurrency,
remote transport, database adapters, energy, and complete model-token savings remain unproven.

The v1.2 query engine remains a fixture. White Tree, PostgreSQL, shared-state concurrency, durable
custody, remote transport, and provider-token savings remain separate unpassed campaigns.

The v1.3 result is a failed Linux ARM64 Docker campaign. Docker Desktop cannot prove bare-metal
absolute latency, energy, NUMA, or physical-core behaviour.

The v1.4 result is also a failed campaign. Its complete-path ratios passed and remained stable.
Its secondary causal-ratio repeatability gate failed.

The v1.9 result is accepted only for the frozen trusted-local fixture boundary.
It does not prove White Tree, PostgreSQL, sockets, concurrency, remote models, or token savings.

The v2.4 result proves one signed White Tree point-query shape on macOS.
The v2.6 result proves no PostgreSQL single-operation speed gain.
The v3.2 result proves one fixed-width homogeneous PostgreSQL point-read batch profile.
Four process-local performance verdicts failed, but the frozen five-process aggregate passed.
The v3.3 result proves the hardened profile across five Linux ARM64 client containers.
Every process-local and aggregate gate passed.
The v3.4 separate-arm concurrency method failed because matching arms received different conditions.
The v3.5 paired method passed every functional and performance target.
Two repeatability gates failed, so v3.5 supports no accepted performance claim.
The v4.0 gateway returned exact results across five processes and passed every security gate.
Its 60-byte request reduced request bytes by 83.91% to 93.68% against PostgREST.
It measured 3.79 to 3.92 times faster than PostgREST and 9.61 to 25.44 times faster than sequential prepared SQL.
The extra gateway round trip made it 1.54 to 1.80 times slower than native prepared-set execution.
The v4.0 campaign therefore failed all ten native-ceiling gates.
The v4.1 embedded campaign passed all twenty-one frozen checks across five Linux ARM64 processes.
Embedded p95 measured 5.57% to 9.03% below native prepared-set execution.
Embedded throughput measured 1.001 to 1.083 times native across concurrency 1 through 128.
It measured 7.10 to 8.95 times faster than PostgREST and reduced request bytes by 84.99% to 94.10%.
The accepted result applies only to the embedded ordered-range PostgreSQL profile.
Physical Linux, TLS, MongoDB, Supabase, energy, and provider tokens remain unproven.

The v4.2 campaign uses the reusable `ndabi-postgres` prototype crate.
It passed all 34 frozen gates across five Linux ARM64 processes and one million PostgreSQL rows.
It covered ordered ranges, indexed predicates, grouped aggregates, joins, and a 4,096-row result.
NDABI p95 measured from 0.31% below native to 5.03% above native across these shapes.
Client CPU measured 5.05% to 14.93% above native.
NDABI added zero to 0.49 mean allocations and used 71.32% to 73.88% fewer request bytes than JSON.
Agent frames cannot contain SQL or write opcodes.
The database authority must still enforce trusted read-only prepared plans.
White Tree still uses its separate governed NDABI research path.

The v4.3 repair campaign rebuilt the adapter after its security and logic audit.
It refuses exact-deadline frames and overflowing ranges.
Unexpected PostgreSQL row types now return typed errors instead of panics.
All 34 gates passed again across five Linux ARM64 processes.
NDABI p95 measured from 2.52% below native to 8.78% above native.
Client CPU measured 1.41% to 15.35% above native.

The v4.5 result proves one equal-security White Tree request profile on macOS.
The v4.6 result proves persistent TLS 1.3 loopback and controlled server delay, not a geographic WAN.
The v4.9 result proves one MongoDB 6.0.26 point-read profile.
MongoDB 8.0 and 8.3 refused the available Docker kernel.
The v5.0 result proves local PostgreSQL and PostgREST JWT bindings, not the hosted Supabase control plane.
The v5.8 result proves the canonical execute-handle frame against the same local data surfaces.
It adds no hosted Supabase or performance claim.
The v6.0 result proves one canonical MongoDB 6.0.26 identifier-window profile.
The v6.3 result proves one canonical PostgreSQL homogeneous-batch profile on local Docker.
The v5.2 result proves one PostgreSQL compare-and-swap write profile.
Tokens, energy, public WAN, production custody, and general query or write support remain unproven.
