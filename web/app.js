const parameters = new URLSearchParams(window.location.search);
const token = parameters.get("token") || "";
window.history.replaceState({}, "", window.location.pathname);

const state = {
  result: null,
  tokenEvidence: null,
  validation: null,
  v06: null,
  v06Validation: null,
  v07Validation: null,
  v08Validation: null,
  v09Validation: null,
  running: false,
};

const elements = {
  form: document.getElementById("run-form"),
  rows: document.getElementById("rows"),
  iterations: document.getElementById("iterations"),
  warmup: document.getElementById("warmup"),
  runButton: document.getElementById("run-button"),
  downloadButton: document.getElementById("download-result"),
  runtimeState: document.getElementById("runtime-state"),
  error: document.getElementById("error-message"),
  overallVerdict: document.getElementById("overall-verdict"),
  overviewCopy: document.getElementById("overview-copy"),
  runMeta: document.getElementById("run-meta"),
  databaseScore: document.getElementById("database-score"),
  databaseContent: document.getElementById("database-content"),
  applicationScore: document.getElementById("application-score"),
  applicationContent: document.getElementById("application-content"),
  whiteTreeScore: document.getElementById("white-tree-score"),
  whiteTreeContent: document.getElementById("white-tree-content"),
  modelState: document.getElementById("model-state"),
  modelContent: document.getElementById("model-content"),
  limitations: document.getElementById("limitations"),
  validationState: document.getElementById("validation-state"),
  validationContent: document.getElementById("validation-content"),
  v06Score: document.getElementById("v06-score"),
  v06Content: document.getElementById("v06-content"),
  scaleScore: document.getElementById("scale-score"),
  scaleContent: document.getElementById("scale-content"),
};

const metricDefinitions = [
  { key: "request_bytes", label: "Request wire size", format: formatBytes },
  { key: "response_bytes", label: "Response wire size", format: formatBytes },
  { key: "p95_ns", label: "p95 loopback latency", format: formatDuration },
  {
    key: "allocated_bytes_per_operation",
    label: "Allocated Rust bytes per operation",
    format: formatBytes,
  },
  { key: "median_thread_cpu_ns", label: "Median thread CPU", format: formatDuration },
  { key: "retained_rust_bytes", label: "Retained Rust capacity", format: formatBytes },
];

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await runShowdown();
});

elements.downloadButton.addEventListener("click", () => {
  if (!state.result) return;
  const blob = new Blob([JSON.stringify(state.result, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `ndabi-showdown-${state.result.generated_at_unix_seconds}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
});

loadLatest();

async function loadLatest() {
  if (!token) {
    showError("The loopback access token is absent. Start the laboratory with ./run.sh.");
    return;
  }
  try {
    const response = await fetch("/api/latest", { headers: requestHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed: ${response.status}`);
    render(result);
    await loadV06();
    await loadScaleCampaigns();
    await loadValidationSuite();
    await loadTokenEvidence();
    elements.runtimeState.textContent = "Evidence loaded";
  } catch (error) {
    showError(error.message);
  }
}

async function loadScaleCampaigns() {
  try {
    const [defaultResponse, qosResponse, pairedResponse] = await Promise.all([
      fetch("/api/v07-validation-suite", { headers: requestHeaders() }),
      fetch("/api/v08-validation-suite", { headers: requestHeaders() }),
      fetch("/api/v09-validation-suite", { headers: requestHeaders() }),
    ]);
    const [defaultResult, qosResult, pairedResult] = await Promise.all([
      defaultResponse.json(),
      qosResponse.json(),
      pairedResponse.json(),
    ]);
    if (!defaultResponse.ok) {
      throw new Error(defaultResult.error || `Request failed: ${defaultResponse.status}`);
    }
    if (!qosResponse.ok) {
      throw new Error(qosResult.error || `Request failed: ${qosResponse.status}`);
    }
    if (!pairedResponse.ok) {
      throw new Error(pairedResult.error || `Request failed: ${pairedResponse.status}`);
    }
    renderScaleCampaigns(defaultResult, qosResult, pairedResult);
  } catch (error) {
    replaceChildren(elements.scaleScore, [
      create("span", { className: "score-verdict negative" }, "Unavailable"),
    ]);
    replaceChildren(elements.scaleContent, [
      create("p", { className: "section-note" }, error.message),
    ]);
  }
}

function renderScaleCampaigns(defaultResult, qosResult, pairedResult) {
  state.v07Validation = defaultResult;
  state.v08Validation = qosResult;
  state.v09Validation = pairedResult;
  if (pairedResult.status === "unavailable") {
    replaceChildren(elements.scaleScore, [
      create("span", { className: "score-verdict negative" }, "Unproven"),
    ]);
    replaceChildren(elements.scaleContent, [
      create(
        "p",
        { className: "section-note" },
        "Run python3 validation_suite_v09.py to create the paired campaign.",
      ),
    ]);
    return;
  }
  const runs = pairedResult.configuration.runs;
  const passed = pairedResult.hard_gates_passed;
  const campaignPassed = pairedResult.campaign_gate.passed;
  replaceChildren(elements.scaleScore, [
    create("span", { className: "score-value" }, `${passed}/${runs}`),
    create(
      "span",
      { className: `score-verdict ${campaignPassed ? "positive" : "negative"}` },
      campaignPassed ? "Paired pass" : "Campaign failed",
    ),
  ]);
  const boundary = create(
    "p",
    { className: "canary-caution" },
    "Paired speedups are stable. Absolute macOS latency still changes with core placement.",
  );
  const grid = create("div", { className: "provider-grid" });
  grid.append(
    createCampaignCard("Direct kernel", pairedResult.direct),
    createCampaignCard("Prepared wire", pairedResult.prepared),
    createCampaignCard("Stateless JSON", pairedResult.stateless_json),
  );
  const comparison = create("section", { className: "proof-panel" });
  comparison.append(
    create("span", { className: "section-label" }, "Negative controls"),
    create("h3", { className: "proof-title" }, "Default scheduling and QoS both failed"),
  );
  const comparisonGrid = create("dl", { className: "proof-grid" });
  if (defaultResult.status !== "unavailable") {
    const defaultRuns = defaultResult.configuration.runs;
    const comparisonRows = [
      ["Default gates", `${defaultResult.hard_gates_passed}/${defaultRuns}`],
      ["Default direct p95 CV", formatCoefficient(defaultResult.direct.p95_ns)],
      [
        "QoS gates",
        qosResult.status === "unavailable"
          ? "unavailable"
          : `${qosResult.hard_gates_passed}/${qosResult.configuration.runs}`,
      ],
      ["Paired direct speedup CV", formatCoefficient(pairedResult.direct.conservative_json_speedup)],
      [
        "Paired prepared speedup CV",
        formatCoefficient(pairedResult.prepared.conservative_json_speedup),
      ],
      ["Absolute direct p95 CV", formatCoefficient(pairedResult.direct.p95_ns)],
      ["Prepared p99.9 maximum", formatDuration(pairedResult.prepared.p999_ns.maximum)],
    ];
    for (const [label, value] of comparisonRows) {
      comparisonGrid.append(create("dt", {}, label), create("dd", {}, value));
    }
  }
  comparison.append(comparisonGrid);
  replaceChildren(elements.scaleContent, [boundary, grid, comparison]);
}

function createCampaignCard(label, track) {
  return createV06Card(label, [
    ["p95", formatNumberRange(track.p95_ns, formatDuration)],
    ["p99", formatNumberRange(track.p99_ns, formatDuration)],
    ["Operations/s", formatNumberRange(track.operations_per_second, formatOperationRate)],
    ["p95 variation", formatCoefficient(track.p95_ns)],
    [
      "JSON speedup",
      track.conservative_json_speedup
        ? formatNumberRange(track.conservative_json_speedup, formatRatio)
        : "baseline",
    ],
  ]);
}

function formatCoefficient(summary) {
  return `${(Number(summary.coefficient_of_variation) * 100).toFixed(1)}%`;
}

function formatOperationRate(value) {
  return formatInteger(Math.round(Number(value)));
}

async function loadValidationSuite() {
  try {
    const response = await fetch("/api/validation-suite", { headers: requestHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed: ${response.status}`);
    renderValidationSuite(result);
  } catch (error) {
    renderValidationUnavailable(error.message);
  }
}

function renderValidationSuite(result) {
  state.validation = result;
  if (result.status === "unavailable" || result.run_count === 0) {
    renderValidationUnavailable("Run python3 validation_suite.py to create repeatability evidence.");
    return;
  }
  replaceChildren(elements.validationState, [
    create("span", { className: "score-value" }, `${result.run_count} runs`),
    create("span", { className: "score-verdict positive" }, "Source-bound"),
  ]);
  const grid = create("div", { className: "provider-grid" });
  for (const track of ["database", "application", "white_tree"]) {
    const summary = result.tracks[track];
    const card = create("section", { className: "provider-card" });
    card.append(
      create("span", { className: "provider-name" }, track.replace("_", " ")),
      create(
        "strong",
        { className: summary.hard_gates_passed === result.run_count ? "positive" : "negative" },
        `${summary.hard_gates_passed}/${result.run_count} hard gates`,
      ),
      create(
        "p",
        { className: "provider-saving" },
        `${formatRange(summary.p95_reduction_min_percent, summary.p95_reduction_max_percent)} p95 reduction`,
      ),
      create(
        "p",
        { className: "section-note" },
        `${formatRange(summary.thread_cpu_reduction_min_percent, summary.thread_cpu_reduction_max_percent)} thread CPU reduction.`,
      ),
      create(
        "p",
        { className: "section-note" },
        `${summary.interval_target_passes}/${result.run_count} conservative interval targets passed.`,
      ),
    );
    grid.append(card);
  }
  replaceChildren(elements.validationContent, [grid]);
}

function renderValidationUnavailable(message) {
  replaceChildren(elements.validationState, [
    create("span", { className: "score-verdict negative" }, "Unproven"),
  ]);
  replaceChildren(elements.validationContent, [
    create("p", { className: "section-note" }, message),
  ]);
}

async function loadTokenEvidence() {
  try {
    const response = await fetch("/api/token-evidence", { headers: requestHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed: ${response.status}`);
    renderTokenEvidence(result);
  } catch (error) {
    renderTokenUnavailable(error.message);
  }
}

async function runShowdown() {
  if (state.running) return;
  state.running = true;
  elements.error.hidden = true;
  elements.runButton.disabled = true;
  elements.runButton.textContent = "Measuring";
  elements.runtimeState.textContent = "Benchmark running";
  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: requestHeaders(),
      body: JSON.stringify({
        rows: Number(elements.rows.value),
        iterations: Number(elements.iterations.value),
        warmup: Number(elements.warmup.value),
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed: ${response.status}`);
    render(result);
    await loadV06();
    elements.runtimeState.textContent = "Measurement complete";
  } catch (error) {
    showError(error.message);
  } finally {
    state.running = false;
    elements.runButton.disabled = false;
    elements.runButton.textContent = "Run showdown";
  }
}

async function loadV06() {
  try {
    const response = await fetch("/api/v06", { headers: requestHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed: ${response.status}`);
    renderV06(result);
    await loadV06Validation();
  } catch (error) {
    replaceChildren(elements.v06Score, [
      create("span", { className: "score-verdict negative" }, "Unavailable"),
    ]);
    replaceChildren(elements.v06Content, [
      create("p", { className: "section-note" }, error.message),
    ]);
  }
}

async function loadV06Validation() {
  try {
    const response = await fetch("/api/v06-validation-suite", { headers: requestHeaders() });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed: ${response.status}`);
    renderV06Validation(result);
  } catch (error) {
    renderV06ValidationUnavailable(error.message);
  }
}

function renderV06(result) {
  state.v06 = result;
  const passed = result.hard_gate.checks.filter((check) => check.passed).length;
  replaceChildren(elements.v06Score, [
    create("span", { className: "score-value" }, `${passed}/${result.hard_gate.checks.length}`),
    create(
      "span",
      {
        className: `score-verdict ${result.hard_gate.passed ? "positive" : "negative"}`,
      },
      result.overall_verdict.replaceAll("-", " "),
    ),
  ]);

  const evidenceBoundary = create(
    "p",
    { className: "canary-caution" },
    "The local event chain trusts the transition kernel. The federated profile still needs an independent proof.",
  );
  const repeatability = create("section", { className: "proof-panel" });
  repeatability.append(
    create("span", { className: "section-label" }, "Repeatability"),
    create("h3", { className: "proof-title" }, "Does the architectural gain survive four runs?"),
    create("div", { id: "v06-validation-content" }),
  );

  const gates = create("div", { className: "gate-list", role: "list" });
  for (const gate of result.hard_gate.checks) {
    gates.append(
      create(
        "span",
        {
          className: `gate ${gate.passed ? "gate-pass" : "gate-fail"}`,
          role: "listitem",
          title: `${gate.target}. Observed: ${gate.observed}.`,
        },
        `${gate.passed ? "Pass" : "Fail"}: ${gate.label}`,
      ),
    );
  }

  const armGrid = create("div", { className: "provider-grid v06-arm-grid" });
  for (const arm of result.arms) {
    armGrid.append(
      createV06Card(arm.label, [
        ["p95", formatDuration(arm.p95_ns)],
        ["Operations/s", formatInteger(Math.round(arm.operations_per_second))],
        ["Request", arm.id === "direct-kernel" ? "native" : formatBytes(arm.request_bytes)],
        ["Response", arm.id === "direct-kernel" ? "native" : formatBytes(arm.response_bytes)],
      ]),
    );
  }

  const exactness = create("section", { className: "proof-panel" });
  exactness.append(
    create("span", { className: "section-label" }, "Lossless and refusal proof"),
    create("h3", { className: "proof-title" }, "One state, one event, one exact human view"),
  );
  const exactGrid = create("dl", { className: "proof-grid" });
  const exactRows = [
    ["Arm states", result.exactness.states_equal ? "exact" : "mismatch"],
    ["Event replay", result.exactness.replay_equal ? "exact" : "mismatch"],
    ["Receipts", result.exactness.receipts_equal ? "exact" : "mismatch"],
    ["Canonical events", result.exactness.canonical_events_equal ? "exact" : "mismatch"],
    ["Human patches", result.exactness.human_views_equal ? "byte-identical" : "mismatch"],
    ["Checkpoints", result.exactness.checkpoints_verify ? "verified" : "refused"],
    ["Negative controls", `${result.exactness.refusals_passed}/${result.exactness.refusals_total}`],
    ["Control memory", formatBytes(result.memory.local_control_bytes)],
  ];
  for (const [label, value] of exactRows) {
    exactGrid.append(create("dt", {}, label), create("dd", {}, value));
  }
  exactness.append(exactGrid);

  const attribution = create("div", { className: "attribution-grid" });
  attribution.append(
    createV06Attribution(
      "Prepared wire",
      `${result.attribution.prepared_vs_v05_tuned_conservative_p95_speedup.toFixed(1)}×`,
      "conservative p95 speedup against the frozen v0.5 tuned result",
    ),
    createV06Attribution(
      "Direct kernel",
      `${result.attribution.direct_vs_v05_tuned_conservative_p95_speedup.toFixed(1)}×`,
      "conservative p95 speedup against the frozen v0.5 tuned result",
    ),
    createV06Attribution(
      "Receipt control",
      `${result.memory.local_control_reduction_percent.toFixed(1)}% less`,
      "local control memory against the v0.5 dual receipt tree",
    ),
  );

  const examples = create("div", { className: "example-grid" });
  const exampleRows = [
    ["Stateless JSON", result.examples.stateless_json],
    ["Stateless wire", result.examples.stateless_wire_hex],
    ["Prepared wire", result.examples.prepared_wire_hex],
    ["Canonical event", result.examples.canonical_event_hex],
    ["Exact human patch", result.examples.exact_human_patch],
  ];
  for (const [label, value] of exampleRows) {
    const details = create("details");
    details.append(create("summary", {}, label), create("pre", {}, value));
    examples.append(details);
  }
  const limitations = create("details", { className: "schedule" });
  limitations.append(
    create("summary", {}, "v0.6 evidence boundaries"),
    create("pre", {}, result.limitations.join("\n")),
  );
  replaceChildren(elements.v06Content, [
    evidenceBoundary,
    repeatability,
    gates,
    armGrid,
    exactness,
    attribution,
    create("h3", { className: "subheading" }, "Complete architectural arms"),
    renderTable(result.arms),
    create("h3", { className: "subheading" }, "Boundary ablations"),
    renderTable(result.ablations.arms),
    create("h3", { className: "subheading" }, "Inspect exact representations"),
    examples,
    limitations,
  ]);
}

function renderV06Validation(result) {
  state.v06Validation = result;
  const target = document.getElementById("v06-validation-content");
  if (!target) return;
  if (result.status === "unavailable" || result.run_count === 0) {
    renderV06ValidationUnavailable("Run python3 validation_suite_v06.py to create repeatability evidence.");
    return;
  }
  const grid = create("dl", { className: "proof-grid" });
  const rows = [
    ["Hard gates", `${result.hard_gates_passed}/${result.run_count}`],
    ["Direct p95", formatNumberRange(result.direct_p95_ns, formatDuration)],
    ["Prepared p95", formatNumberRange(result.prepared_p95_ns, formatDuration)],
    ["Direct speedup", formatNumberRange(result.direct_v05_conservative_speedup, formatRatio)],
    ["Prepared speedup", formatNumberRange(result.prepared_v05_conservative_speedup, formatRatio)],
    ["Receipt cost", formatNumberRange(result.receipt_incremental_ns, formatDuration)],
  ];
  for (const [label, value] of rows) {
    grid.append(create("dt", {}, label), create("dd", {}, value));
  }
  replaceChildren(target, [grid]);
}

function renderV06ValidationUnavailable(message) {
  const target = document.getElementById("v06-validation-content");
  if (!target) return;
  replaceChildren(target, [create("p", { className: "section-note" }, message)]);
}

function createV06Card(label, rows) {
  const section = create("section", { className: "provider-card" });
  section.append(create("span", { className: "provider-name" }, label));
  const list = create("dl", { className: "compact-metrics" });
  for (const [name, value] of rows) {
    list.append(create("dt", {}, name), create("dd", {}, value));
  }
  section.append(list);
  return section;
}

function createV06Attribution(title, value, description) {
  const section = create("section", { className: "attribution" });
  section.append(
    create("h3", {}, title),
    create("strong", { className: "provider-saving" }, value),
    create("p", { className: "section-note" }, description),
  );
  return section;
}

function formatNumberRange(range, formatter) {
  return `${formatter(range.minimum)}-${formatter(range.maximum)}`;
}

function formatRatio(value) {
  return `${Number(value).toFixed(1)}×`;
}

function requestHeaders() {
  return {
    "Content-Type": "application/json",
    "X-NDABI-Token": token,
  };
}

function render(result) {
  state.result = result;
  elements.downloadButton.disabled = false;
  elements.overallVerdict.textContent = result.overall_verdict;
  elements.overallVerdict.className = `overall-verdict ${verdictClass(result.overall_verdict)}`;
  elements.overviewCopy.textContent = verdictCopy(result.overall_verdict);
  setSelect(elements.rows, result.config.rows);
  setSelect(elements.iterations, result.config.iterations);
  setSelect(elements.warmup, result.config.warmup);
  renderMeta(result);
  renderTrack(elements.databaseContent, elements.databaseScore, result.database, "database");
  renderTrack(
    elements.applicationContent,
    elements.applicationScore,
    result.application,
    "application",
  );
  renderTrack(
    elements.whiteTreeContent,
    elements.whiteTreeScore,
    result.white_tree,
    "white-tree",
  );
  replaceChildren(
    elements.limitations,
    result.limitations.map((limitation) => create("li", {}, limitation)),
  );
}

function renderMeta(result) {
  const rows = [
    ["Fixture", `${formatInteger(result.config.rows)} database rows`],
    ["App state", `${formatInteger(result.config.application_tasks)} tasks`],
    ["Samples", `${formatInteger(result.config.iterations)} measured`],
    ["Machine", `${result.environment.os} ${result.environment.architecture}`],
    ["Process peak RSS", formatBytes(result.environment.process_peak_rss_bytes)],
    ["Source state", result.environment.git_worktree_state],
  ];
  const children = [];
  for (const [name, value] of rows) {
    children.push(create("dt", {}, name), create("dd", {}, value));
  }
  replaceChildren(elements.runMeta, children);
}

function renderTrack(container, scoreContainer, track, trackId) {
  replaceChildren(scoreContainer, [
    create("span", { className: "score-value" }, `${track.rubric.score}/100`),
    create(
      "span",
      { className: `score-verdict ${verdictClass(track.rubric.verdict)}` },
      track.rubric.verdict,
    ),
  ]);

  const gates = create("div", { className: "gate-list", role: "list" });
  for (const gate of track.hard_gate.checks) {
    gates.append(
      create(
        "span",
        {
          className: `gate ${gate.passed ? "gate-pass" : "gate-fail"}`,
          role: "listitem",
        },
        `${gate.passed ? "Pass" : "Fail"}: ${gate.label}`,
      ),
    );
  }

  const figure = create("figure", { className: "metric-figure" });
  figure.append(create("figcaption", {}, "Raw measured quantities. Lower is better."));
  const metricGrid = create("div", { className: "metric-grid" });
  for (const metric of metricDefinitions) {
    metricGrid.append(renderMetric(track.arms, metric));
  }
  figure.append(metricGrid);

  const attribution = create("div", { className: "attribution-grid" });
  attribution.append(
    renderAttribution(
      "Human to tuned JSON",
      "Reuse, compact JSON, and state deltas",
      track.human_to_tuned,
    ),
    renderAttribution(
      "Tuned JSON to NDABI wire",
      "Binary representation with equal fused work",
      track.tuned_to_wire,
    ),
    renderLocalAttribution(
      "Tuned JSON to NDABI local",
      "Native calls remove the wire boundary",
      track.tuned_to_local,
    ),
  );

  const schedule = renderSchedule(track.measurement_schedule);
  const rawHeading = create("h3", { className: "subheading" }, "Complete arm comparison");
  const table = renderTable(track.arms);
  const rubricHeading = create("h3", { className: "subheading" }, "Preregistered rubric");
  const rubric = renderRubric(track.rubric);
  const evidenceHeading = create("h3", { className: "subheading" }, "Inspect the representations");
  const examples = renderExamples(track.examples, trackId);

  const children = [
    gates,
    figure,
    attribution,
  ];
  if (trackId === "application") {
    children.push(
      renderReceiptAblation(track.receipt_ablation),
      renderReceiptPipeline(track.receipt_pipeline),
    );
  }
  if (trackId === "white-tree") {
    children.push(renderWhiteTreeProof(track));
  }
  if (track.retained_memory) {
    children.push(
      create("h3", { className: "subheading" }, "Retained memory ownership"),
      renderMemory(track.retained_memory),
    );
  }
  if (track.phase_profiles) {
    children.push(
      create("h3", { className: "subheading" }, "Diagnostic stage attribution"),
      create(
        "p",
        { className: "section-note" },
        `Wall and thread CPU medians over ${formatInteger(track.diagnostic_samples)} diagnostic samples.`,
      ),
      renderPhases(track.phase_profiles),
    );
  }
  children.push(
    schedule,
    rawHeading,
    table,
    rubricHeading,
    rubric,
    evidenceHeading,
    examples,
  );
  replaceChildren(container, children);
}

function renderReceiptPipeline(pipeline) {
  const section = create("section", { className: "proof-panel" });
  section.append(
    create("span", { className: "section-label" }, "Complete-path receipt attribution"),
    create("h3", { className: "proof-title" }, "Producer and verifier remain separate"),
  );
  const grid = create("dl", { className: "proof-grid" });
  const rows = [
    ["Producer wall", formatDuration(pipeline.producer_median_ns)],
    ["Producer CPU", formatDuration(pipeline.producer_median_thread_cpu_ns)],
    ["Verifier wall", formatDuration(pipeline.verifier_median_ns)],
    ["Verifier CPU", formatDuration(pipeline.verifier_median_thread_cpu_ns)],
  ];
  for (const [label, value] of rows) {
    grid.append(create("dt", {}, label), create("dd", {}, value));
  }
  section.append(grid);
  return section;
}

function renderWhiteTreeProof(track) {
  const section = create("section", { className: "proof-panel" });
  section.append(
    create("span", { className: "section-label" }, "Real engine slice"),
    create("h3", { className: "proof-title" }, "Governed context from `.olt` storage"),
    create(
      "p",
      { className: "section-note" },
      "Every arm runs the same governed White Tree fold and returns the complete context receipt.",
    ),
  );
  const grid = create("dl", { className: "proof-grid" });
  const rows = [
    ["Partitions opened", formatInteger(track.partitions_scanned)],
    ["Partitions pruned", formatInteger(track.partitions_pruned)],
    ["Physical bytes", formatBytes(track.physical_bytes_read)],
    ["Context", track.semantic_results_equal ? "exact match" : "mismatch"],
    ["Receipts", track.receipts_equal ? "exact match" : "mismatch"],
    ["Rejected executions", formatInteger(track.refused_engine_executions)],
  ];
  for (const [label, value] of rows) {
    grid.append(create("dt", {}, label), create("dd", {}, value));
  }
  section.append(grid);
  return section;
}

function renderMemory(rows) {
  const wrapper = create("div", { className: "table-wrap" });
  const table = create("table", { className: "memory-table" });
  const head = create("thead");
  const headRow = create("tr");
  for (const label of ["Arm", "Request", "Response", "Render", "Receipt", "State", "Engine", "Total"]) {
    headRow.append(create("th", { className: label === "Arm" ? "" : "numeric" }, label));
  }
  head.append(headRow);
  const body = create("tbody");
  for (const row of rows) {
    const item = create("tr");
    item.append(
      create("td", {}, row.label),
      numericCell(formatBytes(row.request_capacity_bytes)),
      numericCell(formatBytes(row.response_capacity_bytes)),
      numericCell(formatBytes(row.rendered_capacity_bytes)),
      numericCell(formatBytes(row.receipt_tree_bytes)),
      numericCell(formatBytes(row.state_bytes)),
      numericCell(formatBytes(row.engine_handle_bytes)),
      numericCell(formatBytes(row.total_bytes)),
    );
    body.append(item);
  }
  table.append(head, body);
  wrapper.append(table);
  return wrapper;
}

function renderReceiptAblation(ablation) {
  const section = create("section", { className: "proof-panel" });
  const stateClass = ablation.target_passed ? "positive" : "negative";
  section.append(
    create("span", { className: "section-label" }, "Lossless receipt ablation"),
    create("h3", { className: "proof-title" }, "Incremental proof versus complete rebuild"),
    create(
      "p",
      { className: "section-note" },
      "Both paths produce identical SHA-256 semantic and view roots. Preparation is outside the timed boundary.",
    ),
  );
  const grid = create("dl", { className: "proof-grid" });
  const rows = [
    ["Complete rebuild", formatDuration(ablation.full_rebuild_median_thread_cpu_ns)],
    ["Incremental proof", formatDuration(ablation.incremental_median_thread_cpu_ns)],
    ["Thread CPU reduction", `${ablation.thread_cpu_reduction_percent.toFixed(1)}%`],
    ["Wall reduction", `${ablation.wall_reduction_percent.toFixed(1)}%`],
    ["Changed items", formatInteger(ablation.changed_items)],
    ["Roots", ablation.roots_equal ? "exact match" : "mismatch"],
    ["Allocations", ablation.incremental_allocations_per_operation.toFixed(1)],
    ["80% target", ablation.target_passed ? "pass" : "fail"],
  ];
  for (const [label, value] of rows) {
    grid.append(create("dt", {}, label), create("dd", { className: stateClass }, value));
  }
  section.append(grid);
  return section;
}

function renderMetric(arms, metric) {
  const transport = metric.key === "request_bytes" || metric.key === "response_bytes";
  const values = arms
    .filter((arm) => !(transport && arm.id === "local"))
    .map((arm) => Number(arm[metric.key]));
  const maximum = Math.max(...values, 1);
  const group = create("div", { className: "metric-group" });
  group.append(create("div", { className: "metric-name" }, metric.label));
  for (const arm of arms) {
    const value = Number(arm[metric.key]);
    const localTransport = transport && arm.id === "local";
    const row = create("div", { className: "bar-row" });
    const track = create("div", { className: "bar-track" });
    const fill = create("div", { className: `bar-fill arm-${arm.id}` });
    fill.style.width = localTransport ? "0" : `${Math.max(0.8, (value / maximum) * 100)}%`;
    track.append(fill);
    row.append(
      create("span", { className: "bar-label" }, arm.id),
      track,
      create("span", { className: "bar-value" }, localTransport ? "native" : metric.format(value)),
    );
    group.append(row);
  }
  return group;
}

function renderLocalAttribution(title, subtitle, values) {
  const section = create("section", { className: "attribution" });
  section.append(create("h3", {}, title), create("p", { className: "section-note" }, subtitle));
  const list = create("dl");
  const metrics = [
    ["p95 latency", values.p95_reduction_percent],
    ["Thread CPU", values.thread_cpu_reduction_percent],
    ["Allocated bytes", values.allocated_bytes_reduction_percent],
    ["Allocation count", values.allocation_count_reduction_percent],
  ];
  for (const [label, value] of metrics) {
    list.append(
      create("dt", {}, label),
      create("dd", { className: value >= 0 ? "positive" : "negative" }, formatReduction(value)),
    );
  }
  section.append(list);
  return section;
}

function renderPhases(profiles) {
  const grid = create("div", { className: "phase-grid" });
  const phases = [
    ["Admission", "admission_median_ns"],
    ["Admission CPU", "admission_median_thread_cpu_ns"],
    ["Execution", "execution_median_ns"],
    ["Execution CPU", "execution_median_thread_cpu_ns"],
    ["Result", "result_median_ns"],
    ["Result CPU", "result_median_thread_cpu_ns"],
  ];
  for (const [label, key] of phases) {
    grid.append(
      renderMetric(
        profiles,
        { key, label, format: formatDuration },
      ),
    );
  }
  return grid;
}

function renderSchedule(schedule) {
  const details = create("details", { className: "schedule" });
  details.append(
    create("summary", {}, "Balanced measurement order"),
    create("pre", {}, schedule.map((round, index) => `${index + 1}. ${round}`).join("\n")),
  );
  return details;
}

function renderAttribution(title, subtitle, values) {
  const section = create("section", { className: "attribution" });
  section.append(create("h3", {}, title), create("p", { className: "section-note" }, subtitle));
  const list = create("dl");
  const metrics = [
    ["Request bytes", values.request_reduction_percent],
    ["Response bytes", values.response_reduction_percent],
    ["p95 latency", values.p95_reduction_percent],
    ["Thread CPU", values.thread_cpu_reduction_percent],
    ["Allocated bytes", values.allocated_bytes_reduction_percent],
  ];
  for (const [label, value] of metrics) {
    list.append(
      create("dt", {}, label),
      create(
        "dd",
        { className: value >= 0 ? "positive" : "negative" },
        formatReduction(value),
      ),
    );
  }
  section.append(list);
  return section;
}

function renderTable(arms) {
  const wrapper = create("div", { className: "table-wrap" });
  const table = create("table");
  const head = create("thead");
  const headRow = create("tr");
  for (const label of [
    "Arm",
    "Request",
    "Response",
    "Median",
    "p95",
    "Thread CPU",
    "Operations/s",
    "Allocations/op",
    "Allocated/op",
    "Peak live",
    "Retained Rust",
  ]) {
    headRow.append(create("th", { className: label === "Arm" ? "" : "numeric" }, label));
  }
  head.append(headRow);
  const body = create("tbody");
  for (const arm of arms) {
    const local = arm.id === "local";
    const row = create("tr");
    row.append(
      create("td", {}, arm.label),
      numericCell(local ? "native" : formatBytes(arm.request_bytes)),
      numericCell(local ? "native" : formatBytes(arm.response_bytes)),
      numericCell(`${formatDuration(arm.median_ns)} (${formatDuration(arm.median_ci95_low_ns)}-${formatDuration(arm.median_ci95_high_ns)})`),
      numericCell(`${formatDuration(arm.p95_ns)} (${formatDuration(arm.p95_ci95_low_ns)}-${formatDuration(arm.p95_ci95_high_ns)})`),
      numericCell(formatDuration(arm.median_thread_cpu_ns)),
      numericCell(formatInteger(Math.round(arm.operations_per_second))),
      numericCell(arm.allocations_per_operation.toFixed(1)),
      numericCell(formatBytes(arm.allocated_bytes_per_operation)),
      numericCell(formatBytes(arm.peak_additional_live_bytes)),
      numericCell(formatBytes(arm.retained_rust_bytes)),
    );
    body.append(row);
  }
  table.append(head, body);
  wrapper.append(table);
  return wrapper;
}

function renderTokenEvidence(evidence) {
  state.tokenEvidence = evidence;
  if (evidence.status === "unavailable" || evidence.providers.length === 0) {
    renderTokenUnavailable("Run python3 token_canary.py to create provider evidence.");
    return;
  }
  const decoded = evidence.providers.filter((provider) => provider.all_answers_exact).length;
  const measured = evidence.providers.filter(
    (provider) => provider.token_measurement_available,
  ).length;
  replaceChildren(elements.modelState, [
    create("span", { className: "score-value" }, `${decoded}/${evidence.providers.length}`),
    create("span", { className: "score-verdict positive" }, `${measured} token source measured`),
  ]);
  const notice = create(
    "p",
    { className: "section-note model-note" },
    "The model receives a compact semantic form. A local adapter emits NDABI bytes and attaches authority.",
  );
  const targetNotice = create(
    "p",
    { className: "canary-caution" },
    "The preregistered uncached-input target remains unproven. Provider caching prevents comparable uncached form counts.",
  );
  const grid = create("div", { className: "provider-grid" });
  for (const provider of evidence.providers) {
    grid.append(renderProvider(provider));
  }
  const limitations = create("details", { className: "schedule" });
  limitations.append(
    create("summary", {}, "Token canary boundaries"),
    create("pre", {}, evidence.limitations.join("\n")),
  );
  replaceChildren(elements.modelContent, [notice, targetNotice, grid, limitations]);
}

function renderProvider(provider) {
  const section = create("section", { className: "provider-card" });
  section.append(
    create("span", { className: "provider-name" }, provider.provider),
    create("span", { className: "provider-version" }, provider.cli_version || "version unavailable"),
    create(
      "strong",
      { className: provider.all_answers_exact ? "positive" : "negative" },
      provider.all_answers_exact ? "All forms decoded exactly" : "A form changed the answer",
    ),
  );
  if (provider.token_measurement_available) {
    section.append(
      create(
        "p",
        { className: "provider-saving" },
        `${provider.representation_input_reduction_percent.toFixed(1)}% fewer representation tokens`,
      ),
      create(
        "p",
        { className: "section-note" },
        `${provider.complete_input_reduction_percent.toFixed(1)}% fewer complete input tokens in this canary.`,
      ),
    );
  } else {
    section.append(
      create("p", { className: "section-note" }, `Token reduction unproven: ${provider.token_measurement_reason}.`),
    );
  }
  const table = create("table", { className: "provider-table" });
  const head = create("tr");
  for (const label of ["Form", "Bytes", "Input tokens", "Output tokens", "Time"]) {
    head.append(create("th", { className: label === "Form" ? "" : "numeric" }, label));
  }
  const tableHead = create("thead");
  tableHead.append(head);
  const body = create("tbody");
  for (const form of provider.forms) {
    const row = create("tr");
    row.append(
      create("td", {}, form.form.replaceAll("_", " ")),
      numericCell(formatBytes(form.request_bytes)),
      numericCell(
        form.representation_input_tokens === null
          ? "unavailable"
          : formatInteger(form.representation_input_tokens),
      ),
      numericCell(form.usage ? formatInteger(form.usage.output_tokens) : "unavailable"),
      numericCell(formatMilliseconds(form.elapsed_ms)),
    );
    body.append(row);
  }
  table.append(tableHead, body);
  section.append(table);
  return section;
}

function renderTokenUnavailable(message) {
  replaceChildren(elements.modelState, [
    create("span", { className: "score-verdict negative" }, "Unproven"),
  ]);
  replaceChildren(elements.modelContent, [
    create("p", { className: "section-note" }, message),
  ]);
}

function renderRubric(rubric) {
  const list = create("div", { className: "rubric" });
  for (const check of rubric.checks) {
    const item = create("div", {
      className: `rubric-item ${check.passed ? "rubric-pass" : "rubric-fail"}`,
    });
    item.append(
      create("strong", {}, check.label),
      create("span", {}, `${check.target}. Observed: ${check.observed}.`),
      create(
        "span",
        { className: "rubric-points" },
        check.passed ? `+${check.weight}` : "+0",
      ),
    );
    list.append(item);
  }
  return list;
}

function renderExamples(examples, trackId) {
  const grid = create("div", { className: "example-grid" });
  const entries = [
    ["Readable request", examples.human_request],
    ["Tuned JSON request", examples.tuned_request],
    ["NDABI hex", examples.ndabi_hex],
    ["Deterministic disassembly", examples.ndabi_disassembly],
    [trackId === "application" ? "Complete human view" : "Decoded human result", trackId === "application" ? examples.human_view : examples.human_result],
  ];
  for (const [label, value] of entries) {
    const details = create("details");
    details.append(create("summary", {}, label), create("pre", {}, value));
    grid.append(details);
  }
  return grid;
}

function numericCell(value) {
  return create("td", { className: "numeric" }, value);
}

function replaceChildren(parent, children) {
  parent.replaceChildren(...children);
}

function create(tagName, properties = {}, text = null) {
  const element = document.createElement(tagName);
  Object.assign(element, properties);
  if (text !== null) element.textContent = text;
  return element;
}

function setSelect(select, value) {
  const option = [...select.options].find((item) => Number(item.value) === Number(value));
  if (option) select.value = String(value);
}

function formatBytes(value) {
  const number = Number(value);
  if (number < 1024) return `${Math.round(number)} B`;
  return `${(number / 1024).toFixed(number < 10240 ? 1 : 0)} KiB`;
}

function formatDuration(value) {
  const number = Number(value);
  if (number < 1000) return `${Math.round(number)} ns`;
  if (number < 1_000_000) return `${(number / 1000).toFixed(1)} us`;
  return `${(number / 1_000_000).toFixed(2)} ms`;
}

function formatMilliseconds(value) {
  const number = Number(value);
  return number < 1000 ? `${number.toFixed(0)} ms` : `${(number / 1000).toFixed(2)} s`;
}

function formatInteger(value) {
  return new Intl.NumberFormat("en").format(value);
}

function formatReduction(value) {
  const magnitude = Math.abs(value).toFixed(1);
  return value >= 0 ? `${magnitude}% less` : `${magnitude}% more`;
}

function formatRange(minimum, maximum) {
  return `${minimum.toFixed(1)}-${maximum.toFixed(1)}%`;
}

function verdictClass(verdict) {
  return verdict === "strong support" || verdict === "promising" ? "positive" : "negative";
}

function verdictCopy(verdict) {
  const copy = {
    "strong support": "All tracks passed the hard gates and most tuned-baseline targets.",
    promising: "The evidence supports several targets, but important tuned-baseline targets remain open.",
    mixed: "Compression works, but the speed and memory evidence does not move together.",
    rejected: "The broad claim does not pass this run. Inspect the attribution before changing the design.",
    invalid: "A correctness or refusal gate failed. Ignore every performance number from this run.",
  };
  return copy[verdict] || "The result uses an unknown verdict.";
}

function showError(message) {
  elements.error.textContent = message;
  elements.error.hidden = false;
  elements.runtimeState.textContent = "Measurement failed";
}
