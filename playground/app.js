// Client-side deterministic checker mirroring EvidAudit's v2-strict implementation.

const VALID_PACKET_IDS = new Set(["E1", "E2", "E3"]);

const PRESETS = {
  "export-masking": {
    name: "Export Waiver Masking",
    prereqId: "req_clearance",
    prohibId: "prohib_export",
    overrideId: "ov_waiver",
    evidenceHtml:
      "<strong>Source Packet:</strong><ul>" +
      "<li><code>E1</code>: Security clearance verified (<code>req_clearance = TRUE</code>)</li>" +
      "<li><code>E2</code>: Dual-use export restriction applies (<code>prohib_export = TRUE</code>)</li>" +
      "<li><code>E3</code>: Executive waiver status (policy-controlled)</li>" +
      "</ul>",
    initial: { prohib: "FALSE", override: "TRUE", prereq: "TRUE", citation: "E2" },
    transition: { prohib: "FALSE", override: "FALSE", prereq: "TRUE", citation: "E2" },
    repair: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "E2" },
  },
  "payment-expiry": {
    name: "Payment Expiry (v7)",
    prereqId: "req_kyc_ok",
    prohibId: "prohib_expired_window",
    overrideId: "ov_grace_window",
    evidenceHtml:
      "<strong>Source Packet:</strong><ul>" +
      "<li><code>E1</code>: KYC check passed (<code>req_kyc_ok = TRUE</code>)</li>" +
      "<li><code>E2</code>: Invoice date <code>2026-11-25</code> &gt; cutoff <code>2026-11-20</code> (<code>prohib_expired_window = TRUE</code>)</li>" +
      "<li><code>E3</code>: Grace-window exception (revoked in v7 policy)</li>" +
      "</ul>",
    initial: { prohib: "FALSE", override: "TRUE", prereq: "TRUE", citation: "E2" },
    transition: { prohib: "FALSE", override: "FALSE", prereq: "TRUE", citation: "E2" },
    repair: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "E2" },
  },
  "ungrounded-citation": {
    name: "Ungrounded Policy Citation",
    prereqId: "req_clearance",
    prohibId: "prohib_export",
    overrideId: "ov_waiver",
    evidenceHtml:
      "<strong>Source Packet:</strong><ul>" +
      "<li><code>E1</code>: Security clearance verified</li>" +
      "<li><code>E2</code>: Factual export restriction passage</li>" +
      "<li><code>P1</code>: Policy rule ID only (rejected by groundedness check)</li>" +
      "</ul>",
    initial: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "P1" },
    transition: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "P1" },
    repair: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "E2" },
  },
  "safe-faithful": {
    name: "Safe & Faithful",
    prereqId: "req_clearance",
    prohibId: "prohib_export",
    overrideId: "ov_waiver",
    evidenceHtml:
      "<strong>Source Packet:</strong><ul>" +
      "<li><code>E1</code>: Security clearance verified (<code>TRUE</code>)</li>" +
      "<li><code>E2</code>: Export restriction verified (<code>TRUE</code>)</li>" +
      "<li><code>E3</code>: Executive waiver revoked (<code>FALSE</code>)</li>" +
      "</ul>",
    initial: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "E2" },
    transition: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "E2" },
    repair: { prohib: "TRUE", override: "FALSE", prereq: "TRUE", citation: "E2" },
  },
};

let activePresetKey = "export-masking";
let activeConfigFormat = "yaml";

function evaluateV2Strict(extraction) {
  const validOverrides = {};
  for (const ov of extraction.overrides || []) {
    const eids = (ov.evidence_ids || []).filter((id) => VALID_PACKET_IDS.has(id) && !id.startsWith("P"));
    if (ov.override_valid === "TRUE" && eids.length > 0 && Number(ov.authority_rank) >= 2) {
      const target = String(ov.targets_prohibition || "").trim().toLowerCase();
      validOverrides[target] = Math.max(validOverrides[target] || 0, Number(ov.authority_rank));
    }
  }

  const activeBlocks = [];
  const unknownProhibs = [];
  for (const pr of extraction.prohibitions || []) {
    const eids = (pr.evidence_ids || []).filter((id) => VALID_PACKET_IDS.has(id) && !id.startsWith("P"));
    if (pr.prohibition_applies === "TRUE") {
      if (eids.length === 0) return "ABSTAIN";
      const key = String(pr.rule_id || "").trim().toLowerCase();
      if ((validOverrides[key] || 0) >= 2) continue;
      activeBlocks.push(pr.rule_id);
    } else if (pr.prohibition_applies === "UNKNOWN") {
      unknownProhibs.push(pr.rule_id);
    }
  }
  if (activeBlocks.length > 0) return "BLOCK";

  const falsePrereqs = [];
  const unknownPrereqs = [];
  const truePrereqs = [];
  for (const pq of extraction.prerequisites || []) {
    const eids = (pq.evidence_ids || []).filter((id) => VALID_PACKET_IDS.has(id) && !id.startsWith("P"));
    if (pq.prerequisite_satisfied === "FALSE") {
      if (eids.length === 0) return "ABSTAIN";
      falsePrereqs.push(pq.rule_id);
    } else if (pq.prerequisite_satisfied === "TRUE") {
      if (eids.length === 0) return "ABSTAIN";
      truePrereqs.push(pq.rule_id);
    } else {
      unknownPrereqs.push(pq.rule_id);
    }
  }
  if (falsePrereqs.length > 0) return "BLOCK";
  if (unknownPrereqs.length > 0 || unknownProhibs.length > 0) return "ABSTAIN";
  if (truePrereqs.length === 0) return "ABSTAIN";
  return "ALLOW";
}

function setPill(el, decision, isUnsafe) {
  if (!el) return;
  el.textContent = isUnsafe ? "ALLOW (UNSAFE)" : decision;
  el.className = `decision-pill ${isUnsafe ? "unsafe" : decision.toLowerCase()}`;
}

function buildConfigSnippet(preset, extraction, refDecision) {
  if (activeConfigFormat === "python") {
    return [
      "from evidaudit import Auditor",
      "",
      "auditor = Auditor()",
      `evidence = {"packet_ids": {"E1", "E2", "E3"}, "reference_decision": "${refDecision}", "reference_propositions": {"prerequisites": {"${preset.prereqId}": "TRUE"}, "prohibitions": {"${preset.prohibId}": "TRUE"}, "overrides": {"${preset.overrideId}": "${extraction.overrides[0].override_valid}"}}}`,
      `propositions = ${JSON.stringify(extraction)}`,
      "result = auditor.evaluate(propositions=propositions, evidence=evidence)",
      "print(result.decision, result.concealed_corruption, result.semantic_errors)",
    ].join("\n");
  }

  return [
    `name: ${activePresetKey}`,
    `reference_decision: ${refDecision}`,
    "packet_ids: [E1, E2, E3]",
    "reference_propositions:",
    `  ${preset.prereqId}: TRUE`,
    `  ${preset.prohibId}: TRUE`,
    `  ${preset.overrideId}: ${extraction.overrides[0].override_valid}`,
    "extracted:",
    `  ${preset.prereqId}: ${extraction.prerequisites[0].prerequisite_satisfied}`,
    `  ${preset.prohibId}: ${extraction.prohibitions[0].prohibition_applies}`,
    `  ${preset.overrideId}: ${extraction.overrides[0].override_valid}`,
    `  citation_id: ${extraction.prohibitions[0].evidence_ids[0]}`,
  ].join("\n");
}

function updatePlayground() {
  const selProhib = document.getElementById("sel-prohib");
  if (!selProhib) return;

  const preset = PRESETS[activePresetKey];
  const prohibVal = selProhib.value;
  const ovVal = document.getElementById("sel-override").value;
  const prereqVal = document.getElementById("sel-prereq").value;
  const citVal = document.getElementById("sel-citation").value;

  document.getElementById("evidence-summary").innerHTML = preset.evidenceHtml;
  document.getElementById("lbl-prohib").textContent = preset.prohibId;
  document.getElementById("lbl-override").textContent = preset.overrideId;
  document.getElementById("lbl-prereq").textContent = preset.prereqId;

  const extraction = {
    prerequisites: [{ rule_id: preset.prereqId, prerequisite_satisfied: prereqVal, evidence_ids: ["E1"] }],
    prohibitions: [{ rule_id: preset.prohibId, prohibition_applies: prohibVal, evidence_ids: [citVal] }],
    overrides: [
      {
        rule_id: preset.overrideId,
        targets_prohibition: preset.prohibId,
        override_valid: ovVal,
        authority_rank: 3,
        evidence_ids: ["E3"],
      },
    ],
  };

  const repairedExtraction = {
    prerequisites: [{ rule_id: preset.prereqId, prerequisite_satisfied: "TRUE", evidence_ids: ["E1"] }],
    prohibitions: [{ rule_id: preset.prohibId, prohibition_applies: "TRUE", evidence_ids: ["E2"] }],
    overrides: extraction.overrides,
  };

  const refDecision = ovVal === "TRUE" ? "ALLOW" : "BLOCK";
  const actualDecision = evaluateV2Strict(extraction);
  const repairedDecision = evaluateV2Strict(repairedExtraction);

  document.getElementById("json-preview").textContent = JSON.stringify(
    {
      reference_decision: refDecision,
      reference_propositions: {
        [preset.prereqId]: "TRUE",
        [preset.prohibId]: "TRUE",
        [preset.overrideId]: ovVal,
      },
      extracted: extraction,
    },
    null,
    2
  );

  const isUnsafe = actualDecision === "ALLOW" && refDecision === "BLOCK";
  setPill(document.getElementById("ref-decision"), refDecision, false);
  setPill(document.getElementById("actual-decision"), actualDecision, isUnsafe);
  setPill(document.getElementById("repaired-decision"), repairedDecision, false);

  const discrepancies = [];
  if (prohibVal !== "TRUE") discrepancies.push(`${preset.prohibId}: extracted=${prohibVal} vs. reference=TRUE`);
  if (prereqVal !== "TRUE") discrepancies.push(`${preset.prereqId}: extracted=${prereqVal} vs. reference=TRUE`);
  if (citVal === "P1") discrepancies.push(`${preset.prohibId}: ungrounded policy-only citation "P1" (expected factual passage "E2")`);

  const banner = document.getElementById("audit-banner");
  if (isUnsafe) {
    banner.className = "audit-banner danger";
    banner.innerHTML =
      `<strong>UNSAFE APPROVAL EXPOSED:</strong> Policy transition removed override protection and exposed corrupted <code>${preset.prohibId}</code>. Gate returned <code>ALLOW</code> instead of <code>BLOCK</code>.`;
  } else if (actualDecision === "ABSTAIN" && citVal === "P1") {
    banner.className = "audit-banner warn";
    banner.innerHTML =
      "<strong>FAIL-CLOSED ABSTENTION:</strong> Policy-only citation <code>P1</code> rejected by grounding check; gate safely abstained rather than trusting ungrounded evidence.";
  } else if (actualDecision === refDecision && discrepancies.length > 0) {
    banner.className = "audit-banner warn";
    banner.innerHTML =
      `<strong>CONCEALED SEMANTIC CORRUPTION:</strong> Final decision (<code>${actualDecision}</code>) matches reference, masking wrong intermediate proposition <code>${preset.prohibId}</code>.`;
  } else if (actualDecision === refDecision && discrepancies.length === 0) {
    banner.className = "audit-banner ok";
    banner.innerHTML =
      `<strong>SAFE &amp; FAITHFUL:</strong> Decision (<code>${actualDecision}</code>) matches reference with zero semantic or grounding discrepancies.`;
  } else {
    banner.className = "audit-banner warn";
    banner.innerHTML =
      `<strong>DECISION MISMATCH:</strong> Gate returned <code>${actualDecision}</code> (expected <code>${refDecision}</code>).`;
  }

  const details = document.getElementById("audit-details");
  details.innerHTML = "";
  if (discrepancies.length === 0) {
    const li = document.createElement("li");
    li.textContent = "All extracted propositions and evidence citations match reference truth.";
    details.appendChild(li);
  } else {
    for (const d of discrepancies) {
      const li = document.createElement("li");
      li.textContent = d;
      details.appendChild(li);
    }
  }

  document.getElementById("config-format-label").textContent = activeConfigFormat === "python" ? "Python" : "YAML";
  document.getElementById("config-preview").textContent = buildConfigSnippet(preset, extraction, refDecision);
}

function applyState(state) {
  document.getElementById("sel-prohib").value = state.prohib;
  document.getElementById("sel-override").value = state.override;
  document.getElementById("sel-prereq").value = state.prereq;
  document.getElementById("sel-citation").value = state.citation;
  updatePlayground();
}

function updateTrace() {
  const selTrace = document.getElementById("sel-trace");
  if (!selTrace) return;
  const mode = selTrace.value;
  const banner = document.getElementById("trace-banner");
  const jsonEl = document.getElementById("trace-json");

  if (mode === "frozen") {
    banner.className = "audit-banner ok";
    banner.innerHTML =
      "<strong>FROZEN REPLAY (0/96 unsafe):</strong> Replaying clean Phase-1 propositions evaluates the v7 policy safely (<code>BLOCK</code>), hiding model regeneration risk.";
    jsonEl.textContent = JSON.stringify(
      {
        mode: "frozen_replay",
        policy_family: "temporal_payment_window_v7",
        evidence_date: "2026-11-25",
        v7_cutoff_date: "2026-11-20",
        replayed_predicate_satisfied: "FALSE",
        checker_decision: "BLOCK",
        reference_decision: "BLOCK",
      },
      null,
      2
    );
  } else {
    banner.className = "audit-banner danger";
    banner.innerHTML =
      "<strong>FRESH REGENERATION FAILURE (7/96 transitions, 6/48 meaning-preserving):</strong> Upstream model re-extracted the expired temporal window as <code>TRUE</code> under v7, causing an unsafe <code>ALLOW</code>.";
    jsonEl.textContent = JSON.stringify(
      {
        mode: "fresh_regeneration",
        policy_family: "temporal_payment_window_v7",
        evidence_date: "2026-11-25",
        v7_cutoff_date: "2026-11-20",
        regenerated_predicate_satisfied: "TRUE",
        checker_decision: "ALLOW (UNSAFE)",
        reference_decision: "BLOCK",
        failure_type: "temporal_binding_error",
      },
      null,
      2
    );
  }
}

function initThemeAndNav() {
  const params = new URLSearchParams(window.location.search);
  const queryTheme = params.get("theme");
  if (queryTheme === "light" || queryTheme === "dark") {
    document.documentElement.setAttribute("data-theme", queryTheme);
  }
  if (params.get("embed") === "playground") {
    document.body.classList.add("embed-playground");
  }
  const themeBtn = document.getElementById("theme-toggle");
  const syncThemeLabel = () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    if (themeBtn) themeBtn.textContent = current === "dark" ? "Light Mode" : "Dark Mode";
  };
  syncThemeLabel();

  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("evidaudit-theme", next);
      syncThemeLabel();
    });
  }

  const mobileBtn = document.getElementById("mobile-menu-btn");
  const navLinks = document.getElementById("nav-links");
  if (mobileBtn && navLinks) {
    mobileBtn.addEventListener("click", () => {
      const open = navLinks.classList.toggle("open");
      mobileBtn.setAttribute("aria-expanded", String(open));
    });
  }
}

function initCopyButtons() {
  const copyInstallBtn = document.getElementById("copy-install-btn");
  if (copyInstallBtn) {
    copyInstallBtn.addEventListener("click", async () => {
      const text = document.getElementById("install-cmd").textContent;
      await navigator.clipboard.writeText(text);
      copyInstallBtn.textContent = "Copied";
      setTimeout(() => (copyInstallBtn.textContent = "Copy"), 1500);
    });
  }

  const copyConfigBtn = document.getElementById("copy-config-btn");
  if (copyConfigBtn) {
    copyConfigBtn.addEventListener("click", async () => {
      const text = document.getElementById("config-preview").textContent;
      await navigator.clipboard.writeText(text);
      copyConfigBtn.textContent = "Copied";
      setTimeout(() => (copyConfigBtn.textContent = "Copy"), 1500);
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initThemeAndNav();
  initCopyButtons();

  // Tabs
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      document.getElementById(tab.dataset.tab).classList.add("active");
    });
  }

  // Presets
  for (const btn of document.querySelectorAll(".preset-btn")) {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".preset-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      activePresetKey = btn.dataset.preset;
      applyState(PRESETS[activePresetKey].initial);
    });
  }

  const step1 = document.getElementById("btn-step1");
  const step2 = document.getElementById("btn-step2");
  const step3 = document.getElementById("btn-step3");
  if (step1) step1.addEventListener("click", () => applyState(PRESETS[activePresetKey].initial));
  if (step2) step2.addEventListener("click", () => applyState(PRESETS[activePresetKey].transition));
  if (step3) step3.addEventListener("click", () => applyState(PRESETS[activePresetKey].repair));

  for (const id of ["sel-prohib", "sel-override", "sel-prereq", "sel-citation"]) {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", updatePlayground);
  }

  const btnYaml = document.getElementById("btn-fmt-yaml");
  const btnPy = document.getElementById("btn-fmt-py");
  if (btnYaml) btnYaml.addEventListener("click", () => { activeConfigFormat = "yaml"; updatePlayground(); });
  if (btnPy) btnPy.addEventListener("click", () => { activeConfigFormat = "python"; updatePlayground(); });

  const selTrace = document.getElementById("sel-trace");
  if (selTrace) selTrace.addEventListener("change", updateTrace);

  const params = new URLSearchParams(window.location.search);
  const stepParam = params.get("step");
  if (stepParam === "2") {
    applyState(PRESETS[activePresetKey].transition);
  } else if (stepParam === "3") {
    applyState(PRESETS[activePresetKey].repair);
  } else {
    updatePlayground();
  }
  updateTrace();
});
