from __future__ import annotations

import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE_PATH = ROOT / "site" / "index.html"
ASSET_ROOT = ROOT / "site" / "assets"


def _site() -> str:
    return SITE_PATH.read_text(encoding="utf-8")


def test_site_uses_persona_first_request_contract_without_outcome_authority() -> None:
    site = _site()

    assert "persona:state.persona" in site
    assert "persona_token:personaTokens[state.persona]" in site
    assert "journey_id:state.journey" in site
    assert "turn_id:turnId" in site
    assert "scenario_token" not in site
    assert "expected_outcome" not in site
    assert "const scenarios" not in site
    assert "setTimeout(()=>controller.abort(),35000)" in site


def test_site_presents_bounded_events_without_claiming_transport_streaming() -> None:
    site = _site()

    for event_type in (
        "context.bound",
        "policy.decided",
        "memory.authorized",
        "pending.created",
        "boundary.enforced",
        "answer.delta",
        "receipt.verified",
        "turn.complete",
    ):
        assert event_type in site
    assert "Progress is presented in order from one validated API response." in site
    assert "No deterministic substitute or live result is being shown." in site
    assert "EventSource" not in site
    assert "WebSocket" not in site


def test_agent_progress_uses_marketing_copy_and_keeps_technical_proof() -> None:
    site = _site()

    for stage in (
        "Context matched",
        "Useful memory found",
        "Recall approved",
        "Proof attached",
        "Answer ready",
    ):
        assert stage in site
    assert "Signed Recall Receipt" in site
    assert "Decision / reason" in site
    assert "Policy hash" in site
    assert "Signing key" in site


def test_demo_instruction_labels_are_readable_at_a_glance() -> None:
    site = _site()

    assert ".workspace-label strong { color:var(--ink); font-size:.94rem; }" in site
    assert ".workspace-label small { font-size:.82rem; line-height:1.45; }" in site
    assert "Act as a synthetic persona" in site
    assert "Start from a business intent" in site


def test_bedrock_guardrail_block_is_attributed_without_match_details() -> None:
    site = _site()

    assert 'code==="bedrock_guardrail_intervened"' in site
    assert "Amazon Bedrock Guardrails stopped this request" in site
    assert "Amazon Bedrock Guardrails blocked the input" in site
    for category in (
        "hate",
        "insults",
        "sexual content",
        "violence",
        "misconduct",
        "email",
        "phone",
        "US Social Security numbers",
    ):
        assert category in site
    assert "one or more matched" in site
    assert "No Memory Action Gateway decision" in site


def test_catalog_strings_use_text_nodes_not_html_injection_sinks() -> None:
    site = _site()

    assert "innerHTML" not in site
    assert "insertAdjacentHTML" not in site
    assert "document.write" not in site
    assert "textContent=memory.content" not in site
    assert "replaceChildren(emphasis,explanation)" in site


def test_catalog_validation_and_realism_basis_are_bounded() -> None:
    site = _site()

    assert "value.schema_version!==2" in site
    assert 'browse.default_view!=="split-list-detail"' in site
    assert "browse.page_size!==MEMORY_PAGE_SIZE" in site
    assert "value.journeys.filter" in site
    assert "journey.source_keys.some(key=>!sources.has(key))" in site
    assert "memory.source_keys.some(key=>!sources.has(key))" in site
    assert 'basisSummary.textContent="Realism basis"' in site
    assert "basisNote.textContent=memory.realism_note" in site
    assert "memory.summary" in site
    assert "memory.content" not in site
    assert "memory.visible_to_personas" not in site
    assert "has_authorized_internal_detail" not in site


def test_library_is_persona_first_bounded_and_split_view() -> None:
    site = _site()

    assert "const MEMORY_PAGE_SIZE=12" in site
    assert "const MOBILE_MEMORY_PAGE_SIZE=4" in site
    assert "const pageSize=currentMemoryPageSize()" in site
    assert "slice(start,start+pageSize)" in site
    assert 'id="library-search"' in site
    assert 'id="library-persona"' in site
    assert 'id="library-workstream"' in site
    assert 'id="library-source"' in site
    assert 'class="memory-browser"' in site
    assert 'id="memory-detail"' in site
    assert 'class="memory-grid"' not in site


def test_library_persona_focus_is_editorial_and_never_authority() -> None:
    site = _site()

    assert "function isPersonaRelevant(memory)" in site
    assert "function preferredLibraryMemory(page)" in site
    assert (
        "state.catalog._personas.get(state.persona).featured_workstreams.includes(memory.workstream)"
        in site
    )
    assert 'state.libraryMode==="fixture" || isPersonaRelevant(memory)' in site
    assert (
        "const preferred=preferredLibraryMemory(page); "
        "state.selectedMemoryKey=preferred?.catalog_key||null;" in site
    )
    assert (
        "page.find(memory=>memory.catalog_key===state.selectedMemoryKey)||null" in site
    )
    assert "an editorial browsing cue only" in site
    assert "It never grants memory access or changes a gateway decision." in site


def test_mobile_library_bounds_rows_and_focuses_selected_detail() -> None:
    site = _site()

    assert 'window.matchMedia("(max-width: 48rem)")' in site
    assert "mobileLibrary.matches ? MOBILE_MEMORY_PAGE_SIZE : MEMORY_PAGE_SIZE" in site
    assert "if (mobileLibrary.matches) el.memoryDetail.scrollIntoView" in site
    assert 'mobileLibrary.addEventListener("change"' in site


def test_selected_brand_social_metadata_and_assets_are_deterministic() -> None:
    site = _site()

    assert "Critical Context. <span>Controlled Recall.</span>" in site
    assert "gluevenir-mark.svg" not in site  # inline mark avoids an asset-load flash
    assert "Three context nodes converge through a governed red path." in (
        ASSET_ROOT / "gluevenir-mark.svg"
    ).read_text(encoding="utf-8")
    assert (
        'property="og:image" content="https://gluevenir.obsidiantek.io/assets/social-preview.png"'
        in site
    )
    assert '<link rel="icon" type="image/svg+xml" href="./assets/favicon.svg">' in site
    favicon = (ASSET_ROOT / "favicon.svg").read_text(encoding="utf-8")
    assert "Gluevenir connected-context favicon" in favicon
    assert "Three context nodes converge through a governed red path." in favicon
    preview = (ASSET_ROOT / "social-preview.png").read_bytes()
    assert preview[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", preview[16:24]) == (1200, 628)


def test_outbound_obsidiantek_home_links_use_campaign_tracking() -> None:
    site = _site()
    tracked = (
        "https://www.obsidiantek.io/?utm_source=gluevenir&amp;"
        "utm_medium=referral&amp;utm_campaign=agentic_memory_hackathon"
    )

    assert site.count(tracked) == 2
    assert 'href="https://www.linkedin.com/company/obsidiantek/"' in site
    assert 'href="https://www.linkedin.com/in/kris-musard/"' in site
    assert 'rel="canonical" href="https://gluevenir.obsidiantek.io/"' in site
    canonical = site.split('rel="canonical"', 1)[1].split(">", 1)[0]
    assert "utm_" not in canonical


def test_site_has_one_prominent_synthetic_notice_and_observability_navigation() -> None:
    site = _site()

    assert site.count("Synthetic training data") == 1
    assert 'class="compact-synthetic"' in site
    assert 'name="gluevenir-observability-mode" content="hosted"' in site
    assert 'const local=OBSERVABILITY_MODE==="local"' in site
    assert "includes(window.location.hostname)" not in site
    assert site.count('href="./compliance.html"') == 3
    for view in (
        "overview",
        "program_lead",
        "formulation_scientist",
        "clinical_operations_lead",
        "authorized_external_partner",
        "traces",
    ):
        assert f'data-dashboard-view="{view}"' in site
    assert "9e978d5eafa627ea61946044a80f3a41" in site
    assert 'traces:"/jaeger/search?service=gluevenir-bio&lookback=1h&limit=20"' in site
    assert "#dashboard-frame { display:block; width:100%; height:120rem;" in site
    assert '#dashboard-frame[data-dashboard-view="traces"] { height:72rem; }' in site
    assert "el.dashboardFrame.dataset.dashboardView=view" in site


def test_reduced_motion_and_character_counts_use_matching_contracts() -> None:
    site = _site()

    assert "animation:none!important" in site
    assert "Array.from(summary).length" in site
    assert "zero retrieval, model, and write side effects" not in site


def test_decision_surfaces_use_outcome_colors_without_flashing() -> None:
    site = _site()

    assert "el.result.dataset.decision=decision" in site
    assert "delete el.result.dataset.decision" in site
    assert '.result[data-decision="STEP_UP"] { --decision-color:var(--step)' in site
    assert '.result[data-decision="DENY"] { --decision-color:var(--deny)' in site
    assert (
        '.result[data-decision] .governance-step[data-state="complete"]::before' in site
    )
    assert ".result[data-decision] .memory-card.approved" in site
    assert ".result[data-decision] .boundary" in site
    assert "@keyframes pulse" not in site
    assert "animation:pulse" not in site


def test_landing_uses_concise_agentic_story_and_five_step_architecture() -> None:
    site = _site()

    assert 'class="action-standards"' in site
    assert (
        "An AARM-inspired gateway decides before supported memory actions execute."
        in site
    )
    assert "Selected AIUC-1 implementation evidence" in site
    assert "Inspired by standards. Bounded by evidence." not in site
    assert 'class="control-grid"' not in site
    for step in (
        "01 · Ask",
        "02 · Recall",
        "03 · Decide",
        "04 · Generate",
        "05 · Prove",
    ):
        assert step in site
    for decision in ("ALLOW", "MODIFY", "STEP_UP", "DEFER", "DENY"):
        assert f'class="decision-feature" data-decision="{decision}"' in site


def test_chat_geometry_and_mobile_architecture_are_bounded() -> None:
    site = _site()

    assert ".governance-stream,.intercept,.receipt { width:calc(100% - 2.95rem)" in site
    assert ".message { width:100%; min-width:0; max-width:none;" in site
    assert (
        ".system-visual { display:grid; gap:.6rem; height:auto; min-height:0;" in site
    )
    assert ".system-plane { position:relative; inset:auto; width:100%;" in site
    assert (
        ".intercept,.receipt,.governance-stream { width:100%; margin-left:0; }" in site
    )


def test_memory_library_has_fictional_program_context_without_em_dashes() -> None:
    site = _site()

    assert (
        ".library-head { display:grid; grid-template-columns:minmax(22rem,.72fr) "
        "minmax(34rem,1.28fr);" in site
    )
    assert "align-items:end; max-width:none;" in site
    assert "HelixCure Synthetic Labs is advancing HX-17" in site
    assert "wholly fictional investigational monoclonal antibody" in site
    assert "rare complement-mediated inflammatory disorder" in site
    assert "protocol HC-HX17-101 v1.3" in site
    assert "formulation HX17-F3" in site
    assert "Harborlight Research Center Site SYN-03" in site
    assert "Argent Bridge Biologics" in site
    assert "—" not in site
