// Context plan §6.0, I42: every stream is declared EVENT, LEVEL or NOVELTY, and its kind fixes its
// recovery contract and which explanation sources (labels included) apply to it. This is the static
// DECLARATION of the incumbent rules' kinds (the §6.0 table), not a behaviour rule: it changes no
// detection. A rule that is not declared here has no kind, and no label or closure path ever touches
// it (fail toward keeping alerts open).
//
// Named exception (I42, v3 re-review LOW 2): the incumbent edge-triggered EVENT rules session.churn
// and service.disappeared recover on the next tick; that recovery is logged as recovered(edge_rearm)
// and is never evidence that an event un-happened.

export const STREAM_KINDS = Object.freeze(["event", "level", "novelty"]);

const RULE_STREAM_KIND_ENTRIES = [
  ["session.churn", "event"],
  ["service.disappeared", "event"],
  ["session.count_drop", "level"],
  ["peer.count_drop", "level"],
  ["peer.count_spike", "level"],
  ["service.appeared", "novelty"],
  ["scheduled_job.appeared", "novelty"],
  ["process.lineage.novel_edge", "novelty"],
];

export const RULE_STREAM_KINDS = Object.freeze(new Map(RULE_STREAM_KIND_ENTRIES.map(([ruleId, kind]) => {
  if (!STREAM_KINDS.includes(kind)) throw new Error(`alert-stream-kinds: ${ruleId} has unknown kind ${kind}`);
  return [ruleId, kind];
})));

// Every declared rule above is an incumbent (window-based) detector; C1a narrows them (§6.5).
export const INCUMBENT_RULE_IDS = Object.freeze(new Set(RULE_STREAM_KIND_ENTRIES.map(([ruleId]) => ruleId)));

export const EDGE_REARM_RULE_IDS = Object.freeze(new Set(["session.churn", "service.disappeared"]));

export function streamKindForRule(ruleId) {
  return RULE_STREAM_KINDS.get(String(ruleId ?? "")) ?? null;
}
