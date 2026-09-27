// Cold-start reason labels are presentation metadata only. The detector entry conditions remain
// in each detector and must not depend on this helper's result.

export const INITIAL_BASELINE_REASON = "initial_baseline";
export const HISTORY_LOST_REASON = "history_lost";

/**
 * Choose the label persisted when an existing cold-start entry is recorded.
 *
 * A missing baseline store with no established complete census is the first baseline. A missing
 * baseline store after established complete censuses means the detector lost its history. Existing
 * specific store-loss labels and the corrupt-facts label remain unchanged.
 */
export function coldStartEntryReason({
  storeLossThisTick,
  persistedReason,
  currentGroups = [],
}) {
  if (!storeLossThisTick) return "corrupt_facts";
  if (persistedReason && persistedReason !== "missing_store") return persistedReason;

  const establishedCompleteTickCount = currentGroups.filter((group) => group?.censusState === "complete").length;
  return establishedCompleteTickCount > 1 ? HISTORY_LOST_REASON : INITIAL_BASELINE_REASON;
}
