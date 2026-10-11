/** Throw before starting a subprocess when the enclosing collector has been cancelled. */
export function throwIfCollectorAborted(signal) {
  if (signal?.aborted) throw new Error("collector_aborted");
}
