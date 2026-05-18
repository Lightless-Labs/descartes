export function evidenceEnvelope({ id, status = "ok", source, result, confidence = 1, reviewHint = "none", tool, target }) {
  return {
    id,
    status,
    layer: "L0",
    source,
    result,
    confidence,
    review_hint: reviewHint,
    trace: {
      tool,
      target,
      latency_ms: 0,
      ts: new Date().toISOString(),
    },
  };
}

export async function timedEnvelope(fn, envelope) {
  const started = Date.now();
  try {
    const result = await fn();
    const built = envelope(result);
    built.trace.latency_ms = Date.now() - started;
    return built;
  } catch (error) {
    const built = envelope({ error: error instanceof Error ? error.message : String(error) });
    built.status = "unable";
    built.confidence = 0;
    built.review_hint = "missing_permission";
    built.trace.latency_ms = Date.now() - started;
    return built;
  }
}
