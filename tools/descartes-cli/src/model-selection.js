function parseGptVersion(id) {
  const match = id.match(/^gpt-(\d+(?:\.\d+)*)(?:-|$)/i);
  if (!match) return undefined;
  return match[1].split(".").map((part) => Number(part));
}

function compareVersionDesc(left, right) {
  const max = Math.max(left.length, right.length);
  for (let i = 0; i < max; i += 1) {
    const delta = (right[i] ?? 0) - (left[i] ?? 0);
    if (delta !== 0) return delta;
  }
  return 0;
}

function variantRank(id) {
  if (/pro/i.test(id)) return 100;
  if (/codex-max/i.test(id)) return 90;
  if (/codex$/i.test(id)) return 80;
  if (/spark/i.test(id)) return 20;
  if (/mini|nano/i.test(id)) return 10;
  return 70;
}

function highestGptModel(models) {
  return models
    .map((model) => ({ model, version: parseGptVersion(model.id) }))
    .filter((item) => item.version)
    .sort((left, right) => {
      const version = compareVersionDesc(left.version, right.version);
      if (version !== 0) return version;
      return variantRank(right.model.id) - variantRank(left.model.id);
    })[0]?.model;
}

export function selectTriageModel(available, options = {}) {
  if (options.model) return { model: options.model, thinkingLevel: options.thinkingLevel };

  const matchesPattern = (model, pattern) => {
    const normalized = pattern.toLowerCase();
    return `${model.provider}/${model.id}`.toLowerCase() === normalized ||
      model.id.toLowerCase() === normalized ||
      model.name?.toLowerCase() === normalized ||
      `${model.provider}/${model.id}`.toLowerCase().includes(normalized) ||
      model.name?.toLowerCase().includes(normalized);
  };

  if (options.modelPattern) {
    const requested = available.find((model) => matchesPattern(model, options.modelPattern));
    if (!requested) {
      throw new Error(`Configured credentials do not expose requested model: ${options.modelPattern}`);
    }
    return { model: requested, thinkingLevel: options.thinkingLevel ?? (requested.reasoning ? "high" : "off") };
  }

  for (const provider of ["openai-codex", "github-copilot"]) {
    const model = highestGptModel(available.filter((item) => item.provider === provider));
    if (model) return { model, thinkingLevel: options.thinkingLevel ?? (model.reasoning ? "high" : "off") };
  }

  const model = highestGptModel(available) ?? available[0];
  return { model, thinkingLevel: options.thinkingLevel ?? (model?.reasoning ? "high" : "off") };
}
