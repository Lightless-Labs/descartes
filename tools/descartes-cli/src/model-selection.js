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

function parseClaudeModel(id) {
  const newFormat = id.match(/^claude-(sonnet|opus|haiku)-(.+)$/i);
  if (newFormat) {
    const parts = newFormat[2].split("-");
    const maybeDate = parts.at(-1);
    const date = maybeDate && /^\d{8}$/.test(maybeDate) ? Number(parts.pop()) : 0;
    const version = parts.map((part) => Number(part));
    if (version.length > 0 && version.every(Number.isFinite)) {
      return { family: newFormat[1].toLowerCase(), version, date };
    }
  }

  const oldFormat = id.match(/^claude-(.+)-(sonnet|opus|haiku)(?:-(\d{8}|latest))?$/i);
  if (oldFormat) {
    const version = oldFormat[1].split("-").map((part) => Number(part));
    if (version.length > 0 && version.every(Number.isFinite)) {
      return {
        family: oldFormat[2].toLowerCase(),
        version,
        date: oldFormat[3] && oldFormat[3] !== "latest" ? Number(oldFormat[3]) : 0,
      };
    }
  }

  return undefined;
}

function familyRank(family) {
  if (family === "sonnet") return 100;
  if (family === "opus") return 80;
  if (family === "haiku") return 20;
  return 0;
}

function highestClaudeModel(models) {
  return models
    .map((model) => ({ model, parsed: parseClaudeModel(model.id) }))
    .filter((item) => item.parsed)
    .sort((left, right) => {
      const family = familyRank(right.parsed.family) - familyRank(left.parsed.family);
      if (family !== 0) return family;
      const version = compareVersionDesc(left.parsed.version, right.parsed.version);
      if (version !== 0) return version;
      return right.parsed.date - left.parsed.date;
    })[0]?.model;
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

  const anthropicModel = highestClaudeModel(available.filter((item) => item.provider === "anthropic"));
  if (anthropicModel) {
    return { model: anthropicModel, thinkingLevel: options.thinkingLevel ?? (anthropicModel.reasoning ? "high" : "off") };
  }

  const model = highestGptModel(available) ?? available[0];
  return { model, thinkingLevel: options.thinkingLevel ?? (model?.reasoning ? "high" : "off") };
}
