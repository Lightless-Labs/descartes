import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { execFile } from "node:child_process";
import { AuthStorage } from "@earendil-works/pi-coding-agent";

function createPrompt() {
  return readline.createInterface({ input, output });
}

function maybeOpen(url) {
  const opener = process.platform === "darwin" ? "open" : process.platform === "linux" ? "xdg-open" : undefined;
  if (!opener) return;
  execFile(opener, [url], { stdio: "ignore" }, () => {});
}

function parseLoginArgs(args) {
  const options = { authType: "oauth", openBrowser: true };
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--provider" || arg === "-p") options.provider = args[++i];
    else if (arg === "--api-key") options.authType = "api_key";
    else if (arg === "--no-open") options.openBrowser = false;
    else if (!arg.startsWith("-") && !options.provider) options.provider = arg;
    else throw new Error(`Unknown login argument: ${arg}`);
  }
  return options;
}

async function chooseProvider(authStorage, requestedProvider) {
  if (requestedProvider) return requestedProvider;
  const providers = authStorage.getOAuthProviders();
  if (providers.length === 0) throw new Error("No OAuth providers are available in the embedded harness.");

  console.log("Available subscription providers:");
  providers.forEach((provider, index) => console.log(`  ${index + 1}. ${provider.name} (${provider.id})`));

  const rl = createPrompt();
  try {
    const answer = await rl.question("Provider number or id: ");
    const trimmed = answer.trim();
    const index = Number(trimmed);
    if (Number.isInteger(index) && index >= 1 && index <= providers.length) return providers[index - 1].id;
    if (providers.some((provider) => provider.id === trimmed)) return trimmed;
    throw new Error(`Unknown provider: ${trimmed}`);
  } finally {
    rl.close();
  }
}

export async function runLogin(paths, args) {
  const options = parseLoginArgs(args);
  const authStorage = AuthStorage.create(paths.authFile);
  const provider = await chooseProvider(authStorage, options.provider);

  if (options.authType === "api_key") {
    const rl = createPrompt();
    try {
      const key = await rl.question(`API key for ${provider}: `);
      if (!key.trim()) throw new Error("API key cannot be empty.");
      authStorage.set(provider, { type: "api_key", key: key.trim() });
      console.log(`Saved API key credentials for ${provider} in ${paths.authFile}`);
      return;
    } finally {
      rl.close();
    }
  }

  const loginCallbacks = {
    onAuth: (info) => {
      console.log("\nOpen this URL to authorize Descartes:");
      console.log(info.url);
      if (info.instructions) console.log(`\n${info.instructions}`);
      if (options.openBrowser) {
        maybeOpen(info.url);
        console.log("Waiting for browser authentication...");
        console.log("If the browser callback cannot complete, rerun with `descartes login --no-open` and paste the redirect URL or code.");
      } else {
        console.log("Paste the final redirect URL or code when prompted below.");
      }
    },
    onPrompt: async (prompt) => {
      const rl = createPrompt();
      try {
        const suffix = prompt.placeholder ? ` (${prompt.placeholder})` : "";
        const value = await rl.question(`${prompt.message}${suffix}: `);
        if (!value && !prompt.allowEmpty) throw new Error("A value is required to continue login.");
        return value;
      } finally {
        rl.close();
      }
    },
    onProgress: (message) => console.log(message),
    onSelect: async (prompt) => {
      console.log(prompt.message);
      prompt.options.forEach((option, index) => console.log(`  ${index + 1}. ${option.label} (${option.id})`));
      const rl = createPrompt();
      try {
        const answer = (await rl.question("Selection: ")).trim();
        const index = Number(answer);
        if (Number.isInteger(index) && index >= 1 && index <= prompt.options.length) return prompt.options[index - 1].id;
        return prompt.options.find((option) => option.id === answer)?.id;
      } finally {
        rl.close();
      }
    },
  };

  if (!options.openBrowser) {
    loginCallbacks.onManualCodeInput = async () => {
      const rl = createPrompt();
      try {
        return await rl.question("Paste redirect URL or code: ");
      } finally {
        rl.close();
      }
    };
  }

  await authStorage.login(provider, loginCallbacks);

  console.log(`Logged in to ${provider}. Credentials stored under Descartes config: ${paths.authFile}`);
}
