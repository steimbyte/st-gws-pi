import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";

const EXTENSION_NAME = "google-workspace";
const CONFIG_DIR = join(homedir(), ".pi", "agent", "google-workspace");
const CONFIG_PATH = join(CONFIG_DIR, "oauth.json");
const DEFAULT_REDIRECT_URI = "http://127.0.0.1:53682/oauth2callback";
const OAUTH_SCOPE = [
  "https://www.googleapis.com/auth/drive",
  "https://www.googleapis.com/auth/documents",
  "https://www.googleapis.com/auth/presentations",
  "https://www.googleapis.com/auth/spreadsheets",
  "https://www.googleapis.com/auth/calendar",
  "https://www.googleapis.com/auth/calendar.events",
  "https://www.googleapis.com/auth/chat.messages",
  "https://www.googleapis.com/auth/contacts",
].join(" ");

type OAuthTokens = {
  access_token: string;
  refresh_token?: string;
  token_type?: string;
  scope?: string;
  expiry_date?: number;
};

type AuthConfig = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  tokens: OAuthTokens;
};

type JsonMap = Record<string, unknown>;
type DocExportFormat = "pdf" | "docx" | "txt" | "md" | "rtf" | "odt" | "html_zip";

const DOC_EXPORT_MAP: Record<Exclude<DocExportFormat, "md">, { mime: string; ext: string }> = {
  pdf: { mime: "application/pdf", ext: "pdf" },
  docx: { mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ext: "docx" },
  txt: { mime: "text/plain", ext: "txt" },
  rtf: { mime: "application/rtf", ext: "rtf" },
  odt: { mime: "application/vnd.oasis.opendocument.text", ext: "odt" },
  html_zip: { mime: "application/zip", ext: "zip" },
};

async function ensureConfigDir() {
  await mkdir(CONFIG_DIR, { recursive: true });
}

async function readConfig(): Promise<AuthConfig | null> {
  try {
    const raw = await readFile(CONFIG_PATH, "utf-8");
    const parsed = JSON.parse(raw) as AuthConfig;
    if (!parsed?.clientId || !parsed?.clientSecret || !parsed?.tokens?.access_token) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function saveConfig(config: AuthConfig) {
  await ensureConfigDir();
  await writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

function isExpired(tokens: OAuthTokens) {
  if (!tokens.expiry_date) return false;
  return Date.now() >= tokens.expiry_date - 60_000;
}

function parseJson(text: string): JsonMap {
  try {
    return JSON.parse(text) as JsonMap;
  } catch {
    return {};
  }
}

async function refreshToken(config: AuthConfig, signal?: AbortSignal): Promise<AuthConfig> {
  if (!config.tokens.refresh_token) {
    throw new Error("No refresh_token found. Run /gws-setup again.");
  }

  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    refresh_token: config.tokens.refresh_token,
    grant_type: "refresh_token",
  });

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal,
  });

  const text = await res.text();
  const data = parseJson(text);

  if (!res.ok || typeof data.access_token !== "string") {
    const message = typeof data.error_description === "string" ? data.error_description : "Token refresh failed";
    throw new Error(message);
  }

  const expiresIn = typeof data.expires_in === "number" ? data.expires_in : 3600;
  const nextConfig: AuthConfig = {
    ...config,
    tokens: {
      ...config.tokens,
      access_token: data.access_token,
      token_type: typeof data.token_type === "string" ? data.token_type : config.tokens.token_type,
      scope: typeof data.scope === "string" ? data.scope : config.tokens.scope,
      expiry_date: Date.now() + expiresIn * 1000,
    },
  };

  await saveConfig(nextConfig);
  return nextConfig;
}

async function getValidConfig(signal?: AbortSignal): Promise<AuthConfig> {
  const config = await readConfig();
  if (!config) {
    throw new Error(`Google Workspace credentials not found. Run /gws-setup and try again. (${CONFIG_PATH})`);
  }

  if (isExpired(config.tokens)) return refreshToken(config, signal);
  return config;
}

function resolveGoogleApiUrl(path: string) {
  if (path.startsWith("/v1/documents")) return new URL(`https://docs.googleapis.com${path}`);
  if (path.startsWith("/v1/presentations")) return new URL(`https://slides.googleapis.com${path}`);
  if (path.startsWith("/v4/spreadsheets")) return new URL(`https://sheets.googleapis.com${path}`);
  if (path.startsWith("/calendar/")) return new URL(`https://www.googleapis.com/calendar/v3${path.replace('/calendar', '')}`);
  if (path.startsWith("/v1/spaces") || path.startsWith("/v1/") && path.includes("chat")) return new URL(`https://chat.googleapis.com${path}`);
  if (path.startsWith("/v1/people")) return new URL(`https://people.googleapis.com${path}`);
  return new URL(`https://www.googleapis.com${path}`);
}

async function googleRequest(
  path: string,
  options: {
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
    query?: Record<string, string | number | boolean | undefined>;
    body?: JsonMap;
    signal?: AbortSignal;
  } = {},
): Promise<JsonMap> {
  const config = await getValidConfig(options.signal);

  const url = resolveGoogleApiUrl(path);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value === undefined) continue;
    url.searchParams.set(key, String(value));
  }

  const makeRequest = async (accessToken: string) => {
    const res = await fetch(url, {
      method: options.method ?? "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: options.signal,
    });

    const text = await res.text();
    const data = parseJson(text);
    return { res, data };
  };

  let { res, data } = await makeRequest(config.tokens.access_token);

  if (res.status === 401 && config.tokens.refresh_token) {
    const refreshed = await refreshToken(config, options.signal);
    ({ res, data } = await makeRequest(refreshed.tokens.access_token));
  }

  if (!res.ok) {
    const message =
      typeof (data.error as JsonMap | undefined)?.message === "string"
        ? ((data.error as JsonMap).message as string)
        : `Google API error (${res.status})`;
    throw new Error(message);
  }

  return data;
}

async function googleBinaryRequest(
  path: string,
  options: {
    query?: Record<string, string | number | boolean | undefined>;
    signal?: AbortSignal;
  } = {},
) {
  const config = await getValidConfig(options.signal);

  const url = resolveGoogleApiUrl(path);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value === undefined) continue;
    url.searchParams.set(key, String(value));
  }

  const makeRequest = async (accessToken: string) =>
    fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: options.signal,
    });

  let res = await makeRequest(config.tokens.access_token);

  if (res.status === 401 && config.tokens.refresh_token) {
    const refreshed = await refreshToken(config, options.signal);
    res = await makeRequest(refreshed.tokens.access_token);
  }

  if (!res.ok) {
    const text = await res.text();
    const data = parseJson(text);
    const message =
      typeof (data.error as JsonMap | undefined)?.message === "string"
        ? ((data.error as JsonMap).message as string)
        : `Google API error (${res.status})`;
    throw new Error(message);
  }

  const bytes = new Uint8Array(await res.arrayBuffer());
  return {
    bytes,
    contentType: res.headers.get("content-type") ?? "application/octet-stream",
  };
}

async function googleDriveMultipartUpload(
  metadata: JsonMap,
  fileBytes: Uint8Array,
  mimeType: string,
  signal?: AbortSignal,
) {
  const config = await getValidConfig(signal);
  const boundary = `pi-boundary-${randomBytes(8).toString("hex")}`;

  const preamble = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`;
  const middle = `--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`;
  const closing = `\r\n--${boundary}--`;
  const body = Buffer.concat([Buffer.from(preamble + middle, "utf-8"), Buffer.from(fileBytes), Buffer.from(closing, "utf-8")]);

  const doUpload = async (accessToken: string) => {
    const url = new URL("https://www.googleapis.com/upload/drive/v3/files");
    url.searchParams.set("uploadType", "multipart");
    url.searchParams.set("fields", "id,name,mimeType,webViewLink,parents");

    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": `multipart/related; boundary=${boundary}`,
      },
      body,
      signal,
    });

    const text = await res.text();
    return { res, data: parseJson(text) };
  };

  let { res, data } = await doUpload(config.tokens.access_token);

  if (res.status === 401 && config.tokens.refresh_token) {
    const refreshed = await refreshToken(config, signal);
    ({ res, data } = await doUpload(refreshed.tokens.access_token));
  }

  if (!res.ok) {
    const message =
      typeof (data.error as JsonMap | undefined)?.message === "string"
        ? ((data.error as JsonMap).message as string)
        : `Google API error (${res.status})`;
    throw new Error(message);
  }

  return data;
}

function safeFilename(input: string) {
  return input
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120) || "document";
}

function normalizeOutputPath(cwd: string, outputPath: string | undefined, fallbackName: string) {
  const candidate = outputPath?.trim() ? outputPath.trim() : fallbackName;
  return resolve(cwd, candidate.replace(/^@/, ""));
}

function normalizeText(text: string) {
  return text.replace(/\r\n/g, "\n").replace(/\u000b/g, "\n");
}

function escapeMdInline(text: string) {
  return text.replace(/([\\`*_{}\[\]()#+\-.!|>~])/g, "\\$1");
}

function escapeMdTableCell(text: string) {
  return text.replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

function applyInlineStyle(text: string, style: JsonMap | undefined): string {
  if (!text) return "";
  const trimmed = text.trim();
  if (!trimmed) return escapeMdInline(text);

  const trimmedIndex = text.indexOf(trimmed);
  const left = text.slice(0, trimmedIndex);
  const right = text.slice(trimmedIndex + trimmed.length);
  let core = escapeMdInline(trimmed);

  const link = style?.link as JsonMap | undefined;
  const url = typeof link?.url === "string" ? link.url : undefined;

  const bold = style?.bold === true;
  const italic = style?.italic === true;
  const strike = style?.strikethrough === true;

  if (bold) core = `**${core}**`;
  if (italic) core = `*${core}*`;
  if (strike) core = `~~${core}~~`;
  if (url) core = `[${core}](${url})`;

  return `${left}${core}${right}`;
}

function paragraphTextFromElements(elements: JsonMap[] | undefined): string {
  if (!Array.isArray(elements)) return "";

  const chunks: string[] = [];
  for (const element of elements) {
    const run = element.textRun as JsonMap | undefined;
    const content = typeof run?.content === "string" ? run.content : "";
    if (!content) continue;
    const styled = applyInlineStyle(normalizeText(content), run?.textStyle as JsonMap | undefined);
    chunks.push(styled);
  }

  return chunks.join("").replace(/\n+$/g, "").trim();
}

function isOrderedGlyph(glyphType: string | undefined) {
  if (!glyphType) return false;
  return ["DECIMAL", "ALPHA", "ROMAN"].some((token) => glyphType.includes(token));
}

function getHeadingPrefix(namedStyleType: string | undefined): string {
  if (!namedStyleType) return "";
  if (namedStyleType === "TITLE") return "#";
  if (namedStyleType === "SUBTITLE") return "##";
  const match = namedStyleType.match(/^HEADING_(\d)$/);
  if (!match) return "";
  const level = Number(match[1]);
  if (!Number.isFinite(level) || level < 1 || level > 6) return "";
  return "#".repeat(level);
}

function tableToMarkdown(table: JsonMap, lists: JsonMap | undefined) {
  const rows = table.tableRows as JsonMap[] | undefined;
  if (!Array.isArray(rows) || rows.length === 0) return "";

  const renderedRows = rows.map((row) => {
    const cells = row.tableCells as JsonMap[] | undefined;
    if (!Array.isArray(cells)) return [] as string[];

    return cells.map((cell) => {
      if (!cell) return "";
      const content = cell.content as JsonMap[] | undefined;
      if (!Array.isArray(content)) return "";
      const chunks = content
        .map((block) => blockToMarkdown(block, lists))
        .join("\n")
        .replace(/\n{2,}/g, "\n")
        .trim();
      return escapeMdTableCell(chunks);
    });
  });

  if (renderedRows.length === 0) return "";
  const colCount = Math.max(...renderedRows.map((row) => row.length), 1);

  const normalizeRow = (row: string[]) => {
    const cells = [...row];
    while (cells.length < colCount) cells.push("");
    return `| ${cells.join(" | ")} |`;
  };

  const header = normalizeRow(renderedRows[0]);
  const divider = `| ${new Array(colCount).fill("---").join(" | ")} |`;
  const body = renderedRows.slice(1).map(normalizeRow);
  return [header, divider, ...body].join("\n");
}

function blockToMarkdown(block: JsonMap, lists: JsonMap | undefined, listState?: Map<string, number>): string {
  const paragraph = block.paragraph as JsonMap | undefined;
  if (paragraph) {
    const elements = paragraph.elements as JsonMap[] | undefined;
    const text = paragraphTextFromElements(elements);

    const style = paragraph.paragraphStyle as JsonMap | undefined;
    const namedStyleType = typeof style?.namedStyleType === "string" ? style.namedStyleType : undefined;
    const heading = getHeadingPrefix(namedStyleType);
    if (heading && text) return `${heading} ${text}`;

    const bullet = paragraph.bullet as JsonMap | undefined;
    if (bullet) {
      const listId = typeof bullet.listId === "string" ? bullet.listId : "default";
      const nestingLevel = typeof bullet.nestingLevel === "number" ? bullet.nestingLevel : 0;
      const listInfo = (lists?.[listId] as JsonMap | undefined)?.listProperties as JsonMap | undefined;
      const levels = listInfo?.nestingLevels as JsonMap[] | undefined;
      const glyphType = typeof levels?.[nestingLevel]?.glyphType === "string" ? (levels[nestingLevel].glyphType as string) : undefined;
      const ordered = isOrderedGlyph(glyphType);

      const state = listState ?? new Map<string, number>();
      const key = `${listId}:${nestingLevel}`;
      const count = (state.get(key) ?? 0) + 1;
      state.set(key, count);

      for (const existingKey of Array.from(state.keys())) {
        if (!existingKey.startsWith(`${listId}:`)) continue;
        const level = Number(existingKey.split(":")[1]);
        if (Number.isFinite(level) && level > nestingLevel) state.delete(existingKey);
      }

      const indent = "  ".repeat(Math.max(0, nestingLevel));
      const marker = ordered ? `${count}.` : "-";
      return `${indent}${marker} ${text}`.trimEnd();
    }

    return text;
  }

  const table = block.table as JsonMap | undefined;
  if (table) return tableToMarkdown(table, lists);

  return "";
}

function toMarkdownFromDocument(document: JsonMap) {
  const body = (document.body as JsonMap | undefined)?.content as JsonMap[] | undefined;
  if (!Array.isArray(body) || body.length === 0) return "";

  const lists = document.lists as JsonMap | undefined;
  const listState = new Map<string, number>();
  const chunks: string[] = [];

  for (const block of body) {
    const rendered = blockToMarkdown(block, lists, listState).trim();
    if (!rendered) continue;
    chunks.push(rendered);
  }

  const markdown = chunks.join("\n\n").replace(/\n{3,}/g, "\n\n").trim();
  return markdown ? `${markdown}\n` : "";
}

function sheetValuesToText(values: unknown[][]) {
  if (!Array.isArray(values) || values.length === 0) return "(no data)";

  return values
    .map((row) => (Array.isArray(row) ? row.map((cell) => String(cell ?? "")).join("\t") : ""))
    .join("\n");
}

function getDocEndIndex(document: JsonMap): number {
  const body = (document.body as JsonMap | undefined)?.content as JsonMap[] | undefined;
  if (!Array.isArray(body) || body.length === 0) return 1;

  const last = body[body.length - 1];
  const endIndex = typeof last.endIndex === "number" ? last.endIndex : 1;
  return Math.max(1, endIndex);
}

function extractDocText(document: JsonMap): string {
  const body = (document.body as JsonMap | undefined)?.content as JsonMap[] | undefined;
  if (!Array.isArray(body)) return "";

  const chunks: string[] = [];

  for (const block of body) {
    const paragraph = block.paragraph as JsonMap | undefined;
    const elements = paragraph?.elements as JsonMap[] | undefined;
    if (!Array.isArray(elements)) continue;

    for (const element of elements) {
      const run = element.textRun as JsonMap | undefined;
      const content = run?.content;
      if (typeof content === "string") chunks.push(content);
    }
  }

  return chunks.join("").trim();
}

function getDocInsertIndex(document: JsonMap): number {
  const body = (document.body as JsonMap | undefined)?.content as JsonMap[] | undefined;
  if (!Array.isArray(body) || body.length === 0) return 1;

  const last = body[body.length - 1];
  const endIndex = typeof last.endIndex === "number" ? last.endIndex : 1;
  return Math.max(1, endIndex - 1);
}

function extractSlidesText(presentation: JsonMap) {
  const slides = presentation.slides as JsonMap[] | undefined;
  if (!Array.isArray(slides)) return [] as Array<{ slideId: string; index: number; text: string }>;

  return slides.map((slide, index) => {
    const pageElements = slide.pageElements as JsonMap[] | undefined;
    const chunks: string[] = [];

    if (Array.isArray(pageElements)) {
      for (const pageElement of pageElements) {
        const shape = pageElement.shape as JsonMap | undefined;
        const text = shape?.text as JsonMap | undefined;
        const elements = text?.textElements as JsonMap[] | undefined;

        if (!Array.isArray(elements)) continue;

        for (const element of elements) {
          const run = element.textRun as JsonMap | undefined;
          const content = run?.content;
          if (typeof content === "string") chunks.push(content);
        }
      }
    }

    return {
      slideId: typeof slide.objectId === "string" ? slide.objectId : `slide-${index + 1}`,
      index: index + 1,
      text: chunks.join("").trim(),
    };
  });
}

function authUrl(config: { clientId: string; redirectUri: string; state: string }) {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", OAUTH_SCOPE);
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("state", config.state);
  return url.toString();
}

async function waitForAuthCode(redirectUri: string, expectedState: string, timeoutMs = 180_000): Promise<string> {
  const callback = new URL(redirectUri);
  const host = callback.hostname;
  const port = Number(callback.port || (callback.protocol === "https:" ? 443 : 80));
  const expectedPath = callback.pathname;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      server.close();
      reject(new Error("OAuth authorization timed out."));
    }, timeoutMs);

    const server = createServer((req, res) => {
      try {
        const reqUrl = new URL(req.url || "/", `${callback.protocol}//${req.headers.host}`);
        if (reqUrl.pathname !== expectedPath) {
          res.statusCode = 404;
          res.end("Not Found");
          return;
        }

        const error = reqUrl.searchParams.get("error");
        if (error) {
          res.statusCode = 400;
          res.end("Authorization failed. You can close this tab.");
          clearTimeout(timer);
          server.close();
          reject(new Error(`OAuth error: ${error}`));
          return;
        }

        const state = reqUrl.searchParams.get("state");
        const code = reqUrl.searchParams.get("code");

        if (state !== expectedState || !code) {
          res.statusCode = 400;
          res.end("Invalid callback. You can close this tab.");
          clearTimeout(timer);
          server.close();
          reject(new Error("Failed to validate state or receive authorization code."));
          return;
        }

        res.statusCode = 200;
        res.setHeader("content-type", "text/html; charset=utf-8");
        res.end("<h2>Google authentication completed.</h2><p>You can close this tab and return to pi.</p>");

        clearTimeout(timer);
        server.close();
        resolve(code);
      } catch (error) {
        clearTimeout(timer);
        server.close();
        reject(error as Error);
      }
    });

    server.listen(port, host, () => undefined);
    server.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function exchangeCodeForToken(params: {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  code: string;
}) {
  const body = new URLSearchParams({
    client_id: params.clientId,
    client_secret: params.clientSecret,
    code: params.code,
    grant_type: "authorization_code",
    redirect_uri: params.redirectUri,
  });

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const text = await res.text();
  const data = parseJson(text);

  if (!res.ok || typeof data.access_token !== "string") {
    const message = typeof data.error_description === "string" ? data.error_description : "Failed to issue token";
    throw new Error(message);
  }

  const expiresIn = typeof data.expires_in === "number" ? data.expires_in : 3600;

  return {
    access_token: data.access_token,
    refresh_token: typeof data.refresh_token === "string" ? data.refresh_token : undefined,
    token_type: typeof data.token_type === "string" ? data.token_type : "Bearer",
    scope: typeof data.scope === "string" ? data.scope : OAUTH_SCOPE,
    expiry_date: Date.now() + expiresIn * 1000,
  } satisfies OAuthTokens;
}

async function openBrowser(pi: ExtensionAPI, url: string) {
  const platform = process.platform;

  if (platform === "darwin") {
    await pi.exec("open", [url]);
    return;
  }

  if (platform === "win32") {
    await pi.exec("cmd", ["/c", "start", "", url]);
    return;
  }

  await pi.exec("xdg-open", [url]);
}

export default function googleWorkspaceExtension(pi: ExtensionAPI) {
  pi.registerCommand("gws-setup", {
    description: "Configure Google Workspace OAuth (personal account)",
    handler: async (_args, ctx) => {
      const existing = await readConfig();
      if (existing) {
        const overwrite = await ctx.ui.confirm(
          "Existing configuration found",
          `A configuration file already exists. Overwrite it?\n${CONFIG_PATH}`,
        );
        if (!overwrite) return;
      }

      const clientId = await ctx.ui.input("Google OAuth Client ID", "...apps.googleusercontent.com");
      if (!clientId) return;

      const clientSecret = await ctx.ui.input("Google OAuth Client Secret", "GOCSPX-...");
      if (!clientSecret) return;

      const redirectUriInput = await ctx.ui.input("Redirect URI", DEFAULT_REDIRECT_URI);
      const redirectUri = redirectUriInput?.trim() || DEFAULT_REDIRECT_URI;

      let parsedRedirect: URL;
      try {
        parsedRedirect = new URL(redirectUri);
      } catch {
        ctx.ui.notify("Redirect URI format is invalid.", "error");
        return;
      }

      if (!["http:", "https:"].includes(parsedRedirect.protocol)) {
        ctx.ui.notify("Redirect URI must use http or https.", "error");
        return;
      }

      const state = randomBytes(12).toString("hex");
      const url = authUrl({ clientId: clientId.trim(), redirectUri, state });

      ctx.ui.notify("Opening your browser to start Google authentication...", "info");
      try {
        await openBrowser(pi, url);
      } catch {
        ctx.ui.notify("Failed to open browser automatically. Open this URL manually:", "warning");
        ctx.ui.notify(url, "info");
      }

      let code = "";
      try {
        code = await waitForAuthCode(redirectUri, state);
      } catch (error) {
        ctx.ui.notify(`Automatic callback failed: ${(error as Error).message}`, "warning");
        const manualCode = await ctx.ui.input("Paste the authorization code", "4/0A...");
        if (!manualCode) return;
        code = manualCode.trim();
      }

      try {
        const tokens = await exchangeCodeForToken({
          clientId: clientId.trim(),
          clientSecret: clientSecret.trim(),
          redirectUri,
          code,
        });

        const config: AuthConfig = {
          clientId: clientId.trim(),
          clientSecret: clientSecret.trim(),
          redirectUri,
          tokens: {
            ...tokens,
            refresh_token: tokens.refresh_token ?? existing?.tokens.refresh_token,
          },
        };

        await saveConfig(config);
        ctx.ui.notify(`Configuration saved: ${CONFIG_PATH}`, "info");
      } catch (error) {
        ctx.ui.notify(`Configuration failed: ${(error as Error).message}`, "error");
      }
    },
  });

  pi.registerCommand("gws-logout", {
    description: "Delete local Google Workspace credentials",
    handler: async (_args, ctx) => {
      const ok = await ctx.ui.confirm("Delete credentials", `Delete this file?\n${CONFIG_PATH}`);
      if (!ok) return;

      try {
        await rm(CONFIG_PATH, { force: true });
        ctx.ui.notify("Credentials deleted.", "info");
      } catch (error) {
        ctx.ui.notify(`Deletion failed: ${(error as Error).message}`, "error");
      }
    },
  });

  pi.registerTool({
    name: "google_workspace_status",
    label: "Google Workspace Status",
    description: "Check Google Workspace OAuth configuration status.",
    promptSnippet: "Check whether Google Workspace OAuth is configured and token status.",
    parameters: Type.Object({}),
    async execute() {
      const config = await readConfig();
      const baseDetails = { configPath: CONFIG_PATH };

      if (!config) {
        return {
          content: [{ type: "text", text: `Not configured. Run /gws-setup. (${CONFIG_PATH})` }],
          details: { ...baseDetails, configured: false, refreshToken: false, expiresAt: null as number | null, expired: null as boolean | null },
        };
      }

      const expiresAt = config.tokens.expiry_date ?? null;
      const refreshAvailable = !!config.tokens.refresh_token;
      const now = Date.now();
      const isExpired = expiresAt ? now > expiresAt : null;

      return {
        content: [
          {
            type: "text",
            text: [
              "Google Workspace connection status",
              `- config: ${CONFIG_PATH}`,
              `- refresh_token: ${refreshAvailable ? "yes" : "no"}`,
              `- expires: ${expiresAt ? new Date(expiresAt).toISOString() : "unknown"}`,
              `- expired: ${expiresAt ? String(now > expiresAt) : "unknown"}`,
            ].join("\n"),
          },
        ],
        details: { ...baseDetails, configured: true, refreshToken: refreshAvailable, expiresAt, expired: isExpired },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_list",
    label: "Google Drive List",
    description: "List files in Google Drive with optional query.",
    promptSnippet: "List Google Drive files by query, mime type, and page size.",
    parameters: Type.Object({
      query: Type.Optional(Type.String({ description: "Drive query. Example: trashed = false" })),
      pageSize: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest("/drive/v3/files", {
        query: {
          q: params.query ?? "trashed = false",
          pageSize: params.pageSize ?? 20,
          fields: "files(id,name,mimeType,modifiedTime,webViewLink),nextPageToken",
          orderBy: "modifiedTime desc",
        },
        signal,
      });

      const files = Array.isArray(data.files) ? (data.files as JsonMap[]) : [];
      const lines = files.map((file, idx) => {
        const id = typeof file.id === "string" ? file.id : "";
        const name = typeof file.name === "string" ? file.name : "(no name)";
        const mime = typeof file.mimeType === "string" ? file.mimeType : "unknown";
        const modified = typeof file.modifiedTime === "string" ? file.modifiedTime : "";
        return `${idx + 1}. ${name}\n   - id: ${id}\n   - mime: ${mime}\n   - modified: ${modified}`;
      });

      return {
        content: [{ type: "text", text: lines.length > 0 ? lines.join("\n") : "No files found." }],
        details: { files, count: files.length, nextPageToken: data.nextPageToken ?? null },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_download",
    label: "Google Drive Download",
    description: "Download a non-Google file from Drive to local path.",
    promptSnippet: "Download Drive binary files to local filesystem.",
    parameters: Type.Object({
      fileId: Type.String({ description: "Drive file ID" }),
      outputPath: Type.Optional(Type.String({ description: "Optional local output path" })),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      if (!params.fileId?.trim()) {
        throw new Error("fileId is required and cannot be empty");
      }
      
      const metadata = await googleRequest(`/drive/v3/files/${encodeURIComponent(params.fileId)}`, {
        query: { fields: "id,name,mimeType" },
        signal,
      });

      const name = typeof metadata.name === "string" ? metadata.name : params.fileId;
      const mimeType = typeof metadata.mimeType === "string" ? metadata.mimeType : "application/octet-stream";
      if (mimeType.startsWith("application/vnd.google-apps")) {
        throw new Error("This is a Google-native file type. Use a dedicated export tool (for example google_docs_download).");
      }

      const binary = await googleBinaryRequest(`/drive/v3/files/${encodeURIComponent(params.fileId)}`, {
        query: { alt: "media" },
        signal,
      });

      const outputFile = normalizeOutputPath(ctx.cwd, params.outputPath, safeFilename(name));
      await mkdir(dirname(outputFile), { recursive: true });
      await writeFile(outputFile, binary.bytes);

      return {
        content: [{ type: "text", text: `Drive download complete\n- name: ${name}\n- path: ${outputFile}` }],
        details: { fileId: params.fileId, name, mimeType, outputPath: outputFile, bytesWritten: binary.bytes.byteLength },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_upload",
    label: "Google Drive Upload",
    description: "Upload a local file to Google Drive.",
    promptSnippet: "Upload local file into Google Drive and return file id.",
    parameters: Type.Object({
      localPath: Type.String({ description: "Local path to upload" }),
      name: Type.Optional(Type.String({ description: "Optional file name in Drive" })),
      parentId: Type.Optional(Type.String({ description: "Optional destination folder id" })),
      mimeType: Type.Optional(Type.String({ description: "Optional mime type" })),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const localPath = resolve(ctx.cwd, params.localPath.replace(/^@/, ""));
      
      let bytes: Buffer;
      try {
        bytes = await readFile(localPath);
      } catch (err) {
        throw new Error(`Failed to read file: ${localPath} - ${(err as Error).message}`);
      }
      
      const driveName = params.name?.trim() || basename(localPath);
      const mimeType = params.mimeType?.trim() || "application/octet-stream";

      const metadata: JsonMap = { name: driveName };
      if (params.parentId) metadata.parents = [params.parentId];

      const uploaded = await googleDriveMultipartUpload(metadata, new Uint8Array(bytes), mimeType, signal);
      const fileId = typeof uploaded.id === "string" ? uploaded.id : "";
      const webViewLink = typeof uploaded.webViewLink === "string" ? uploaded.webViewLink : "";

      return {
        content: [
          {
            type: "text",
            text: `Drive upload complete\n- id: ${fileId}\n- name: ${driveName}${webViewLink ? `\n- url: ${webViewLink}` : ""}`,
          },
        ],
        details: { fileId, name: driveName, webViewLink, localPath, mimeType },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_create_folder",
    label: "Google Drive Create Folder",
    description: "Create a folder in Google Drive.",
    promptSnippet: "Create Drive folder and return folder id.",
    parameters: Type.Object({
      name: Type.String({ description: "Folder name" }),
      parentId: Type.Optional(Type.String({ description: "Optional parent folder id" })),
    }),
    async execute(_toolCallId, params, signal) {
      const body: JsonMap = {
        name: params.name,
        mimeType: "application/vnd.google-apps.folder",
      };
      if (params.parentId) body.parents = [params.parentId];

      const created = await googleRequest("/drive/v3/files", {
        method: "POST",
        query: { fields: "id,name,webViewLink,parents" },
        body,
        signal,
      });

      const folderId = typeof created.id === "string" ? created.id : "";
      const webViewLink = typeof created.webViewLink === "string" ? created.webViewLink : "";

      return {
        content: [{ type: "text", text: `Folder created\n- name: ${params.name}\n- id: ${folderId}${webViewLink ? `\n- url: ${webViewLink}` : ""}` }],
        details: { folderId, name: params.name, webViewLink },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_copy",
    label: "Google Drive Copy File",
    description: "Copy a file in Google Drive.",
    promptSnippet: "Duplicate a file in Google Drive.",
    parameters: Type.Object({
      fileId: Type.String({ description: "File ID to copy" }),
      name: Type.Optional(Type.String({ description: "New file name (optional)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const copied = await googleRequest(`/drive/v3/files/${encodeURIComponent(params.fileId)}/copy`, {
        method: "POST",
        body: params.name ? { name: params.name } : {},
        query: { fields: "id,name,webViewLink" },
        signal,
      });

      const newId = typeof copied.id === "string" ? copied.id : "";
      const newName = typeof copied.name === "string" ? copied.name : params.name ?? "copied file";

      return {
        content: [{ type: "text", text: `File copied\n- original: ${params.fileId}\n- copy: ${newName}\n- id: ${newId}` }],
        details: { originalFileId: params.fileId, newFileId: newId, name: newName },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_delete",
    label: "Google Drive Delete File",
    description: "Move a file to trash in Google Drive.",
    promptSnippet: "Delete (trash) a file in Google Drive.",
    parameters: Type.Object({
      fileId: Type.String({ description: "File ID to delete" }),
    }),
    async execute(_toolCallId, params, signal) {
      await googleRequest(`/drive/v3/files/${encodeURIComponent(params.fileId)}`, {
        // @ts-ignore - DELETE method not in typed union but supported by Google API
        method: "DELETE",
        signal,
      });

      return {
        content: [{ type: "text", text: `Deleted file: ${params.fileId}` }],
        details: { fileId: params.fileId },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_share",
    label: "Google Drive Share",
    description: "Share a file with specific email or make it public.",
    promptSnippet: "Share a Google Drive file with permissions.",
    parameters: Type.Object({
      fileId: Type.String({ description: "File ID to share" }),
      email: Type.Optional(Type.String({ description: "Email to share with (optional for public)" })),
      role: Type.Optional(Type.String({ description: "Role: reader, writer, commenter (default: reader)" })),
      type: Type.Optional(Type.String({ description: "Type: user, group, domain, anyone (default: user if email given, anyone otherwise)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const validRoles = ["reader", "writer", "commenter", "owner", "fileOrganizer"];
      const validTypes = ["user", "group", "domain", "anyone"];
      
      const type = (params.type as string) ?? (params.email ? "user" : "anyone");
      const role = (params.role as string) ?? "reader";
      
      if (!validTypes.includes(type)) {
        throw new Error(`Invalid type: ${type}. Valid values: ${validTypes.join(", ")}`);
      }
      if (!validRoles.includes(role)) {
        throw new Error(`Invalid role: ${role}. Valid values: ${validRoles.join(", ")}`);
      }
      
      const permission: JsonMap = { type, role };
      if (params.email) {
        permission.emailAddress = params.email;
      }

      const result = await googleRequest(`/drive/v3/files/${encodeURIComponent(params.fileId)}/permissions`, {
        method: "POST",
        body: permission,
        signal,
      });

      return {
        content: [{ type: "text", text: `Shared file: ${params.fileId}\n- type: ${permission.type}\n- role: ${permission.role}${params.email ? `\n- email: ${params.email}` : ""}` }],
        details: { fileId: params.fileId, permissionId: result.id, type: permission.type, role: permission.role },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_search",
    label: "Google Drive Search",
    description: "Search for files in Google Drive.",
    promptSnippet: "Search files by name or type in Google Drive.",
    parameters: Type.Object({
      query: Type.String({ description: "Search query (e.g., 'name contains report')" }),
      pageSize: Type.Optional(Type.Integer({ description: "Max results (default: 20)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest("/drive/v3/files", {
        query: {
          q: params.query,
          pageSize: params.pageSize ?? 20,
          fields: "files(id,name,mimeType,modifiedTime)",
          orderBy: "modifiedTime desc",
        },
        signal,
      });

      const files = Array.isArray(data.files) ? data.files : [];
      const lines = files.map((file: JsonMap, idx: number) => {
        return `${idx + 1}. ${file.name} (${file.mimeType})\n   ID: ${file.id}`;
      });

      return {
        content: [{ type: "text", text: lines.length > 0 ? lines.join("\n") : "No files found." }],
        details: { count: files.length, files },
      };
    },
  });

  pi.registerTool({
    name: "google_drive_get_permissions",
    label: "Google Drive Get Permissions",
    description: "Get sharing permissions of a file.",
    promptSnippet: "List who has access to a Google Drive file.",
    parameters: Type.Object({
      fileId: Type.String({ description: "File ID" }),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/drive/v3/files/${encodeURIComponent(params.fileId)}/permissions`, {
        query: { fields: "permissions(id,type,role,emailAddress)" },
        signal,
      });

      const perms = Array.isArray(data.permissions) ? data.permissions : [];
      const lines = perms.map((p: JsonMap) => {
        return `- ${p.type}: ${p.emailAddress ?? "(anyone)"} - ${p.role}`;
      });

      return {
        content: [{ type: "text", text: lines.length > 0 ? `Permissions:\n${lines.join("\n")}` : "No permissions found." }],
        details: { fileId: params.fileId, permissions: perms },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_create",
    label: "Google Sheets Create",
    description: "Create a spreadsheet and optionally write a header row.",
    promptSnippet: "Create spreadsheet and return spreadsheetId.",
    parameters: Type.Object({
      title: Type.String({ description: "Spreadsheet title" }),
      sheetTitle: Type.Optional(Type.String({ description: "Optional first sheet title" })),
      headerRow: Type.Optional(Type.Array(Type.String({ description: "Header cell" }))),
    }),
    async execute(_toolCallId, params, signal) {
      const payload: JsonMap = {
        properties: { title: params.title },
      };
      if (params.sheetTitle) payload.sheets = [{ properties: { title: params.sheetTitle } }];

      const created = await googleRequest("/v4/spreadsheets", {
        method: "POST",
        body: payload,
        signal,
      });

      const spreadsheetId = typeof created.spreadsheetId === "string" ? created.spreadsheetId : "";
      const spreadsheetUrl = typeof created.spreadsheetUrl === "string" ? created.spreadsheetUrl : "";
      if (!spreadsheetId) throw new Error("spreadsheetId was not returned.");

      if (params.headerRow && params.headerRow.length > 0) {
        const firstSheet = Array.isArray(created.sheets) ? ((created.sheets[0] as JsonMap | undefined)?.properties as JsonMap | undefined) : undefined;
        const title = typeof firstSheet?.title === "string" ? firstSheet.title : params.sheetTitle || "Sheet1";

        await googleRequest(`/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(`${title}!A1`)}`, {
          method: "PUT",
          query: { valueInputOption: "USER_ENTERED" },
          body: { range: `${title}!A1`, majorDimension: "ROWS", values: [params.headerRow] },
          signal,
        });
      }

      return {
        content: [{ type: "text", text: `Spreadsheet created\n- id: ${spreadsheetId}${spreadsheetUrl ? `\n- url: ${spreadsheetUrl}` : ""}` }],
        details: { spreadsheetId, spreadsheetUrl, title: params.title },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_read",
    label: "Google Sheets Read",
    description: "Read values from a Google Sheets range.",
    promptSnippet: "Read spreadsheet cells by spreadsheetId and range.",
    parameters: Type.Object({
      spreadsheetId: Type.String({ description: "Spreadsheet ID" }),
      range: Type.Optional(Type.String({ description: "A1 range (e.g. Sheet1!A1:D20)" })),
      valueRenderOption: Type.Optional(Type.String({ description: "FORMATTED_VALUE | UNFORMATTED_VALUE | FORMULA" })),
    }),
    async execute(_toolCallId, params, signal) {
      const range = params.range?.trim() || "Sheet1!A1:Z200";
      const data = await googleRequest(
        `/v4/spreadsheets/${encodeURIComponent(params.spreadsheetId)}/values/${encodeURIComponent(range)}`,
        {
          query: {
            valueRenderOption: params.valueRenderOption ?? "FORMATTED_VALUE",
            majorDimension: "ROWS",
          },
          signal,
        },
      );

      const values = Array.isArray(data.values) ? (data.values as unknown[][]) : [];
      return {
        content: [{ type: "text", text: sheetValuesToText(values) }],
        details: { spreadsheetId: params.spreadsheetId, range, rowCount: values.length, values },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_update_values",
    label: "Google Sheets Update Values",
    description: "Update a range in Google Sheets.",
    promptSnippet: "Write 2D values array to a spreadsheet range.",
    parameters: Type.Object({
      spreadsheetId: Type.String({ description: "Spreadsheet ID" }),
      range: Type.String({ description: "A1 range (e.g. Sheet1!A2:C2)" }),
      values: Type.Array(Type.Array(Type.Any())),
      valueInputOption: Type.Optional(Type.String({ description: "RAW | USER_ENTERED" })),
    }),
    async execute(_toolCallId, params, signal) {
      const updated = await googleRequest(
        `/v4/spreadsheets/${encodeURIComponent(params.spreadsheetId)}/values/${encodeURIComponent(params.range)}`,
        {
          method: "PUT",
          query: { valueInputOption: params.valueInputOption ?? "USER_ENTERED" },
          body: {
            range: params.range,
            majorDimension: "ROWS",
            values: params.values,
          },
          signal,
        },
      );

      const updatedRange = typeof updated.updatedRange === "string" ? updated.updatedRange : params.range;
      const updatedRows = typeof updated.updatedRows === "number" ? updated.updatedRows : 0;

      return {
        content: [{ type: "text", text: `Sheet update complete\n- range: ${updatedRange}\n- rows: ${updatedRows}` }],
        details: { spreadsheetId: params.spreadsheetId, updatedRange, updatedRows },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_list",
    label: "Google Sheets List",
    description: "List all Google Spreadsheets accessible to the user.",
    promptSnippet: "List all Google Spreadsheets the user has access to.",
    parameters: Type.Object({
      pageSize: Type.Optional(Type.Integer({ description: "Maximum number of results (default: 25)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest("/drive/v3/files", {
        query: {
          q: "mimeType='application/vnd.google-apps.spreadsheet'",
          pageSize: params.pageSize ?? 25,
          fields: "files(id,name,modifiedTime,webViewLink)",
          orderBy: "modifiedTime desc",
        },
        signal,
      });

      const files = Array.isArray(data.files) ? (data.files as JsonMap[]) : [];
      const lines = files.map((file, idx) => {
        const id = typeof file.id === "string" ? file.id : "";
        const name = typeof file.name === "string" ? file.name : "(no name)";
        const modified = typeof file.modifiedTime === "string" ? file.modifiedTime : "";
        const link = typeof file.webViewLink === "string" ? file.webViewLink : "";
        return `${idx + 1}. ${name}\n   - id: ${id}\n   - modified: ${modified}\n   - link: ${link}`;
      });

      return {
        content: [{ type: "text", text: lines.length > 0 ? lines.join("\n") : "No spreadsheets found." }],
        details: { count: files.length, files },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_get_info",
    label: "Google Sheets Get Info",
    description: "Get information about a spreadsheet including its sheets.",
    promptSnippet: "Get spreadsheet metadata including sheet names and grid size.",
    parameters: Type.Object({
      spreadsheetId: Type.String({ description: "Spreadsheet ID" }),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v4/spreadsheets/${encodeURIComponent(params.spreadsheetId)}`, {
        query: {
          fields: "spreadsheetId,properties(title,locale),sheets(properties(title,sheetId,gridProperties(rowCount,columnCount)))",
        },
        signal,
      });

      const props = data.properties as JsonMap | undefined;
      const title = typeof props?.title === "string" ? String(props.title) : "Unknown";
      const locale = typeof props?.locale === "string" ? String(props.locale) : "Unknown";
      const sheets = Array.isArray(data.sheets) ? data.sheets : [];

      const sheetInfo = sheets.map((sheet: JsonMap) => {
        const props = sheet.properties as JsonMap | undefined;
        const grid = props?.gridProperties as JsonMap | undefined;
        return `- "${props?.title}" (ID: ${props?.sheetId}) | Size: ${grid?.rowCount ?? "?"}x${grid?.columnCount ?? "?"}`;
      }).join("\n");

      return {
        content: [{ type: "text", text: `Spreadsheet: ${title} (ID: ${params.spreadsheetId})\nLocale: ${locale}\n\nSheets (${sheets.length}):\n${sheetInfo}` }],
        details: { title, locale, sheetCount: sheets.length, sheets },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_clear",
    label: "Google Sheets Clear",
    description: "Clear values from a range in Google Sheets.",
    promptSnippet: "Clear cell values from a spreadsheet range.",
    parameters: Type.Object({
      spreadsheetId: Type.String({ description: "Spreadsheet ID" }),
      range: Type.String({ description: "A1 range to clear (e.g. Sheet1!A1:D10)" }),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v4/spreadsheets/${encodeURIComponent(params.spreadsheetId)}/values/${encodeURIComponent(params.range)}:clear`, {
        method: "POST",
        signal,
      });

      return {
        content: [{ type: "text", text: `Cleared range: ${data.clearedRange ?? params.range}` }],
        details: { spreadsheetId: params.spreadsheetId, clearedRange: data.clearedRange },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_create_sheet",
    label: "Google Sheets Create Sheet",
    description: "Create a new sheet/tab in an existing spreadsheet.",
    promptSnippet: "Add a new sheet tab to an existing spreadsheet.",
    parameters: Type.Object({
      spreadsheetId: Type.String({ description: "Spreadsheet ID" }),
      title: Type.String({ description: "Name of the new sheet/tab" }),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v4/spreadsheets/${encodeURIComponent(params.spreadsheetId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [{
            addSheet: {
              properties: { title: params.title },
            },
          }],
        },
        signal,
      });

      const replies = (data as JsonMap).replies as JsonMap[] | undefined;
      const reply = Array.isArray(replies) && replies.length > 0 ? replies[0] : {};
      const addSheet = (reply as JsonMap).addSheet as JsonMap | undefined;
      const sheetProps = typeof addSheet === "object" && addSheet !== null ? (addSheet.properties as JsonMap | undefined) : undefined;
      const sheetId = sheetProps?.sheetId;

      return {
        content: [{ type: "text", text: `Created sheet: ${params.title} (ID: ${sheetId})` }],
        details: { spreadsheetId: params.spreadsheetId, title: params.title, sheetId },
      };
    },
  });

  pi.registerTool({
    name: "google_sheets_delete_sheet",
    label: "Google Sheets Delete Sheet",
    description: "Delete a sheet/tab from a spreadsheet.",
    promptSnippet: "Remove a sheet tab from a spreadsheet.",
    parameters: Type.Object({
      spreadsheetId: Type.String({ description: "Spreadsheet ID" }),
      sheetId: Type.Integer({ description: "Sheet ID to delete" }),
    }),
    async execute(_toolCallId, params, signal) {
      await googleRequest(`/v4/spreadsheets/${encodeURIComponent(params.spreadsheetId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [{
            deleteSheet: { sheetId: params.sheetId },
          }],
        },
        signal,
      });

      return {
        content: [{ type: "text", text: `Deleted sheet ID: ${params.sheetId}` }],
        details: { spreadsheetId: params.spreadsheetId, sheetId: params.sheetId },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_read",
    label: "Google Docs Read",
    description: "Read text content from a Google Docs document.",
    promptSnippet: "Read a Google Docs document by documentId and return plain text.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
    }),
    async execute(_toolCallId, params, signal) {
      const document = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}`, { signal });
      const title = typeof document.title === "string" ? document.title : params.documentId;
      const text = extractDocText(document);

      return {
        content: [{ type: "text", text: `# ${title}\n\n${text || "(no body text)"}` }],
        details: { title, documentId: params.documentId, textLength: text.length },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_create",
    label: "Google Docs Create",
    description: "Create a new Google Docs document and optionally insert initial text.",
    promptSnippet: "Create a Google Docs document and return its documentId.",
    parameters: Type.Object({
      title: Type.String({ description: "Document title" }),
      initialText: Type.Optional(Type.String({ description: "Initial text content" })),
    }),
    async execute(_toolCallId, params, signal) {
      const created = await googleRequest("/v1/documents", {
        method: "POST",
        body: { title: params.title },
        signal,
      });

      const documentId = typeof created.documentId === "string" ? created.documentId : "";
      if (!documentId) throw new Error("documentId was not returned.");

      if (params.initialText && params.initialText.length > 0) {
        await googleRequest(`/v1/documents/${encodeURIComponent(documentId)}:batchUpdate`, {
          method: "POST",
          body: {
            requests: [
              {
                insertText: {
                  location: { index: 1 },
                  text: params.initialText,
                },
              },
            ],
          },
          signal,
        });
      }

      return {
        content: [{ type: "text", text: `Document created: ${params.title}\n- documentId: ${documentId}` }],
        details: { documentId, title: params.title },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_replace_all_text",
    label: "Google Docs Replace All Text",
    description: "Replace entire body text of a Google Docs document.",
    promptSnippet: "Overwrite Google Docs body text with new content.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      text: Type.String({ description: "New full body text" }),
    }),
    async execute(_toolCallId, params, signal) {
      const document = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}`, { signal });
      const endIndex = getDocEndIndex(document);

      const requests: JsonMap[] = [];
      if (endIndex > 1) {
        requests.push({
          deleteContentRange: {
            range: { startIndex: 1, endIndex: endIndex - 1 },
          },
        });
      }
      if (params.text.length > 0) {
        requests.push({
          insertText: {
            location: { index: 1 },
            text: params.text,
          },
        });
      }

      await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: { requests },
        signal,
      });

      return {
        content: [{ type: "text", text: `Replaced full document body. (documentId=${params.documentId})` }],
        details: { documentId: params.documentId, replaced: true, endIndex },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_append_text",
    label: "Google Docs Append Text",
    description: "Append text to the end of a Google Docs document.",
    promptSnippet: "Append text to a Google Docs document by documentId.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      text: Type.String({ description: "Text to append" }),
    }),
    async execute(_toolCallId, params, signal) {
      const document = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}`, { signal });
      const index = getDocInsertIndex(document);

      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              insertText: {
                location: { index },
                text: params.text,
              },
            },
          ],
        },
        signal,
      });

      return {
        content: [{ type: "text", text: `Appended text to document end. (index=${index})` }],
        details: { documentId: params.documentId, index, replyCount: Array.isArray(data.replies) ? data.replies.length : 0 },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_insert_text",
    label: "Google Docs Insert Text",
    description: "Insert text at a specific index position in a Google Docs document.",
    promptSnippet: "Insert text at a specific position in a Google Docs document by documentId and index.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      index: Type.Integer({ description: "Index position to insert text at (0-based)" }),
      text: Type.String({ description: "Text to insert" }),
    }),
    async execute(_toolCallId, params, signal) {
      // Google Docs API uses 1-based indexing, body starts at index 1
      const apiIndex = Math.max(1, params.index);

      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              insertText: {
                location: { index: apiIndex },
                text: params.text,
              },
            },
          ],
        },
        signal,
      });

      return {
        content: [{ type: "text", text: `Inserted text at index ${apiIndex}. (documentId=${params.documentId})` }],
        details: { documentId: params.documentId, index: apiIndex, textLength: params.text.length, replyCount: Array.isArray(data.replies) ? data.replies.length : 0 },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_find_and_replace",
    label: "Google Docs Find and Replace",
    description: "Find and replace text throughout a Google Docs document.",
    promptSnippet: "Find and replace text in a Google Docs document without needing to calculate indices.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      findText: Type.String({ description: "Text to search for" }),
      replaceText: Type.String({ description: "Text to replace with" }),
      matchCase: Type.Optional(Type.Boolean({ description: "Case-sensitive matching (default: false)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              replaceAllText: {
                containsText: {
                  text: params.findText,
                  matchCase: params.matchCase ?? false,
                },
                replaceText: params.replaceText,
              },
            },
          ],
        },
        signal,
      });

      const firstReply = Array.isArray(data.replies) ? (data.replies[0] as JsonMap | undefined) : undefined;
      const replaceDetails = (firstReply?.replaceAllText as JsonMap | undefined) ?? {};
      const occurrencesChanged = typeof replaceDetails.occurrencesChanged === "number" ? replaceDetails.occurrencesChanged : 0;

      return {
        content: [{ type: "text", text: `Replaced ${occurrencesChanged} occurrence(s) of '${params.findText}' with '${params.replaceText}'. (documentId=${params.documentId})` }],
        details: { documentId: params.documentId, findText: params.findText, replaceText: params.replaceText, occurrencesChanged },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_insert_table",
    label: "Google Docs Insert Table",
    description: "Insert a table at a specific position in a Google Docs document.",
    promptSnippet: "Insert a table at a specific index in a Google Docs document.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      index: Type.Integer({ description: "Index position to insert table at" }),
      rows: Type.Integer({ description: "Number of rows" }),
      columns: Type.Integer({ description: "Number of columns" }),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              insertTable: {
                location: { index: Math.max(1, params.index) },
                rows: params.rows,
                columns: params.columns,
              },
            },
          ],
        },
        signal,
      });

      return {
        content: [{ type: "text", text: `Inserted ${params.rows}x${params.columns} table at index ${params.index}.` }],
        details: { documentId: params.documentId, rows: params.rows, columns: params.columns, index: params.index },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_insert_page_break",
    label: "Google Docs Insert Page Break",
    description: "Insert a page break at a specific position in a Google Docs document.",
    promptSnippet: "Insert a page break at a specific index.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      index: Type.Integer({ description: "Index position to insert page break" }),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              insertPageBreak: {
                location: { index: Math.max(1, params.index) },
              },
            },
          ],
        },
        signal,
      });

      return {
        content: [{ type: "text", text: `Inserted page break at index ${params.index}.` }],
        details: { documentId: params.documentId, index: params.index },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_update_header",
    label: "Google Docs Update Header",
    description: "Update the header text of a Google Docs document.",
    promptSnippet: "Set or update the header text of a document.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      text: Type.String({ description: "Header text" }),
    }),
    async execute(_toolCallId, params, signal) {
      // Insert header text at the beginning of the document (index 1)
      // Note: Google Docs API doesn't support direct header insertion; this adds text styled as header at document start
      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              insertText: {
                location: { index: 1 },
                text: params.text + "\n",
              },
            },
            {
              updateParagraphStyle: {
                range: { startIndex: 0, endIndex: params.text.length + 2 },
                style: { namedStyleType: "HEADER" },
                fields: "namedStyleType",
              },
            },
          ],
        },
        signal,
      });

      return {
        content: [{ type: "text", text: `Updated header: ${params.text}` }],
        details: { documentId: params.documentId, header: params.text },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_batch_update",
    label: "Google Docs Batch Update",
    description: "Execute multiple operations in a single batch update request.",
    promptSnippet: "Execute multiple insert/delete/format operations in one request.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      operations: Type.Array(Type.Any(), { description: "Array of operations to execute" }),
    }),
    async execute(_toolCallId, params, signal) {
      const requests = (params.operations as JsonMap[]).map((op: JsonMap) => {
        const type = op.type as string;
        switch (type) {
          case "insertText":
            return { insertText: { location: { index: op.index ?? 1 }, text: op.text as string } };
          case "deleteText":
            return { deleteContentRange: { range: { startIndex: op.startIndex, endIndex: op.endIndex } } };
          case "insertTable":
            return { insertTable: { location: { index: op.index ?? 1 }, rows: op.rows, columns: op.columns } };
          case "insertPageBreak":
            return { insertPageBreak: { location: { index: op.index ?? 1 } } };
          case "updateParagraphStyle":
            return { updateParagraphStyle: { range: { startIndex: op.startIndex, endIndex: op.endIndex }, style: op.style, fields: op.fields ?? "*" } };
          default:
            return op;
        }
      });

      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: { requests },
        signal,
      });

      return {
        content: [{ type: "text", text: `Batch update completed. ${requests.length} operations executed.` }],
        details: { documentId: params.documentId, operationCount: requests.length, replies: data.replies },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_delete_content",
    label: "Google Docs Delete Content",
    description: "Delete content from a specific range in a Google Docs document.",
    promptSnippet: "Delete text or elements from a document at specific indices.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      startIndex: Type.Integer({ description: "Start index of content to delete" }),
      endIndex: Type.Integer({ description: "End index of content to delete" }),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              deleteContentRange: {
                range: { startIndex: params.startIndex, endIndex: params.endIndex },
              },
            },
          ],
        },
        signal,
      });

      return {
        content: [{ type: "text", text: `Deleted content from index ${params.startIndex} to ${params.endIndex}.` }],
        details: { documentId: params.documentId, startIndex: params.startIndex, endIndex: params.endIndex },
      };
    },
  });

  pi.registerTool({
    name: "google_docs_download",
    label: "Google Docs Download",
    description: "Download a Google Docs document to local file as pdf/docx/md/txt/rtf/odt/html_zip.",
    promptSnippet: "Export Google Docs to local file in requested format.",
    parameters: Type.Object({
      documentId: Type.String({ description: "Google Docs document ID" }),
      format: Type.String({ description: "pdf | docx | md | txt | rtf | odt | html_zip" }),
      outputPath: Type.Optional(Type.String({ description: "Optional local output path" })),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      const format = params.format as DocExportFormat;
      const allowedFormats: DocExportFormat[] = ["pdf", "docx", "md", "txt", "rtf", "odt", "html_zip"];
      if (!allowedFormats.includes(format)) {
        throw new Error(`Unsupported format: ${params.format}`);
      }

      const document = await googleRequest(`/v1/documents/${encodeURIComponent(params.documentId)}`, { signal });
      const title = typeof document.title === "string" ? document.title : params.documentId;
      const base = safeFilename(title);

      let outputFile = "";
      let bytesWritten = 0;

      if (format === "md") {
        const markdown = toMarkdownFromDocument(document);
        outputFile = normalizeOutputPath(ctx.cwd, params.outputPath, `${base}.md`);
        await mkdir(dirname(outputFile), { recursive: true });
        await writeFile(outputFile, markdown, "utf-8");
        bytesWritten = Buffer.byteLength(markdown, "utf-8");
      } else {
        const spec = DOC_EXPORT_MAP[format];
        const exported = await googleBinaryRequest(`/drive/v3/files/${encodeURIComponent(params.documentId)}/export`, {
          query: { mimeType: spec.mime },
          signal,
        });

        outputFile = normalizeOutputPath(ctx.cwd, params.outputPath, `${base}.${spec.ext}`);
        await mkdir(dirname(outputFile), { recursive: true });
        await writeFile(outputFile, exported.bytes);
        bytesWritten = exported.bytes.byteLength;
      }

      return {
        content: [
          {
            type: "text",
            text: [
              "Document download complete",
              `- title: ${title}`,
              `- format: ${format}`,
              `- path: ${outputFile}`,
              `- bytes: ${bytesWritten}`,
            ].join("\n"),
          },
        ],
        details: {
          documentId: params.documentId,
          title,
          format,
          outputPath: outputFile,
          bytesWritten,
        },
      };
    },
  });

  pi.registerTool({
    name: "google_slides_read",
    label: "Google Slides Read",
    description: "Read text content from all slides in a presentation.",
    promptSnippet: "Read all text from a Google Slides presentation by presentationId.",
    parameters: Type.Object({
      presentationId: Type.String({ description: "Google Slides presentation ID" }),
    }),
    async execute(_toolCallId, params, signal) {
      const presentation = await googleRequest(`/v1/presentations/${encodeURIComponent(params.presentationId)}`, { signal });
      const title = typeof presentation.title === "string" ? presentation.title : params.presentationId;
      const slides = extractSlidesText(presentation);

      const rendered = slides
        .map((slide) => `## Slide ${slide.index} (${slide.slideId})\n${slide.text || "(no text)"}`)
        .join("\n\n");

      return {
        content: [{ type: "text", text: `# ${title}\n\n${rendered || "No slide body text."}` }],
        details: { presentationId: params.presentationId, title, slideCount: slides.length },
      };
    },
  });

  pi.registerTool({
    name: "google_slides_replace_text",
    label: "Google Slides Replace Text",
    description: "Replace text across all slides in a presentation.",
    promptSnippet: "Find and replace text in Google Slides presentation.",
    parameters: Type.Object({
      presentationId: Type.String({ description: "Google Slides presentation ID" }),
      findText: Type.String({ description: "Text to find" }),
      replaceText: Type.String({ description: "Replacement text" }),
      matchCase: Type.Optional(Type.Boolean({ description: "Case-sensitive matching" })),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest(`/v1/presentations/${encodeURIComponent(params.presentationId)}:batchUpdate`, {
        method: "POST",
        body: {
          requests: [
            {
              replaceAllText: {
                containsText: {
                  text: params.findText,
                  matchCase: params.matchCase ?? false,
                },
                replaceText: params.replaceText,
              },
            },
          ],
        },
        signal,
      });

      const firstReply = Array.isArray(data.replies) ? (data.replies[0] as JsonMap | undefined) : undefined;
      const replaceDetails = (firstReply?.replaceAllText as JsonMap | undefined) ?? {};
      const occurrencesChanged = typeof replaceDetails.occurrencesChanged === "number" ? replaceDetails.occurrencesChanged : 0;

      return {
        content: [{ type: "text", text: `Replace complete: ${occurrencesChanged} item(s) changed` }],
        details: { presentationId: params.presentationId, occurrencesChanged },
      };
    },
  });

  // Calendar tools
  pi.registerTool({
    name: "google_calendar_list",
    label: "Google Calendar List",
    description: "List all calendars accessible to the user.",
    promptSnippet: "List Google Calendars",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      const data = await googleRequest("/calendar/v3/users/me/calendarList", { query: { maxResults: 100 }, signal });
      const items = Array.isArray(data.items) ? data.items : [];
      const lines = items.map((cal: JsonMap) => `${cal.summary || "(no summary)"} (ID: ${cal.id || ""})${cal.primary ? " [PRIMARY]" : ""}`);
      if (items.length === 0) return { content: [{ type: "text", text: "No calendars found." }], details: { count: 0, calendars: [] as JsonMap[] } };
      return { content: [{ type: "text", text: `Calendars:\n${lines.join("\n")}` }], details: { count: items.length, calendars: items } };
    },
  });

  pi.registerTool({
    name: "google_calendar_get_events",
    label: "Google Calendar Get Events",
    description: "Get events from a Google Calendar with optional time range filtering.",
    promptSnippet: "Get calendar events with time range.",
    parameters: Type.Object({
      calendarId: Type.Optional(Type.String({ description: "Calendar ID (default: primary)" })),
      timeMin: Type.Optional(Type.String({ description: "Start time (RFC3339)" })),
      timeMax: Type.Optional(Type.String({ description: "End time (RFC3339)" })),
      maxResults: Type.Optional(Type.Integer({ description: "Max events (default: 25)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const calendarId = params.calendarId || "primary";
      const query: Record<string, string | number | boolean> = { maxResults: params.maxResults ?? 25, singleEvents: true, orderBy: "startTime" };
      if (params.timeMin) query.timeMin = params.timeMin;
      if (params.timeMax) query.timeMax = params.timeMax;
      const data = await googleRequest(`/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`, { query, signal });
      const items = Array.isArray(data.items) ? data.items : [];
      if (items.length === 0) return { content: [{ type: "text", text: "No events found." }], details: { count: 0, events: [] as JsonMap[] } };
      const lines = items.map((item: JsonMap) => {
        const start = (item.start as JsonMap)?.dateTime || (item.start as JsonMap)?.date || "";
        const end = (item.end as JsonMap)?.dateTime || (item.end as JsonMap)?.date || "";
        return `"${item.summary || "No Title"}" | ${start} → ${end}`;
      });
      return { content: [{ type: "text", text: `Events:\n${lines.join("\n")}` }], details: { count: items.length, events: items } };
    },
  });

  pi.registerTool({
    name: "google_calendar_manage_event",
    label: "Google Calendar Manage Event",
    description: "Create, update, or delete calendar events.",
    promptSnippet: "Create/update/delete calendar events.",
    parameters: Type.Object({
      action: Type.String({ description: "Action: create, update, or delete" }),
      calendarId: Type.Optional(Type.String({ description: "Calendar ID (default: primary)" })),
      eventId: Type.Optional(Type.String({ description: "Event ID (for update/delete)" })),
      summary: Type.Optional(Type.String({ description: "Event title" })),
      startTime: Type.Optional(Type.String({ description: "Start time (RFC3339 or YYYY-MM-DD)" })),
      endTime: Type.Optional(Type.String({ description: "End time (RFC3339 or YYYY-MM-DD)" })),
      description: Type.Optional(Type.String({ description: "Event description" })),
      attendees: Type.Optional(Type.Array(Type.String(), { description: "Attendee emails" })),
      addGoogleMeet: Type.Optional(Type.Boolean({ description: "Add Google Meet link" })),
    }),
    async execute(_toolCallId, params, signal) {
      const calendarId = params.calendarId || "primary";
      const action = params.action.toLowerCase();
      
      if (action === "delete") {
        if (!params.eventId) throw new Error("eventId required for delete");
        // @ts-ignore - DELETE method not in typed union but supported by Google API
        await googleRequest(`/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(params.eventId)}`, { method: "DELETE", signal });
        return { content: [{ type: "text", text: `Deleted event: ${params.eventId}` }], details: { action: "delete" as string, eventId: params.eventId as string, event: undefined as unknown } } as any;
      }

      const eventBody: JsonMap = {};
      if (params.summary) eventBody.summary = params.summary;
      if (params.description) eventBody.description = params.description;
      if (params.startTime) eventBody.start = params.startTime.includes("T") ? { dateTime: params.startTime } : { date: params.startTime };
      if (params.endTime) eventBody.end = params.endTime.includes("T") ? { dateTime: params.endTime } : { date: params.endTime };
      if (params.attendees?.length) eventBody.attendees = params.attendees.map(e => ({ email: e }));
      if (params.addGoogleMeet) eventBody.conferenceData = { createRequest: { requestId: crypto.randomUUID(), conferenceSolutionKey: { type: "hangoutsMeet" } } };

      if (action === "create") {
        const created = await googleRequest(`/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`, { method: "POST", body: eventBody, signal });
        const newEventId = typeof created.id === "string" ? created.id : "";
        return { content: [{ type: "text", text: `Created: ${created.summary || params.summary}\nID: ${newEventId}\nLink: ${created.htmlLink || ""}` }], details: { action: "create" as string, event: created, eventId: newEventId } } as any;
      }

      if (!params.eventId) throw new Error("eventId required for update");
      const updated = await googleRequest(`/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events/${encodeURIComponent(params.eventId)}`, { method: "PUT", body: eventBody, signal });
      const updatedEventId = typeof updated.id === "string" ? updated.id : params.eventId;
      return { content: [{ type: "text", text: `Updated: ${updated.summary || params.summary}\nID: ${updatedEventId}` }], details: { action: "update" as string, event: updated, eventId: updatedEventId } } as any;
    },
  });

  // Chat tools
  pi.registerTool({
    name: "google_chat_list_spaces",
    label: "Google Chat List Spaces",
    description: "List Google Chat spaces.",
    promptSnippet: "List Chat spaces.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, signal) {
      const data = await googleRequest("/v1/spaces", { query: { pageSize: 100 }, signal });
      const spaces = Array.isArray(data.spaces) ? data.spaces : [];
      if (spaces.length === 0) return { content: [{ type: "text", text: "No Chat spaces found." }], details: { count: 0, spaces: [] as JsonMap[] } };
      const lines = spaces.map((s: JsonMap) => `${s.displayName || "Unnamed"} | ${s.name || ""}`);
      return { content: [{ type: "text", text: `Spaces:\n${lines.join("\n")}` }], details: { count: spaces.length, spaces } };
    },
  });

  pi.registerTool({
    name: "google_chat_send_message",
    label: "Google Chat Send Message",
    description: "Send a message to a Google Chat space.",
    promptSnippet: "Send message to Chat space.",
    parameters: Type.Object({
      spaceId: Type.String({ description: "Chat space ID (e.g. spaces/xxx)" }),
      messageText: Type.String({ description: "Message text" }),
    }),
    async execute(_toolCallId, params, signal) {
      const sent = await googleRequest(`/v1/spaces/${encodeURIComponent(params.spaceId)}/messages`, {
        method: "POST",
        body: { text: params.messageText },
        signal,
      });
      return { content: [{ type: "text", text: `Sent to ${params.spaceId}\nMessage ID: ${sent.name || ""}` }], details: { spaceId: params.spaceId, messageId: sent.name } };
    },
  });

  // Contacts tools
  pi.registerTool({
    name: "google_contacts_list",
    label: "Google Contacts List",
    description: "List contacts for the authenticated user.",
    promptSnippet: "List Google Contacts.",
    parameters: Type.Object({
      pageSize: Type.Optional(Type.Integer({ description: "Max contacts (default: 100)" })),
    }),
    async execute(_toolCallId, params, signal) {
      const data = await googleRequest("/v1/people/me/connections", {
        query: { personFields: "names,emailAddresses,phoneNumbers", pageSize: params.pageSize ?? 100 },
        signal,
      });
      const connections = Array.isArray(data.connections) ? data.connections : [];
      if (connections.length === 0) return { content: [{ type: "text", text: "No contacts found." }], details: { count: 0, contacts: [] as JsonMap[] } };
      const lines = connections.map((p: JsonMap) => {
        const name = (p.names as JsonMap[])?.[0]?.displayName || "No name";
        const email = (p.emailAddresses as JsonMap[])?.[0]?.value || "";
        const phone = (p.phoneNumbers as JsonMap[])?.[0]?.value || "";
        return `${name}${email ? ` | ${email}` : ""}${phone ? ` | ${phone}` : ""}`;
      });
      return { content: [{ type: "text", text: `Contacts:\n${lines.join("\n")}` }], details: { count: connections.length, contacts: connections } };
    },
  });

  pi.registerTool({
    name: "google_contacts_get",
    label: "Google Contacts Get",
    description: "Get detailed contact information.",
    promptSnippet: "Get contact details by ID.",
    parameters: Type.Object({
      contactId: Type.String({ description: "Contact ID" }),
    }),
    async execute(_toolCallId, params, signal) {
      let resourceName = params.contactId.startsWith("people/") ? params.contactId : `people/${params.contactId}`;
      const person = await googleRequest(`/v1/${encodeURIComponent(resourceName)}`, {
        query: { personFields: "names,emailAddresses,phoneNumbers,organizations,addresses" },
        signal,
      });
      const name = (person.names as JsonMap[])?.[0]?.displayName || "No name";
      const emails = (person.emailAddresses as JsonMap[])?.map(e => e.value).join(", ") || "";
      const phones = (person.phoneNumbers as JsonMap[])?.map(p => p.value).join(", ") || "";
      const org = (person.organizations as JsonMap[])?.[0]?.name || "";
      return { content: [{ type: "text", text: `${name}\nEmail: ${emails}\nPhone: ${phones}\nOrganization: ${org}` }], details: { contact: person } };
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    ctx.ui.setStatus(EXTENSION_NAME, "Use /gws-setup to connect Google Workspace");
  });
}
