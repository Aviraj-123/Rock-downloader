import { Router, type Request, type Response } from "express";
import { execFile, spawn } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs";
import { eq, lt, and } from "drizzle-orm";
import { db } from "@workspace/db";
import { downloadHistoryTable, suspiciousUsersTable } from "@workspace/db";
import { logger } from "../lib/logger";

const execFileAsync = promisify(execFile);
const router = Router();

const workspaceRoot = process.cwd().endsWith(path.join("artifacts", "api-server"))
  ? path.resolve(process.cwd(), "../..")
  : process.cwd();

const downloadsDir = path.resolve(workspaceRoot, "artifacts/api-server/downloads");
if (!fs.existsSync(downloadsDir)) fs.mkdirSync(downloadsDir, { recursive: true });

// ──────────────────────────────────────────────
// Cleanup job — runs every 10 minutes
// Deletes DB rows AND downloaded files older than 1 hour
// ──────────────────────────────────────────────
function scheduleCleanup() {
  setInterval(async () => {
    const cutoff = new Date(Date.now() - 60 * 60 * 1000); // 1 hour ago
    try {
      await db.delete(downloadHistoryTable).where(lt(downloadHistoryTable.downloadedAt, cutoff));
      logger.info("Cleanup: old download history purged");
    } catch (err) {
      logger.error({ err }, "Cleanup: DB purge failed");
    }
    // Also clean leftover files in downloads dir older than 1 hour
    try {
      const files = fs.readdirSync(downloadsDir);
      const now = Date.now();
      for (const f of files) {
        const fp = path.join(downloadsDir, f);
        const stat = fs.statSync(fp);
        if (now - stat.mtimeMs > 60 * 60 * 1000) fs.unlinkSync(fp);
      }
    } catch { /* non-fatal */ }
  }, 10 * 60 * 1000); // every 10 minutes
}
scheduleCleanup();

// ──────────────────────────────────────────────
// Suspicious user detection
// ──────────────────────────────────────────────
const downloadCounts = new Map<string, { count: number; firstAt: number }>();

async function checkSuspicious(req: Request, url: string) {
  const token = (req as any).userToken as string;
  const ip = req.ip ?? req.socket?.remoteAddress ?? "unknown";
  const ua = req.headers["user-agent"] ?? "";
  const now = Date.now();
  const window = 10 * 60 * 1000; // 10 min window

  // Rate tracking
  const entry = downloadCounts.get(token) ?? { count: 0, firstAt: now };
  if (now - entry.firstAt > window) { entry.count = 0; entry.firstAt = now; }
  entry.count++;
  downloadCounts.set(token, entry);

  const reasons: string[] = [];

  if (entry.count > 15) reasons.push(`High rate: ${entry.count} downloads in 10 min`);
  if (!ua || ua.length < 10) reasons.push("Missing or suspicious User-Agent");
  // Known bot user agents
  if (/curl|wget|python|scrapy|httpie|go-http/i.test(ua)) reasons.push(`Bot-like UA: ${ua.slice(0, 80)}`);

  if (reasons.length > 0) {
    const reason = reasons.join(" | ");
    logger.warn({ token, ip, reason, url }, "Suspicious user flagged");
    try {
      await db.insert(suspiciousUsersTable).values({ userToken: token, reason, url, ipAddress: ip, userAgent: ua });
    } catch { /* non-fatal */ }
  }
}

// ──────────────────────────────────────────────
// yt-dlp helpers
// ──────────────────────────────────────────────
/**
 * Fast nix-store binary discovery — scans /nix/store directory listing
 * instead of shelling out to `which` (avoids 3-second startup delay).
 * Sorts candidates by embedded version number (not hash prefix) to always
 * pick the latest installed version.
 */
function findNixBin(name: string): string {
  try {
    const entries = fs.readdirSync("/nix/store");
    // Match dirs like: <hash>-yt-dlp-2025.6.30  or  <hash>-ffmpeg-7.1.1-bin
    const versionRe = new RegExp(`-${name}-(\\d+[\\d.]+)`);
    const candidates = entries
      .map((d) => {
        const m = d.match(versionRe);
        if (!m) return null;
        const p = `/nix/store/${d}/bin/${name}`;
        return { version: m[1], path: p };
      })
      .filter((c): c is { version: string; path: string } =>
        c !== null && fs.existsSync(c.path)
      );
    if (candidates.length === 0) return name;
    // Sort by version number (numeric comparison handles 2021.x vs 2025.x correctly)
    candidates.sort((a, b) =>
      a.version.localeCompare(b.version, undefined, { numeric: true })
    );
    return candidates[candidates.length - 1]!.path;
  } catch { /* nix store not available */ }
  return name; // fall back to PATH
}

const YTDLP_PATH = findNixBin("yt-dlp");
const FFMPEG_PATH = findNixBin("ffmpeg");
const FFMPEG_DIR = path.dirname(FFMPEG_PATH);

logger.info({ ytdlp: YTDLP_PATH, ffmpeg: FFMPEG_PATH }, "yt-dlp and ffmpeg resolved");

// ──────────────────────────────────────────────
// YouTube cookies — bypasses bot detection on datacenter/production IPs
// Set YOUTUBE_COOKIES env var to the full text content of a cookies.txt file
// (Netscape format, exported from browser using "Get cookies.txt LOCALLY" extension)
// ──────────────────────────────────────────────
const COOKIES_FILE = "/tmp/yt-cookies.txt";
let COOKIES_AVAILABLE = false;

if (process.env.YOUTUBE_COOKIES && process.env.YOUTUBE_COOKIES.trim().length > 10) {
  try {
    fs.writeFileSync(COOKIES_FILE, process.env.YOUTUBE_COOKIES, "utf8");
    COOKIES_AVAILABLE = true;
    logger.info("YouTube cookies loaded from YOUTUBE_COOKIES env var");
  } catch (e) {
    logger.warn({ err: e }, "Failed to write YouTube cookies file");
  }
} else {
  logger.warn("YOUTUBE_COOKIES env var not set — production downloads may fail due to YouTube bot detection");
}

function getYtDlpPath(): string { return YTDLP_PATH; }
function getFfmpegDir(): string { return FFMPEG_DIR; }
function getCookiesArgs(): string[] {
  return COOKIES_AVAILABLE ? ["--cookies", COOKIES_FILE] : [];
}

function cleanUrl(raw: string): string {
  try {
    const u = new URL(raw.trim());
    ["si", "igshid", "utm_source", "utm_medium", "utm_campaign", "feature", "app"].forEach(p => u.searchParams.delete(p));
    return u.toString();
  } catch {
    return raw.trim();
  }
}

function commonArgs(): string[] {
  return [
    "--no-playlist",
    "--no-warnings",
    // tv_embedded is least restricted by YouTube bot detection; ios as fallback
    "--extractor-args", "youtube:player_client=tv_embedded,ios,android,web",
    "--geo-bypass",
    "--ffmpeg-location", getFfmpegDir(),
    ...getCookiesArgs(),
  ];
}

function runYtDlp(args: string[]): Promise<void> {
  const ytdlp = getYtDlpPath();
  return new Promise((resolve, reject) => {
    const proc = spawn(ytdlp, args, { timeout: 180000 });
    let stderr = "";
    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    proc.stdout.on("data", () => {});
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`yt-dlp failed (exit ${code}): ${stderr.slice(-600)}`));
    });
    proc.on("error", (err) => reject(new Error(`yt-dlp spawn error: ${err.message}`)));
  });
}

async function getVideoMeta(url: string): Promise<{ title: string; thumbnail: string; uploader: string }> {
  const { stdout } = await execFileAsync(getYtDlpPath(), [
    ...commonArgs(),
    "--dump-json",
    url,
  ], { timeout: 30000 });
  const info = JSON.parse(stdout);
  return {
    title: (info.title as string) || "Video",
    thumbnail: (info.thumbnail as string) || "",
    uploader: ((info.uploader || info.channel || "Unknown") as string),
  };
}

function findDownloadedFile(prefix: string): string | null {
  const files = fs.readdirSync(downloadsDir)
    .filter((f) => f.startsWith(prefix))
    .map((f) => ({ name: f, mtime: fs.statSync(path.join(downloadsDir, f)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  return files.length ? path.join(downloadsDir, files[0].name) : null;
}

// ──────────────────────────────────────────────
// GET video info
// ──────────────────────────────────────────────
router.post("/download/info", async (req: Request, res: Response) => {
  const { url } = req.body as { url: string };
  if (!url) { res.status(400).json({ error: "URL is required" }); return; }

  const cleanedUrl = cleanUrl(url);
  try {
    const { stdout } = await execFileAsync(getYtDlpPath(), [
      ...commonArgs(),
      "--dump-json",
      cleanedUrl,
    ], { timeout: 30000 });
    const info = JSON.parse(stdout);

    const formats = [
      { id: "1080", label: "1080p — Full HD", quality: "1080", ext: "mp4", filesize: null },
      { id: "720",  label: "720p — HD",       quality: "720",  ext: "mp4", filesize: null },
      { id: "480",  label: "480p — SD",        quality: "480",  ext: "mp4", filesize: null },
      { id: "360",  label: "360p — SD",        quality: "360",  ext: "mp4", filesize: null },
      { id: "240",  label: "240p",             quality: "240",  ext: "mp4", filesize: null },
      { id: "144",  label: "144p — Low",       quality: "144",  ext: "mp4", filesize: null },
    ];

    res.json({
      title: (info.title as string) || "Unknown",
      thumbnail: (info.thumbnail as string) || "",
      duration: (info.duration as number) || null,
      uploader: ((info.uploader || info.channel || "Unknown") as string),
      formats,
    });
  } catch (err: any) {
    logger.error({ err }, "info fetch failed");
    res.status(500).json({ error: err.message || "Failed to fetch video info" });
  }
});

// ──────────────────────────────────────────────
// Download video (normal or TV-compatible)
// ──────────────────────────────────────────────
router.post("/download/video", async (req: Request, res: Response) => {
  const { url, quality, mode } = req.body as { url: string; quality: string; mode: "normal" | "tv" };
  if (!url) { res.status(400).json({ error: "URL is required" }); return; }

  const userToken = (req as any).userToken as string;
  const cleanedUrl = cleanUrl(url);
  const h = Math.min(parseInt(quality) || 720, mode === "tv" ? 720 : 1080).toString();

  await checkSuspicious(req, cleanedUrl);

  try {
    const ts = Date.now();
    const outTemplate = path.join(downloadsDir, `${ts}_%(title)s.%(ext)s`);

    let formatStr: string;
    if (mode === "tv") {
      formatStr = [
        `bestvideo[vcodec^=avc1][height<=${h}]+bestaudio[ext=m4a]`,
        `bestvideo[vcodec^=avc1][height<=${h}]+bestaudio`,
        `best[vcodec^=avc1][height<=${h}]`,
        `best[height<=${h}]`,
        "best",
      ].join("/");
    } else {
      formatStr = [
        `bestvideo[height<=${h}]+bestaudio`,
        `best[height<=${h}]`,
        "best",
      ].join("/");
    }

    const args = [
      ...commonArgs(),
      "-f", formatStr,
      "--merge-output-format", "mp4",
      "-o", outTemplate,
      cleanedUrl,
    ];

    logger.info({ mode, h, formatStr, url: cleanedUrl, userToken }, "starting video download");
    await runYtDlp(args);

    const filepath = findDownloadedFile(`${ts}_`);
    if (!filepath) { res.status(500).json({ error: "Download completed but file not found" }); return; }

    const filename = path.basename(filepath);
    const { size } = fs.statSync(filepath);

    let title = "Video";
    let thumbnail: string | null = null;
    try {
      const meta = await getVideoMeta(cleanedUrl);
      title = meta.title;
      thumbnail = meta.thumbnail;
      await db.insert(downloadHistoryTable).values({ userToken, title, url: cleanedUrl, type: "video", thumbnail, quality: h, filesize: size });
    } catch { /* non-fatal */ }

    res.json({ downloadUrl: `/api/download/file/${encodeURIComponent(filename)}`, filename, title, filesize: size });
  } catch (err: any) {
    logger.error({ err }, "video download failed");
    res.status(500).json({ error: err.message || "Download failed" });
  }
});

// ──────────────────────────────────────────────
// Download audio (MP3)
// ──────────────────────────────────────────────
router.post("/download/audio", async (req: Request, res: Response) => {
  const { url, quality } = req.body as { url: string; quality?: string };
  if (!url) { res.status(400).json({ error: "URL is required" }); return; }

  const userToken = (req as any).userToken as string;
  const cleanedUrl = cleanUrl(url);
  const aqMap: Record<string, string> = { best: "0", "192": "0", "128": "5" };
  const aq = aqMap[quality || "best"] ?? "0";

  await checkSuspicious(req, cleanedUrl);

  try {
    const ts = Date.now();
    const outTemplate = path.join(downloadsDir, `${ts}_%(title)s.%(ext)s`);

    const args = [
      ...commonArgs(),
      "-x",
      "--audio-format", "mp3",
      "--audio-quality", aq,
      "-o", outTemplate,
      cleanedUrl,
    ];

    logger.info({ quality, aq, url: cleanedUrl, userToken }, "starting audio download");
    await runYtDlp(args);

    const filepath = findDownloadedFile(`${ts}_`);
    if (!filepath) { res.status(500).json({ error: "Audio download completed but file not found" }); return; }

    const filename = path.basename(filepath);
    const { size } = fs.statSync(filepath);

    let title = "Audio";
    let thumbnail: string | null = null;
    try {
      const meta = await getVideoMeta(cleanedUrl);
      title = meta.title;
      thumbnail = meta.thumbnail;
      await db.insert(downloadHistoryTable).values({ userToken, title, url: cleanedUrl, type: "audio", thumbnail, quality: quality || "best", filesize: size });
    } catch { /* non-fatal */ }

    res.json({ downloadUrl: `/api/download/file/${encodeURIComponent(filename)}`, filename, title, filesize: size });
  } catch (err: any) {
    logger.error({ err }, "audio download failed");
    res.status(500).json({ error: err.message || "Audio download failed" });
  }
});

// ──────────────────────────────────────────────
// Serve downloaded file
// ──────────────────────────────────────────────
router.get("/download/file/:filename", (req: Request, res: Response) => {
  const raw = req.params.filename;
  const filename = decodeURIComponent(Array.isArray(raw) ? raw[0] : raw);
  const safeFilename = path.basename(filename);
  const filepath = path.join(downloadsDir, safeFilename);
  if (!fs.existsSync(filepath)) { res.status(404).json({ error: "File not found" }); return; }
  res.download(filepath, safeFilename, (err) => {
    if (!err) setTimeout(() => { try { fs.unlinkSync(filepath); } catch { /* ok */ } }, 60000);
  });
});

// ──────────────────────────────────────────────
// Download history — only returns THIS user's history
// ──────────────────────────────────────────────
router.get("/download/history", async (req: Request, res: Response) => {
  const userToken = (req as any).userToken as string;
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const rows = await db
      .select()
      .from(downloadHistoryTable)
      .where(and(
        eq(downloadHistoryTable.userToken, userToken),
        // Only return records from last 1 hour (older ones get purged anyway)
        // using downloadedAt >= oneHourAgo — drizzle uses gt for >=
      ))
      .orderBy(downloadHistoryTable.downloadedAt)
      .limit(50);

    // Filter client-side as a belt-and-suspenders check
    const fresh = rows.filter(h => h.downloadedAt >= oneHourAgo);

    res.json(fresh.map((h) => ({
      id: h.id,
      title: h.title,
      url: h.url,
      downloadedAt: h.downloadedAt.toISOString(),
      type: h.type,
      thumbnail: h.thumbnail,
    })));
  } catch {
    res.json([]);
  }
});

export default router;
