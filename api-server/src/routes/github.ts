import { Router, type Request, type Response } from "express";
import { logger } from "../lib/logger";

const router = Router();

const GITHUB_USER = "DevAbhishek-in";

router.get("/github/profile", async (_req: Request, res: Response) => {
  try {
    const profileRes = await fetch(`https://api.github.com/users/${GITHUB_USER}`, {
      headers: {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "RockDownloader/1.0",
      },
    });

    if (!profileRes.ok) {
      throw new Error(`GitHub API error: ${profileRes.status}`);
    }

    const profile = await profileRes.json() as Record<string, unknown>;

    const reposRes = await fetch(`https://api.github.com/users/${GITHUB_USER}/repos?sort=stars&per_page=6`, {
      headers: {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "RockDownloader/1.0",
      },
    });

    let repos: Array<{ name: string; html_url: string; description: string | null; language: string | null; stargazers_count: number }> = [];
    if (reposRes.ok) {
      const reposData = await reposRes.json() as Array<Record<string, unknown>>;
      repos = reposData.map((r) => ({
        name: r.name as string,
        html_url: r.html_url as string,
        description: r.description as string | null,
        language: r.language as string | null,
        stargazers_count: (r.stargazers_count as number) || 0,
      }));
    }

    res.json({
      login: profile.login,
      name: profile.name || profile.login,
      bio: profile.bio || null,
      avatar_url: profile.avatar_url,
      html_url: profile.html_url,
      public_repos: profile.public_repos || 0,
      followers: profile.followers || 0,
      following: profile.following || 0,
      repos,
    });
  } catch (err: any) {
    logger.error({ err }, "Failed to fetch GitHub profile");
    res.status(500).json({ error: err.message || "Failed to fetch GitHub profile" });
  }
});

export default router;
