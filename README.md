# PALACO-INDUSTRIE

## Vision

PALACO-INDUSTRIE is the foundation for the Future Internet Era (F.I.E.) program and the long-term development of the PALACO product ecosystem. The goal is to create a low-threshold, inclusive digital system in which every person can build and manage their own Citadel(s) and one or more PALACO'S WORLD(S).

## Core Product Direction

The platform is intended to provide each user with:

- a personal digital environment built around one or more Citadels
- access to one or more PALACO'S WORLD(S)
- an integrated chatbox function named **RIO**
- an integrated browser function named **L.O.G.O.**

## Target Audience

PALACO is designed for everyone, from young to old. Nobody is excluded: the system should be welcoming, understandable, and usable for all kinds of users.

## Design Principles

The project should be guided by these core principles:

- low barrier to entry
- universal, easy-to-understand interfaces
- accessibility for a broad audience
- flexibility for users to shape their own digital spaces
- a product structure that can grow into a broader PALACO ecosystem

## Current Repository Status

This repository is currently at the concept stage. The next step is to translate this vision into a first concrete product scope, technical architecture, and implementation roadmap.

## First Build

The repository now includes a first static PALACO prototype with:

- a landing experience for the F.I.E. vision
- a personal Citadel setup flow
- a browser-based **RIO** chatbox prototype
- a guided **L.O.G.O.** browser area with curated destinations
- account-based sign-up and sign-in
- backend persistence for Citadel data and RIO message history
- repository-world integration for the current PALACO repository portfolio
- live GitHub repository sync with fallback catalog support

## Local Usage

Start the local PALACO server from `/home/runner/work/PALACO-INDUSTRIE/PALACO-INDUSTRIE`:

```bash
npm start
```

Then open `http://localhost:3000`.

The current build uses a small Node server to:

- serve the frontend
- create and authenticate accounts
- persist Citadel data
- persist RIO chat history
- persist sign-in sessions across server restarts
- sync the repository catalog from GitHub
- fall back to a local repository catalog when live sync is unavailable

Saved application data is written locally to the SQLite database at `/home/runner/work/PALACO-INDUSTRIE/PALACO-INDUSTRIE/data/palaco.db`.

If an older `/home/runner/work/PALACO-INDUSTRIE/PALACO-INDUSTRIE/data/palaco-store.json` file is present, the server migrates its account, Citadel, and RIO data into SQLite on startup.

The current repository-world catalog includes:

- `Maurits-pixe/PALACO`
- `Maurits-pixe/PALACO-INDUSTRIE`

## GitHub Repository Sync

By default, the server loads public repositories from `Maurits-pixe` through the GitHub API.

Optional environment variables:

- `GITHUB_OWNER` to load repositories for a different GitHub account
- `GITHUB_TOKEN` to include private owned repositories in the sync
- `SESSION_TTL_DAYS` to control how long persisted sign-in sessions remain valid

When GitHub sync is unavailable, the interface falls back to the built-in PALACO repository catalog so the application remains usable.

## Authentication

The app now uses an httpOnly session cookie for browser authentication. Session tokens are stored hashed in SQLite and are not kept in browser localStorage. Authenticated write requests also require a session-bound CSRF token supplied by the frontend.

This build now uses SQLite for persistence, including persisted sign-in sessions, but it still does not include a managed production database, shared multi-user spaces, or advanced world-building features.