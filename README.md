# StormForge

**Self-evolving autonomous red teaming / bug hunting framework.**  
Cloudflare-native upgrade of T3MP3ST with Tactic Genome Evolution Engine (grammar-guided genetic algorithm breeding), parallel execution, atomic payloads, frontier LLM dynamic planning (Grok 4.5 / Sonnet 5 class), automatic tool calling, and dead-simple dashboard.

**Warning**: Authorized targets only. Unauthorized use is illegal. Use at your own risk.

## Features
- Full autonomous kill chain with real-time LLM replanning
- Self-evolving Tactic Genome Breeding (unique GA + grammar guidance)
- Parallel recon & execution
- Atomic payload engine
- Risk scoring before exploitation
- Automatic disclosure draft generation
- Ultra-simple dashboard (one button launch)
- Hybrid Cloudflare Workers + Durable Objects

## Quick Start
1. Clone this repo
2. Configure LLM endpoint in `src/planning/llm-dynamic-planner.ts`
3. Deploy to Cloudflare Workers/Pages
4. Open `dashboard/index.html` → enter target → Launch Hunt

**For Claude Code / Cursor**: The full source is here. Edit freely.

See `UPGRADE_ARSENAL_CHAINING.md` for detailed architecture.

**Authorized use only.**