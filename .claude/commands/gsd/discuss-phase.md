---
name: gsd:discuss-phase
description: Gather phase context through adaptive questioning before planning. For UI phases, generates design mockups via Pencil MCP for ideation.
argument-hint: '<phase>'
allowed-tools:
  - Read
  - Write
  - Bash
  - Glob
  - Grep
  - AskUserQuestion
  - mcp__pencil__*
---

<objective>
Extract implementation decisions that downstream agents need — researcher and planner will use CONTEXT.md to know what to investigate and what choices are locked.

**How it works:**

1. Analyze the phase to identify gray areas (UI, UX, behavior, etc.)
2. **For UI phases:** Generate design mockups via Pencil MCP to visualize options
3. Present gray areas — user selects which to discuss
4. Deep-dive each selected area until satisfied
5. Create CONTEXT.md with decisions that guide research and planning

**Output:** `{phase}-CONTEXT.md` — decisions clear enough that downstream agents can act without asking the user again

**For UI phases, also outputs:** Design mockups in Pencil file (in "Draft: Phase X" frame)
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/discuss-phase.md
@./.claude/get-shit-done/templates/context.md
</execution_context>

<context>
Phase number: $ARGUMENTS (required)

**Load project state:**
@.planning/STATE.md

**Load roadmap:**
@.planning/ROADMAP.md
</context>

<process>
1. Validate phase number (error if missing or not in roadmap)
2. **Create phase branch** — Create `feat/phase-{number}-{slug}` branch for all phase work
3. Check if CONTEXT.md exists (offer update/view/skip if yes)
4. **Analyze phase** — Identify domain and generate phase-specific gray areas
5. **Detect UI phase** — If phase involves UI, prepare for design mockup generation
6. **Present gray areas** — Multi-select: which to discuss? (NO skip option)
7. **Deep-dive each area** — 4 questions per area, then offer more/next
8. **For UI phases: Generate design mockups** — Create visual options in Pencil for user to choose
9. **Write CONTEXT.md** — Sections match areas discussed, include approved designs
10. Offer next steps (research or plan)

**CRITICAL: Scope guardrail**

- Phase boundary from ROADMAP.md is FIXED
- Discussion clarifies HOW to implement, not WHETHER to add more
- If user suggests new capabilities: "That's its own phase. I'll note it for later."
- Capture deferred ideas — don't lose them, don't act on them

**Domain-aware gray areas:**
Gray areas depend on what's being built. Analyze the phase goal:

- Something users SEE → layout, density, interactions, states
- Something users CALL → responses, errors, auth, versioning
- Something users RUN → output format, flags, modes, error handling
- Something users READ → structure, tone, depth, flow
- Something being ORGANIZED → criteria, grouping, naming, exceptions

Generate 3-4 **phase-specific** gray areas, not generic categories.

**UI Phase Detection:**
Check if phase involves UI work:

- Phase name contains: "UI", "restyle", "design", "layout", "component", "page", "view"
- Phase goal mentions: visual, styling, interface, appearance, frontend, display
- Phase involves: user-facing changes, screens, forms, dialogs

If UI phase detected, enable Pencil MCP design ideation workflow.

**Probing depth:**

- Ask 4 questions per area before checking
- "More questions about [area], or move to next?"
- If more → ask 4 more, check again
- After all areas → "Ready to create context?"
- **For UI phases:** "Would you like me to generate design mockups based on our discussion?"

**Do NOT ask about (Claude handles these):**

- Technical implementation
- Architecture choices
- Performance concerns
- Scope expansion
  </process>

<success_criteria>

- Gray areas identified through intelligent analysis
- User chose which areas to discuss
- Each selected area explored until satisfied
- Scope creep redirected to deferred ideas
- CONTEXT.md captures decisions, not vague vision
- User knows next steps
  </success_criteria>
