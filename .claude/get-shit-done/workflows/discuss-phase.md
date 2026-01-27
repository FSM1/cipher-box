<purpose>
Extract implementation decisions that downstream agents need. Analyze the phase to identify gray areas, let the user choose what to discuss, then deep-dive each selected area until satisfied.

You are a thinking partner, not an interviewer. The user is the visionary — you are the builder. Your job is to capture decisions that will guide research and planning, not to figure out implementation yourself.
</purpose>

<downstream_awareness>
**CONTEXT.md feeds into:**

1. **gsd-phase-researcher** — Reads CONTEXT.md to know WHAT to research
   - "User wants card-based layout" → researcher investigates card component patterns
   - "Infinite scroll decided" → researcher looks into virtualization libraries

2. **gsd-planner** — Reads CONTEXT.md to know WHAT decisions are locked
   - "Pull-to-refresh on mobile" → planner includes that in task specs
   - "Claude's Discretion: loading skeleton" → planner can decide approach

**Your job:** Capture decisions clearly enough that downstream agents can act on them without asking the user again.

**Not your job:** Figure out HOW to implement. That's what research and planning do with the decisions you capture.
</downstream_awareness>

<philosophy>
**User = founder/visionary. Claude = builder.**

The user knows:

- How they imagine it working
- What it should look/feel like
- What's essential vs nice-to-have
- Specific behaviors or references they have in mind

The user doesn't know (and shouldn't be asked):

- Codebase patterns (researcher reads the code)
- Technical risks (researcher identifies these)
- Implementation approach (planner figures this out)
- Success metrics (inferred from the work)

Ask about vision and implementation choices. Capture decisions for downstream agents.
</philosophy>

<scope_guardrail>
**CRITICAL: No scope creep.**

The phase boundary comes from ROADMAP.md and is FIXED. Discussion clarifies HOW to implement what's scoped, never WHETHER to add new capabilities.

**Allowed (clarifying ambiguity):**

- "How should posts be displayed?" (layout, density, info shown)
- "What happens on empty state?" (within the feature)
- "Pull to refresh or manual?" (behavior choice)

**Not allowed (scope creep):**

- "Should we also add comments?" (new capability)
- "What about search/filtering?" (new capability)
- "Maybe include bookmarking?" (new capability)

**The heuristic:** Does this clarify how we implement what's already in the phase, or does it add a new capability that could be its own phase?

**When user suggests scope creep:**

```
"[Feature X] would be a new capability — that's its own phase.
Want me to note it for the roadmap backlog?

For now, let's focus on [phase domain]."
```

Capture the idea in a "Deferred Ideas" section. Don't lose it, don't act on it.
</scope_guardrail>

<gray_area_identification>
Gray areas are **implementation decisions the user cares about** — things that could go multiple ways and would change the result.

**How to identify gray areas:**

1. **Read the phase goal** from ROADMAP.md
2. **Understand the domain** — What kind of thing is being built?
   - Something users SEE → visual presentation, interactions, states matter
   - Something users CALL → interface contracts, responses, errors matter
   - Something users RUN → invocation, output, behavior modes matter
   - Something users READ → structure, tone, depth, flow matter
   - Something being ORGANIZED → criteria, grouping, handling exceptions matter
3. **Generate phase-specific gray areas** — Not generic categories, but concrete decisions for THIS phase

**Don't use generic category labels** (UI, UX, Behavior). Generate specific gray areas:

```
Phase: "User authentication"
→ Session handling, Error responses, Multi-device policy, Recovery flow

Phase: "Organize photo library"
→ Grouping criteria, Duplicate handling, Naming convention, Folder structure

Phase: "CLI for database backups"
→ Output format, Flag design, Progress reporting, Error recovery

Phase: "API documentation"
→ Structure/navigation, Code examples depth, Versioning approach, Interactive elements
```

**The key question:** What decisions would change the outcome that the user should weigh in on?

**Claude handles these (don't ask):**

- Technical implementation details
- Architecture patterns
- Performance optimization
- Scope (roadmap defines this)
  </gray_area_identification>

<process>

<step name="validate_phase" priority="first">
Phase number from argument (required).

Load and validate:

- Read `.planning/ROADMAP.md`
- Find phase entry
- Extract: number, name, description, status

**If phase not found:**

```
Phase [X] not found in roadmap.

Use /gsd:progress to see available phases.
```

Exit workflow.

**If phase found:** Continue to create_phase_branch.
</step>

<step name="create_phase_branch">
Create a dedicated branch for all phase work before any changes.

```bash
# Get current branch
CURRENT_BRANCH=$(git branch --show-current)

# Extract phase name from roadmap
PHASE_NAME=$(grep -E "^\*?\*?Phase ${PHASE}:" .planning/ROADMAP.md | sed -E 's/.*Phase [0-9]+: //' | sed 's/\*//g' | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | cut -d'-' -f1-3)
PADDED_PHASE=$(printf "%02d" ${PHASE})
BRANCH_NAME="feat/phase-${PADDED_PHASE}-${PHASE_NAME}"

# Check if already on this phase branch (resuming)
if [ "$CURRENT_BRANCH" = "$BRANCH_NAME" ]; then
  echo "Already on phase branch: $BRANCH_NAME"
else
  # Check if branch already exists
  if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
    echo "Switching to existing phase branch: $BRANCH_NAME"
    git checkout "$BRANCH_NAME"
  else
    echo "Creating phase branch from main: $BRANCH_NAME"
    git checkout main
    git pull origin main
    git checkout -b "$BRANCH_NAME"
  fi
fi
```

**Skip conditions:**

- Already on the correct phase branch (resuming discussion)

Report: "Working on branch: {branch_name}"

Continue to check_existing.
</step>

<step name="check_existing">
Check if CONTEXT.md already exists:

```bash
# Match both zero-padded (05-*) and unpadded (5-*) folders
PADDED_PHASE=$(printf "%02d" ${PHASE})
ls .planning/phases/${PADDED_PHASE}-*/CONTEXT.md .planning/phases/${PADDED_PHASE}-*/${PADDED_PHASE}-CONTEXT.md .planning/phases/${PHASE}-*/CONTEXT.md .planning/phases/${PHASE}-*/${PHASE}-CONTEXT.md 2>/dev/null
```

**If exists:**
Use AskUserQuestion:

- header: "Existing context"
- question: "Phase [X] already has context. What do you want to do?"
- options:
  - "Update it" — Review and revise existing context
  - "View it" — Show me what's there
  - "Skip" — Use existing context as-is

If "Update": Load existing, continue to analyze_phase
If "View": Display CONTEXT.md, then offer update/skip
If "Skip": Exit workflow

**If doesn't exist:** Continue to analyze_phase.
</step>

<step name="analyze_phase">
Analyze the phase to identify gray areas worth discussing.

**Read the phase description from ROADMAP.md and determine:**

1. **Domain boundary** — What capability is this phase delivering? State it clearly.

2. **Gray areas by category** — For each relevant category (UI, UX, Behavior, Empty States, Content), identify 1-2 specific ambiguities that would change implementation.

3. **Skip assessment** — If no meaningful gray areas exist (pure infrastructure, clear-cut implementation), the phase may not need discussion.

**Output your analysis internally, then present to user.**

Example analysis for "Post Feed" phase:

```
Domain: Displaying posts from followed users
Gray areas:
- UI: Layout style (cards vs timeline vs grid)
- UI: Information density (full posts vs previews)
- Behavior: Loading pattern (infinite scroll vs pagination)
- Empty State: What shows when no posts exist
- Content: What metadata displays (time, author, reactions count)
```

</step>

<step name="present_gray_areas">
Present the domain boundary and gray areas to user.

**First, state the boundary:**

```
Phase [X]: [Name]
Domain: [What this phase delivers — from your analysis]

We'll clarify HOW to implement this.
(New capabilities belong in other phases.)
```

**Then use AskUserQuestion (multiSelect: true):**

- header: "Discuss"
- question: "Which areas do you want to discuss for [phase name]?"
- options: Generate 3-4 phase-specific gray areas, each formatted as:
  - "[Specific area]" (label) — concrete, not generic
  - [1-2 questions this covers] (description)

**Do NOT include a "skip" or "you decide" option.** User ran this command to discuss — give them real choices.

**Examples by domain:**

For "Post Feed" (visual feature):

```
☐ Layout style — Cards vs list vs timeline? Information density?
☐ Loading behavior — Infinite scroll or pagination? Pull to refresh?
☐ Content ordering — Chronological, algorithmic, or user choice?
☐ Post metadata — What info per post? Timestamps, reactions, author?
```

For "Database backup CLI" (command-line tool):

```
☐ Output format — JSON, table, or plain text? Verbosity levels?
☐ Flag design — Short flags, long flags, or both? Required vs optional?
☐ Progress reporting — Silent, progress bar, or verbose logging?
☐ Error recovery — Fail fast, retry, or prompt for action?
```

For "Organize photo library" (organization task):

```
☐ Grouping criteria — By date, location, faces, or events?
☐ Duplicate handling — Keep best, keep all, or prompt each time?
☐ Naming convention — Original names, dates, or descriptive?
☐ Folder structure — Flat, nested by year, or by category?
```

Continue to discuss_areas with selected areas.
</step>

<step name="discuss_areas">
For each selected area, conduct a focused discussion loop.

**Philosophy: 4 questions, then check.**

Ask 4 questions per area before offering to continue or move on. Each answer often reveals the next question.

**For each area:**

1. **Announce the area:**

   ```
   Let's talk about [Area].
   ```

2. **Ask 4 questions using AskUserQuestion:**
   - header: "[Area]"
   - question: Specific decision for this area
   - options: 2-3 concrete choices (AskUserQuestion adds "Other" automatically)
   - Include "You decide" as an option when reasonable — captures Claude discretion

3. **After 4 questions, check:**
   - header: "[Area]"
   - question: "More questions about [area], or move to next?"
   - options: "More questions" / "Next area"

   If "More questions" → ask 4 more, then check again
   If "Next area" → proceed to next selected area

4. **After all areas complete:**
   - header: "Done"
   - question: "That covers [list areas]. Ready to create context?"
   - options: "Create context" / "Revisit an area"

**Question design:**

- Options should be concrete, not abstract ("Cards" not "Option A")
- Each answer should inform the next question
- If user picks "Other", receive their input, reflect it back, confirm

**Scope creep handling:**
If user mentions something outside the phase domain:

```
"[Feature] sounds like a new capability — that belongs in its own phase.
I'll note it as a deferred idea.

Back to [current area]: [return to current question]"
```

Track deferred ideas internally.
</step>

<step name="write_context">
Create CONTEXT.md capturing decisions made.

**Find or create phase directory:**

```bash
# Match existing directory (padded or unpadded)
PADDED_PHASE=$(printf "%02d" ${PHASE})
PHASE_DIR=$(ls -d .planning/phases/${PADDED_PHASE}-* .planning/phases/${PHASE}-* 2>/dev/null | head -1)
if [ -z "$PHASE_DIR" ]; then
  # Create from roadmap name (lowercase, hyphens)
  PHASE_NAME=$(grep "Phase ${PHASE}:" .planning/ROADMAP.md | sed 's/.*Phase [0-9]*: //' | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
  mkdir -p ".planning/phases/${PADDED_PHASE}-${PHASE_NAME}"
  PHASE_DIR=".planning/phases/${PADDED_PHASE}-${PHASE_NAME}"
fi
```

**File location:** `${PHASE_DIR}/${PADDED_PHASE}-CONTEXT.md`

**Structure the content by what was discussed:**

```markdown
# Phase [X]: [Name] - Context

**Gathered:** [date]
**Status:** Ready for planning

<domain>
## Phase Boundary

[Clear statement of what this phase delivers — the scope anchor]

</domain>

<decisions>
## Implementation Decisions

### [Category 1 that was discussed]

- [Decision or preference captured]
- [Another decision if applicable]

### [Category 2 that was discussed]

- [Decision or preference captured]

### Claude's Discretion

[Areas where user said "you decide" — note that Claude has flexibility here]

</decisions>

<specifics>
## Specific Ideas

[Any particular references, examples, or "I want it like X" moments from discussion]

[If none: "No specific requirements — open to standard approaches"]

</specifics>

<deferred>
## Deferred Ideas

[Ideas that came up but belong in other phases. Don't lose them.]

[If none: "None — discussion stayed within phase scope"]

</deferred>

---

_Phase: XX-name_
_Context gathered: [date]_
```

Write file.
</step>

<step name="confirm_creation">
Present summary and next steps:

```
Created: .planning/phases/${PADDED_PHASE}-${SLUG}/${PADDED_PHASE}-CONTEXT.md

## Decisions Captured

### [Category]
- [Key decision]

### [Category]
- [Key decision]

[If deferred ideas exist:]
## Noted for Later
- [Deferred idea] — future phase

---

## ▶ Next Up

**Phase ${PHASE}: [Name]** — [Goal from ROADMAP.md]

`/gsd:plan-phase ${PHASE}`

<sub>`/clear` first → fresh context window</sub>

---

**Also available:**
- `/gsd:plan-phase ${PHASE} --skip-research` — plan without research
- Review/edit CONTEXT.md before continuing

---
```

</step>

<step name="git_commit">
Commit phase context:

```bash
git add "${PHASE_DIR}/${PADDED_PHASE}-CONTEXT.md"
git commit -m "$(cat <<'EOF'
docs(${PADDED_PHASE}): capture phase context

Phase ${PADDED_PHASE}: ${PHASE_NAME}
- Implementation decisions documented
- Phase boundary established
EOF
)"
```

Confirm: "Committed: docs(${PADDED_PHASE}): capture phase context"
</step>

</process>

<step name="detect_ui_phase">
After analyzing the phase, determine if it involves UI work.

**UI phase indicators:**

- Phase name contains: "UI", "restyle", "design", "layout", "component", "page", "view", "browser", "dashboard"
- Phase goal mentions: visual, styling, interface, appearance, frontend, display, screen
- Phase involves: user-facing changes, forms, dialogs, navigation

```bash
# Check phase name and description for UI keywords
PHASE_TEXT=$(grep -i "Phase ${PHASE}:" .planning/ROADMAP.md)
if echo "$PHASE_TEXT" | grep -iqE "ui|restyle|design|layout|component|page|view|browser|dashboard|visual|interface|frontend|display|screen"; then
  IS_UI_PHASE=true
else
  IS_UI_PHASE=false
fi
```

**If UI phase:**

1. Check for existing Pencil design file
2. Load existing design tokens (colors, typography, spacing) if available
3. Enable design mockup generation during discussion
4. Note to user: "This is a UI phase — I can generate design mockups to help visualize options."
</step>

<step name="generate_design_mockups">
**Only for UI phases.** After discussing gray areas, offer to generate design mockups.

**Trigger:**
After all areas discussed, before writing CONTEXT.md:

```
We've discussed the implementation details. Since this is a UI phase,
I can generate design mockups in Pencil to visualize the options.

Would you like me to create design mockups based on our discussion?
```

- Options: "Yes, generate mockups" / "Skip mockups"

**If yes, generate mockups:**

1. **Create draft frame in Pencil:**

```typescript
// Create a separate frame for draft designs (doesn't interfere with existing)
mcp__pencil__create_design({
  type: 'frame',
  name: `Draft: Phase ${PHASE} - ${PHASE_NAME}`,
  width: 1440,
  height: 900,
  fill: '#000000',  // Use existing design tokens
  children: []
});
```

2. **Generate design options based on discussion:**

For each major UI decision, create visual options:

```typescript
// Example: Layout options discussed
if (layoutDecision === 'needs_mockup') {
  // Option A: Card layout
  mcp__pencil__create_design({
    parentFrame: `Draft: Phase ${PHASE}`,
    type: 'frame',
    name: 'Option A: Card Layout',
    x: 0,
    y: 0,
    width: 400,
    height: 300,
    children: [/* card components */]
  });

  // Option B: List layout
  mcp__pencil__create_design({
    parentFrame: `Draft: Phase ${PHASE}`,
    type: 'frame',
    name: 'Option B: List Layout',
    x: 420,
    y: 0,
    width: 400,
    height: 300,
    children: [/* list components */]
  });
}
```

3. **Use existing design tokens:**

```bash
# Extract tokens from existing design
DESIGN_FILE=$(ls designs/*.pen 2>/dev/null | head -1)
if [ -n "$DESIGN_FILE" ]; then
  # Get color palette
  COLORS=$(cat "$DESIGN_FILE" | jq -r '.. | .fill? // empty' | sort -u | grep "^#")
  # Get typography
  FONTS=$(cat "$DESIGN_FILE" | jq -r '.. | select(.type=="text") | .fontFamily' | sort -u | head -1)
fi
```

Apply existing tokens to maintain visual consistency with the rest of the app.

4. **Present options to user:**

```
I've created design mockups in Pencil:

**Frame:** "Draft: Phase ${PHASE} - ${PHASE_NAME}"

**Options generated:**
- Option A: [Description] - [What it looks like]
- Option B: [Description] - [What it looks like]
- Option C: [Description] - [What it looks like]

You can view these in Pencil. Which approach do you prefer?
```

Use AskUserQuestion:
- header: "Design Options"
- question: "Which design direction do you prefer?"
- options: ["Option A: [name]", "Option B: [name]", "Option C: [name]", "Combine elements", "None - try different approach"]

5. **Iterate if needed:**

If user wants changes:
- "Combine elements" → Ask which elements from which options
- "None" → Ask what they'd like to see instead, generate new options

6. **Finalize approved design:**

Once user approves:

```typescript
// Rename approved design frame
mcp__pencil__update_design({
  frameId: approvedFrameId,
  name: `Approved: Phase ${PHASE} - ${PHASE_NAME}`
});

// Or copy to main design area if user wants
mcp__pencil__copy_frame({
  sourceFrame: approvedFrameId,
  targetParent: 'root',  // Main design area
  newName: `Phase ${PHASE}: ${COMPONENT_NAME}`
});
```

**Record in CONTEXT.md:**

```markdown
### Approved Design

**Pencil frame:** "Approved: Phase ${PHASE} - ${PHASE_NAME}"
**Design file:** designs/[filename].pen

The approved design mockup captures:
- [Key visual decision 1]
- [Key visual decision 2]
- [Key visual decision 3]

This design serves as the source of truth for implementation.
```
</step>

<step name="design_mockup_patterns">
**Common mockup patterns for UI phases:**

### File Browser / List View
```typescript
{
  type: 'frame',
  name: 'File List Option',
  layout: 'vertical',
  gap: 0,
  children: [
    // Header row
    { type: 'frame', name: 'header', height: 40, layout: 'horizontal', children: [...] },
    // File rows
    { type: 'frame', name: 'row', height: 48, layout: 'horizontal', children: [...] }
  ]
}
```

### Card Grid
```typescript
{
  type: 'frame',
  name: 'Card Grid Option',
  layout: 'horizontal',
  wrap: true,
  gap: 16,
  children: [
    { type: 'frame', name: 'card', width: 200, height: 150, cornerRadius: 8, children: [...] }
  ]
}
```

### Modal / Dialog
```typescript
{
  type: 'frame',
  name: 'Modal Option',
  width: 400,
  height: 300,
  fill: '#111111',
  stroke: { thickness: 1, fill: '#00D084' },
  cornerRadius: 8,
  children: [
    { type: 'text', content: 'Title', fontSize: 16, fontWeight: '600' },
    // Content
    { type: 'frame', name: 'actions', layout: 'horizontal', gap: 12, children: [...] }
  ]
}
```

### Navigation / Sidebar
```typescript
{
  type: 'frame',
  name: 'Sidebar Option',
  width: 240,
  height: 'fill_container',
  fill: '#0a0a0a',
  layout: 'vertical',
  padding: [16, 12],
  gap: 8,
  children: [
    { type: 'text', content: 'Navigation', fontSize: 12, fontWeight: '600' },
    // Nav items
  ]
}
```

### Empty State
```typescript
{
  type: 'frame',
  name: 'Empty State Option',
  layout: 'vertical',
  justifyContent: 'center',
  alignItems: 'center',
  gap: 16,
  children: [
    { type: 'text', content: 'No items yet', fontSize: 14, fill: '#666666' },
    { type: 'frame', name: 'cta-button', children: [...] }
  ]
}
```
</step>

<success_criteria>

- Phase validated against roadmap
- Gray areas identified through intelligent analysis (not generic questions)
- User selected which areas to discuss
- Each selected area explored until user satisfied
- Scope creep redirected to deferred ideas
- **For UI phases:** Design mockups generated and user approved a direction
- CONTEXT.md captures actual decisions, not vague vision
- **For UI phases:** CONTEXT.md references approved Pencil design frame
- Deferred ideas preserved for future phases
- User knows next steps
  </success_criteria>
