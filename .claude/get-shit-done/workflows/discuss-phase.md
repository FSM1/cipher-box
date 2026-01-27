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

## Step 1: Load Existing Design Context (REQUIRED)

Before creating ANY new design, load the existing design system:

```typescript
// Get existing design file
const designFile = await mcp__pencil__read_design({ path: 'designs/*.pen' });

// Extract established tokens
const existingTokens = await mcp__pencil__get_design_tokens({
  file: designFile.path,
  extract: ['colors', 'typography', 'spacing', 'effects', 'borders']
});

// Example extracted tokens:
// {
//   colors: {
//     background: '#000000',
//     primary: '#00D084',
//     secondary: '#006644',
//     border: '#003322',
//     text: '#00D084',
//     textMuted: '#006644'
//   },
//   typography: {
//     fontFamily: 'JetBrains Mono',
//     sizes: { xs: 10, sm: 11, base: 14, lg: 18, xl: 24 },
//     weights: { normal: 400, semibold: 600, bold: 700 }
//   },
//   spacing: { xs: 8, sm: 12, md: 16, lg: 24, xl: 32 },
//   borders: { thickness: 1, radius: 0 },
//   effects: { glow: { blur: 10, color: '#00D08466' } }
// }
```

## Step 2: Translate User Intent to Design Parameters

Map discussion decisions to concrete design specs:

```typescript
// Capture user preferences from discussion
const userIntent = {
  // From discussion answers
  layout: discussionAnswers.layoutStyle,      // e.g., "cards", "list", "grid"
  density: discussionAnswers.density,          // e.g., "compact", "comfortable", "spacious"
  emphasis: discussionAnswers.emphasis,        // e.g., "content-first", "visual-heavy"
  interactions: discussionAnswers.interactions, // e.g., "hover effects", "minimal"

  // Quoted user statements (preserve exact wording)
  userQuotes: [
    "I want it to feel like a terminal",
    "Green accents but not overwhelming",
    "Clean and minimal"
  ]
};

// Translate intent to design parameters
function translateIntentToDesign(intent, existingTokens) {
  const params = {
    // Always use existing tokens for consistency
    colors: existingTokens.colors,
    typography: existingTokens.typography,
    spacing: existingTokens.spacing,

    // Derive layout from user preferences
    layout: {
      type: intent.layout,
      gap: intent.density === 'compact' ? existingTokens.spacing.xs :
           intent.density === 'spacious' ? existingTokens.spacing.lg :
           existingTokens.spacing.md,
      padding: intent.density === 'compact' ? existingTokens.spacing.sm :
               existingTokens.spacing.md
    },

    // Derive visual treatment from user quotes
    visualStyle: {
      useBorders: intent.userQuotes.some(q => q.includes('terminal')),
      useGlow: intent.userQuotes.some(q => q.includes('accent')),
      cornerRadius: intent.userQuotes.some(q => q.includes('terminal')) ? 0 : 4
    }
  };

  return params;
}

const designParams = translateIntentToDesign(userIntent, existingTokens);
```

## Step 3: Create Design with Full Context

Pass both user intent AND existing tokens to Pencil:

```typescript
// Create draft frame with consistency context
const draftFrame = await mcp__pencil__create_design({
  type: 'frame',
  name: `Draft: Phase ${PHASE} - ${PHASE_NAME}`,
  width: 1440,
  height: 900,

  // Use ONLY existing tokens
  fill: existingTokens.colors.background,

  // Pass context for AI-assisted design generation
  designContext: {
    // Existing design system (for consistency)
    tokens: existingTokens,

    // User's stated preferences (from discussion)
    userIntent: userIntent,

    // Translated parameters
    derivedParams: designParams,

    // Reference to existing components (match their patterns)
    referenceFrames: ['Desktop File Browser', 'Login Screen'],

    // Explicit consistency rules
    consistencyRules: [
      'Use ONLY colors from existing palette',
      'Match typography scale exactly',
      'Follow established spacing increments',
      'Maintain border style (1px solid, sharp corners)',
      'Apply glow effects consistently with existing usage'
    ]
  }
});
```

## Step 4: Generate Options Based on User Preferences

For each discussed gray area, generate options that respect both user intent AND existing design:

```typescript
// Example: User discussed layout preferences
// Discussion captured: "cards vs list", user said "I like the density of lists but visual appeal of cards"

const optionA = await mcp__pencil__create_design({
  parentFrame: draftFrame.id,
  type: 'frame',
  name: 'Option A: Compact Cards',

  // Derived from user intent: "density of lists" + "visual appeal of cards"
  layout: 'grid',
  gap: existingTokens.spacing.xs,  // Compact like list

  // Visual treatment from existing design
  children: [
    {
      type: 'frame',
      name: 'card',
      width: 280,
      height: 80,  // Shorter than typical cards = more dense
      fill: existingTokens.colors.background,
      stroke: { thickness: 1, fill: existingTokens.colors.border },
      // ... using existing tokens throughout
    }
  ],

  // Document the reasoning
  designNotes: 'Combines list density (compact height) with card visual structure. ' +
               'Uses existing border style and spacing tokens.'
});

const optionB = await mcp__pencil__create_design({
  parentFrame: draftFrame.id,
  type: 'frame',
  name: 'Option B: Dense List with Card Accents',

  // Alternative interpretation of same user intent
  layout: 'vertical',
  gap: 0,  // List-like, no gaps

  children: [
    {
      type: 'frame',
      name: 'row',
      height: 48,
      // Card-like visual: subtle background on hover, border-bottom
      stroke: { thickness: 1, fill: existingTokens.colors.border, sides: ['bottom'] },
    }
  ],

  designNotes: 'List structure with card-like visual treatment (borders, hover states). ' +
               'Matches existing file browser row pattern.'
});
```

## Step 5: Present with Design Rationale

Show user how their input shaped each option:

```markdown
I've created design mockups based on our discussion:

**Frame:** "Draft: Phase ${PHASE} - ${PHASE_NAME}"

**Your preferences I incorporated:**
- "${userQuote1}" → [how it influenced the design]
- "${userQuote2}" → [how it influenced the design]
- Layout: ${layoutChoice} → [specific implementation]

**Design consistency maintained:**
- Colors: Using existing palette (#000000, #00D084, #006644)
- Typography: JetBrains Mono at established sizes
- Spacing: Following 8/12/16/24/32px scale
- Borders: 1px solid, sharp corners (terminal aesthetic)

**Options generated:**

**Option A: Compact Cards**
- Addresses: "density of lists" + "visual appeal of cards"
- Layout: Grid with 8px gaps
- Cards: 280×80px (shorter than typical = more dense)

**Option B: Dense List with Card Accents**
- Addresses: Same preferences, different approach
- Layout: Vertical list, no gaps
- Visual: Card-like borders and hover states

Which direction resonates more with your vision?
```

## Step 6: Iterate with Context Preserved

If user wants changes, preserve all context:

```typescript
// User says: "I like Option A but want more breathing room"
const revision = await mcp__pencil__create_design({
  parentFrame: draftFrame.id,
  type: 'frame',
  name: 'Option A (Revised): Cards with More Space',

  // Start from Option A
  baseOn: optionA.id,

  // Apply user's revision request
  modifications: {
    gap: existingTokens.spacing.sm,  // Increased from xs
    cardHeight: 96,  // Slightly taller
  },

  // Track the iteration
  designNotes: 'Revision of Option A per user feedback: "more breathing room". ' +
               'Increased gap to 12px, card height to 96px. ' +
               'Still within established spacing scale.'
});
```

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
