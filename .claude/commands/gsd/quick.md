---
name: gsd:quick
description: Execute a quick task with GSD guarantees (atomic commits, state tracking) but skip optional agents. For UI tasks, supports Pencil design-first workflow.
argument-hint: ""
allowed-tools:
  - Read
  - Write
  - Edit
  - Glob
  - Grep
  - Bash
  - Task
  - AskUserQuestion
  - mcp__pencil__*
  - mcp__playwright__*
---

<objective>
Execute small, ad-hoc tasks with GSD guarantees (atomic commits, STATE.md tracking) while skipping optional agents (research, plan-checker, verifier).

Quick mode is the same system with a shorter path:
- Spawns gsd-planner (quick mode) + gsd-executor(s)
- Skips gsd-phase-researcher, gsd-plan-checker, gsd-verifier
- Quick tasks live in `.planning/quick/` separate from planned phases
- Updates STATE.md "Quick Tasks Completed" table (NOT ROADMAP.md)

**For UI tasks:**
- Detects UI-related task descriptions
- Offers to generate/use Pencil designs before planning
- Optionally verifies against design with Playwright MCP after execution

Use when: You know exactly what to do and the task is small enough to not need research or verification.
</objective>

<execution_context>
Orchestration is inline - no separate workflow file. Quick mode is deliberately simpler than full GSD.
</execution_context>

<context>
@.planning/STATE.md
</context>

<process>
**Step 1: Pre-flight validation**

Check that an active GSD project exists:

```bash
if [ ! -f .planning/ROADMAP.md ]; then
  echo "Quick mode requires an active project with ROADMAP.md."
  echo "Run /gsd:new-project first."
  exit 1
fi
```

If validation fails, stop immediately with the error message.

Quick tasks can run mid-phase - validation only checks ROADMAP.md exists, not phase status.

---

**Step 2: Get task description**

Prompt user interactively for the task description:

```
AskUserQuestion(
  header: "Quick Task",
  question: "What do you want to do?",
  followUp: null
)
```

Store response as `$DESCRIPTION`.

If empty, re-prompt: "Please provide a task description."

Generate slug from description:
```bash
slug=$(echo "$DESCRIPTION" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//' | cut -c1-40)
```

---

**Step 2b: Detect UI task and offer design workflow**

Check if the task description involves UI work:

```bash
# Check for UI keywords in description
if echo "$DESCRIPTION" | grep -iqE "ui|style|design|layout|component|page|view|button|form|modal|dialog|sidebar|header|footer|nav|menu|card|list|table|icon|color|font|spacing|responsive|mobile|css|visual|appearance"; then
  IS_UI_TASK=true
else
  IS_UI_TASK=false
fi
```

**If UI task detected:**

1. Check for existing Pencil design file:
```bash
DESIGN_FILE=$(ls designs/*.pen 2>/dev/null | head -1)
```

2. Offer design workflow:
```
AskUserQuestion(
  header: "UI Task Detected",
  question: "This looks like a UI task. How would you like to proceed?",
  options: [
    "Use existing Pencil design" (if design file exists),
    "Generate new design mockup first",
    "Skip design - just implement"
  ]
)
```

3. **If "Use existing design":**
   - Load design tokens from existing `.pen` file
   - Ask which frame/component to reference
   - Store design reference for planner context

4. **If "Generate new mockup":**

   First, load existing design context for consistency:
   ```typescript
   // Load existing design system
   const existingDesign = await mcp__pencil__read_design({ path: DESIGN_FILE });
   const tokens = await mcp__pencil__get_design_tokens({
     file: DESIGN_FILE,
     extract: ['colors', 'typography', 'spacing', 'effects', 'borders']
   });
   ```

   Then, translate user's task description to design parameters:
   ```typescript
   // Parse task description for design intent
   const taskIntent = {
     description: DESCRIPTION,  // e.g., "Add a delete confirmation modal"
     componentType: inferComponentType(DESCRIPTION),  // e.g., "modal"
     action: inferAction(DESCRIPTION),  // e.g., "delete" → destructive styling
   };

   // Map to design parameters using existing tokens
   const designParams = {
     colors: tokens.colors,
     typography: tokens.typography,
     // Adjust for context (e.g., destructive action = error color)
     accentColor: taskIntent.action === 'delete' ? '#EF4444' : tokens.colors.primary,
   };
   ```

   Create mockup with full context:
   ```typescript
   await mcp__pencil__create_design({
     type: 'frame',
     name: `Quick: ${slug}`,
     width: 800,
     height: 600,
     fill: tokens.colors.background,

     // Pass context for consistency
     designContext: {
       tokens: tokens,
       taskIntent: taskIntent,
       referenceFrames: existingDesign.frames.map(f => f.name),
       consistencyRules: [
         'Use ONLY colors from existing palette',
         'Match existing component patterns',
         'Follow established spacing scale'
       ]
     },

     children: [/* generated based on componentType */]
   });
   ```

   - Present to user for approval with design rationale
   - Store approved design reference

5. **If "Skip design":**
   - Proceed without design reference
   - Note: Verification against design will be skipped

Store result as `$DESIGN_CONTEXT` for planner.

---

**Step 3: Calculate next quick task number**

Ensure `.planning/quick/` directory exists and find the next sequential number:

```bash
# Ensure .planning/quick/ exists
mkdir -p .planning/quick

# Find highest existing number and increment
last=$(ls -1d .planning/quick/[0-9][0-9][0-9]-* 2>/dev/null | sort -r | head -1 | xargs -I{} basename {} | grep -oE '^[0-9]+')

if [ -z "$last" ]; then
  next_num="001"
else
  next_num=$(printf "%03d" $((10#$last + 1)))
fi
```

---

**Step 4: Create quick task directory**

Create the directory for this quick task:

```bash
QUICK_DIR=".planning/quick/${next_num}-${slug}"
mkdir -p "$QUICK_DIR"
```

Report to user:
```
Creating quick task ${next_num}: ${DESCRIPTION}
Directory: ${QUICK_DIR}
```

Store `$QUICK_DIR` for use in orchestration.

---

**Step 5: Spawn planner (quick mode)**

Spawn gsd-planner with quick mode context:

```
Task(
  prompt="
<planning_context>

**Mode:** quick
**Directory:** ${QUICK_DIR}
**Description:** ${DESCRIPTION}

**Project State:**
@.planning/STATE.md

${DESIGN_CONTEXT ? `
**Design Reference (UI Task):**
- Design file: ${DESIGN_FILE}
- Frame: ${DESIGN_FRAME}
- Design tokens: Use colors, typography, spacing from existing design

Implementation must match Pencil design specifications exactly.
Verification will compare against design frame.
` : ''}

</planning_context>

<constraints>
- Create a SINGLE plan with 1-3 focused tasks
- Quick tasks should be atomic and self-contained
- No research phase, no checker phase
- Target ~30% context usage (simple, focused)
${IS_UI_TASK ? '- Include CSS values from design specs in task descriptions' : ''}
${IS_UI_TASK ? '- Add verification step to check implementation matches design' : ''}
</constraints>

<output>
Write plan to: ${QUICK_DIR}/${next_num}-PLAN.md
Return: ## PLANNING COMPLETE with plan path
</output>
",
  subagent_type="gsd-planner",
  description="Quick plan: ${DESCRIPTION}"
)
```

After planner returns:
1. Verify plan exists at `${QUICK_DIR}/${next_num}-PLAN.md`
2. Extract plan count (typically 1 for quick tasks)
3. Report: "Plan created: ${QUICK_DIR}/${next_num}-PLAN.md"

If plan not found, error: "Planner failed to create ${next_num}-PLAN.md"

---

**Step 6: Spawn executor**

Spawn gsd-executor with plan reference:

```
Task(
  prompt="
Execute quick task ${next_num}.

Plan: @${QUICK_DIR}/${next_num}-PLAN.md
Project state: @.planning/STATE.md

<constraints>
- Execute all tasks in the plan
- Commit each task atomically
- Create summary at: ${QUICK_DIR}/${next_num}-SUMMARY.md
- Do NOT update ROADMAP.md (quick tasks are separate from planned phases)
</constraints>
",
  subagent_type="gsd-executor",
  description="Execute: ${DESCRIPTION}"
)
```

After executor returns:
1. Verify summary exists at `${QUICK_DIR}/${next_num}-SUMMARY.md`
2. Extract commit hash from executor output
3. Report completion status

If summary not found, error: "Executor failed to create ${next_num}-SUMMARY.md"

Note: For quick tasks producing multiple plans (rare), spawn executors in parallel waves per execute-phase patterns.

---

**Step 6b: Quick UI verification (for UI tasks only)**

If `IS_UI_TASK=true` and `DESIGN_CONTEXT` exists, offer quick verification:

```
AskUserQuestion(
  header: "UI Verification",
  question: "Task complete. Would you like me to verify the UI matches the design?",
  options: ["Yes, verify against design", "Skip verification"]
)
```

**If "Yes, verify":**

1. **Use Playwright MCP to verify (if available):**
```typescript
// Navigate to the app
await mcp__playwright__navigate({ url: 'http://localhost:5173' });

// Capture screenshot
await mcp__playwright__screenshot({
  selector: '${COMPONENT_SELECTOR}',
  name: 'quick-${next_num}-result'
});

// Verify computed styles match design
const styles = await mcp__playwright__evaluate({
  script: `
    const el = document.querySelector('${COMPONENT_SELECTOR}');
    const s = getComputedStyle(el);
    return {
      backgroundColor: s.backgroundColor,
      color: s.color,
      fontFamily: s.fontFamily,
      padding: s.padding
    };
  `
});
```

2. **Compare against design specs:**
```typescript
// Load expected values from design
const designSpecs = await mcp__pencil__get_frame({ frameId: DESIGN_FRAME });

// Compare and report
const discrepancies = compareStyles(styles, designSpecs);
```

3. **Report results:**
```
## Quick Verification Results

**Component:** ${COMPONENT_SELECTOR}
**Design frame:** ${DESIGN_FRAME}

| Property | Design | Implemented | Status |
|----------|--------|-------------|--------|
| background | #000000 | rgb(0,0,0) | ✓ |
| color | #00D084 | rgb(0,208,132) | ✓ |
| padding | 12px 24px | 12px 24px | ✓ |

**Result:** [All specs match / X discrepancies found]
```

4. **If discrepancies found:**
```
AskUserQuestion(
  header: "Discrepancies Found",
  question: "Found ${count} discrepancies. What would you like to do?",
  options: ["Fix now", "Accept as-is", "View details"]
)
```

If "Fix now" → Re-run executor with fix instructions
If "Accept as-is" → Continue to STATE.md update
If "View details" → Show full discrepancy report

**If Playwright MCP not available:**

Document for manual verification:
```
## Manual Verification Required

Playwright MCP not available. Please verify manually:

1. Open http://localhost:5173
2. Check ${COMPONENT_SELECTOR}
3. Compare against design frame: ${DESIGN_FRAME}

Expected:
- Background: ${expected_bg}
- Color: ${expected_color}
- Padding: ${expected_padding}
```

---

**Step 7: Update STATE.md**

Update STATE.md with quick task completion record.

**7a. Check if "Quick Tasks Completed" section exists:**

Read STATE.md and check for `### Quick Tasks Completed` section.

**7b. If section doesn't exist, create it:**

Insert after `### Blockers/Concerns` section:

```markdown
### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
```

**7c. Append new row to table:**

```markdown
| ${next_num} | ${DESCRIPTION} | $(date +%Y-%m-%d) | ${commit_hash} | [${next_num}-${slug}](./quick/${next_num}-${slug}/) |
```

**7d. Update "Last activity" line:**

Find and update the line:
```
Last activity: $(date +%Y-%m-%d) - Completed quick task ${next_num}: ${DESCRIPTION}
```

Use Edit tool to make these changes atomically

---

**Step 8: Final commit and completion**

Stage and commit quick task artifacts:

```bash
# Stage quick task artifacts
git add ${QUICK_DIR}/${next_num}-PLAN.md
git add ${QUICK_DIR}/${next_num}-SUMMARY.md
git add .planning/STATE.md

# Commit with quick task format
git commit -m "$(cat <<'EOF'
docs(quick-${next_num}): ${DESCRIPTION}

Quick task completed.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

Get final commit hash:
```bash
commit_hash=$(git rev-parse --short HEAD)
```

Display completion output:
```
---

GSD > QUICK TASK COMPLETE

Quick Task ${next_num}: ${DESCRIPTION}

Summary: ${QUICK_DIR}/${next_num}-SUMMARY.md
Commit: ${commit_hash}

---

Ready for next task: /gsd:quick
```

</process>

<success_criteria>
- [ ] ROADMAP.md validation passes
- [ ] User provides task description
- [ ] Slug generated (lowercase, hyphens, max 40 chars)
- [ ] Next number calculated (001, 002, 003...)
- [ ] Directory created at `.planning/quick/NNN-slug/`
- [ ] **For UI tasks:** Design workflow offered (use existing / generate / skip)
- [ ] **For UI tasks:** Design context passed to planner if applicable
- [ ] `${next_num}-PLAN.md` created by planner
- [ ] `${next_num}-SUMMARY.md` created by executor
- [ ] **For UI tasks:** Quick verification offered (Playwright MCP if available)
- [ ] STATE.md updated with quick task row
- [ ] Artifacts committed
</success_criteria>
