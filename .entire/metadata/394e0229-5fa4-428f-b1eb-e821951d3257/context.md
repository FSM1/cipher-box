# Session Context

**Session ID:** 394e0229-5fa4-428f-b1eb-e821951d3257

**Commit Message:** <objective>
Add a new integer phase to the end of the current milestone

## Prompt

yeah thats a great plan. I think it makes sense to insert 12.6 after 12.5, and then just 12.1 needs to be moved to after 12.6.

---

<objective>
Add a new integer phase to the end of the current milestone in the roadmap.

This command appends sequential phases to the current milestone's phase list, automatically calculating the next phase number based on existing phases.

Purpose: Add planned work discovered during execution that belongs at the end of current milestone.
</objective>

<execution_context>
@.planning/ROADMAP.md
@.planning/STATE.md
</execution_context>

<process>

<step name="parse_arguments">
Parse the command arguments:
- All arguments become the phase description
- Example: `/gsd:add-phase Add authentication` → description = "Add authentication"
- Example: `/gsd:add-phase Fix critical performance issues` → description = "Fix critical performance issues"

If no arguments provided:

```
ERROR: Phase description required
Usage: /gsd:add-phase <description>
Example: /gsd:add-phase Add authentication system
```

Exit.
</step>

<step name="load_roadmap">
Load the roadmap file:

```bash
if [ -f .planning/ROADMAP.md ]; then
  ROADMAP=".planning/ROADMAP.md"
else
  echo "ERROR: No roadmap found (.planning/ROADMAP.md)"
  exit 1
fi
```

Read roadmap content for parsing.
</step>

<step name="find_current_milestone">
Parse the roadmap to find the current milestone section:

1. Locate the "## Current Milestone:" heading
2. Extract milestone name and version
3. Identify all phases under this milestone (before next "---" separator or next milestone heading)
4. Parse existing phase numbers (including decimals if present)

Example structure:

```
## Current Milestone: v1.0 Foundation

### Phase 4: Focused Command System
### Phase 5: Path Routing & Validation
### Phase 6: Documentation & Distribution
```

</step>

<step name="calculate_next_phase">
Find the highest integer phase number in the current milestone:

1. Extract all phase numbers from phase headings (### Phase N:)
2. Filter to integer phases only (ignore decimals like 4.1, 4.2)
3. Find the maximum integer value
4. Add 1 to get the next phase number

Example: If phases are 4, 5, 5.1, 6 → next is 7

Format as two-digit: `printf "%02d" $next_phase`
</step>

<step name="generate_slug">
Convert the phase description to a kebab-case slug:

```bash
# Example transformation:
# "Add authentication" → "add-authentication"
# "Fix critical performance issues" → "fix-critical-performance-issues"

slug=$(echo "$description" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//')
```

Phase directory name: `{two-digit-phase}-{slug}`
Example: `07-add-authentication`
</step>

<step name="create_phase_directory">
Create the phase directory structure:

```bash
phase_dir=".planning/phases/${phase_num}-${slug}"
mkdir -p "$phase_dir"
```

Confirm: "Created directory: $phase_dir"
</step>

<step name="update_roadmap">
Add the new phase entry to the roadmap:

1. Find the insertion point (after last phase in current milestone, before "---" separator)
2. Insert new phase heading:

   ```
   ### Phase {N}: {Description}

   **Goal:** [To be planned]
   **Depends on:** Phase {N-1}
   **Plans:** 0 plans

   Plans:
   - [ ] TBD (run /gsd:plan-phase {N} to break down)

   **Details:**
   [To be added during planning]
   ```

3. Write updated roadmap back to file

Preserve all other content exactly (formatting, spacing, other phases).
</step>

<step name="update_project_state">
Update STATE.md to reflect the new phase:

1. Read `.planning/STATE.md`
2. Under "## Current Position" → "**Next Phase:**" add reference to new phase
3. Under "## Accumulated Context" → "### Roadmap Evolution" add entry:
   ```
   - Phase {N} added: {description}
   ```

If "Roadmap Evolution" section doesn't exist, create it.
</step>

<step name="completion">
Present completion summary:

```
Phase {N} added to current milestone:
- Description: {description}
- Directory: .planning/phases/{phase-num}-{slug}/
- Status: Not planned yet

Roadmap updated: {roadmap-path}
Project state updated: .planning/STATE.md

---

## ▶ Next Up

**Phase {N}: {description}**

`/gsd:plan-phase {N}`

<sub>`/clear` first → fresh context window</sub>

---

**Also available:**
- `/gsd:add-phase <description>` — add another phase
- Review roadmap

---
```
</step>

</process>

<anti_patterns>

- Don't modify phases outside current milestone
- Don't renumber existing phases
- Don't use decimal numbering (that's /gsd:insert-phase)
- Don't create plans yet (that's /gsd:plan-phase)
- Don't commit changes (user decides when to commit)
  </anti_patterns>

<success_criteria>
Phase addition is complete when:

- [ ] Phase directory created: `.planning/phases/{NN}-{slug}/`
- [ ] Roadmap updated with new phase entry
- [ ] STATE.md updated with roadmap evolution note
- [ ] New phase appears at end of current milestone
- [ ] Next phase number calculated correctly (ignoring decimals)
- [ ] User informed of next steps
      </success_criteria>


ARGUMENTS: Phase 12.6: Per-File IPNS Metadata Split — Split file metadata into separate per-file IPNS-addressed objects. Folder metadata retains only name + pointer (fileMetaIpnsName); file metadata (CID, fileKeyEncrypted, fileIv, size, mimeType) lives in its own IPNS record. HKDF derivation for file IPNS keypairs (same pattern as folder/vault IPNS). Enables per-file sharing, decouples content updates from folder publishes, and prepares clean foundation for AES-CTR streaming (Phase 12.1). Clean break — no dual-schema or migration code needed since vaults will be reset. Depends on Phase 12.5. Must complete before Phase 12.1.

## Summary

Phase 12.6 added to the roadmap. Here's the summary:

**Phase 12.6: Per-File IPNS Metadata Split** (INSERTED)
- Directory: `.planning/phases/12.6-per-file-ipns-metadata-split/`
- Status: Not planned yet
- Execution order: 12 → 12.5 → **12.6** → 12.1 → 13 → ...

Roadmap and STATE.md updated. The todo for this can also be moved to done since it's now a full phase.

---

**Next Up**

**Phase 12.6: Per-File IPNS Metadata Split**

`/gsd:research-phase 12.6` → then `/gsd:plan-phase 12.6`

`/clear` first for a fresh context window

---

Want me to commit these roadmap changes first?

## Key Actions

- - **Skill**: 
- - **Bash**: Create phase directory
- - **Read**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
- - **Edit**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
- - **Read**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
- - **Edit**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
- - **Read**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
- - **Edit**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
- - **Read**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
- - **Edit**: /Users/michael/Code/cipher-box/.planning/ROADMAP.md
