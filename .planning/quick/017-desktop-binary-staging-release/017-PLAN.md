---
phase: quick
plan: 017
type: execute
wave: 1
depends_on: []
files_modified:
  - .github/workflows/deploy-staging.yml
autonomous: true

must_haves:
  truths:
    - 'Pushing a v*-staging* tag builds a macOS .dmg and uploads it to a GitHub pre-release'
    - 'The build-desktop job runs in parallel with existing build-api, build-tee, build-web jobs'
    - 'The deploy-vps job does NOT depend on build-desktop (desktop build failure cannot block server deploy)'
    - 'The .dmg contains the staging API URL and staging Web3Auth client ID baked in'
  artifacts:
    - path: '.github/workflows/deploy-staging.yml'
      provides: 'build-desktop job using tauri-apps/tauri-action'
      contains: 'build-desktop'
  key_links:
    - from: 'build-desktop job'
      to: 'GitHub Release'
      via: 'tauri-apps/tauri-action release upload'
      pattern: 'tauri-apps/tauri-action'
---

<objective>
Add a `build-desktop` job to the staging deploy workflow that builds the CipherBox macOS desktop app (.dmg) on a macOS runner and uploads it to a GitHub pre-release for the staging tag.

Purpose: Enable testers to download a pre-built macOS desktop binary from the GitHub Releases page for staging tags, without blocking the existing server deployment pipeline.

Output: Modified `.github/workflows/deploy-staging.yml` with a new parallel `build-desktop` job.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.github/workflows/deploy-staging.yml
@apps/desktop/src-tauri/tauri.conf.json
@apps/desktop/src-tauri/Cargo.toml
@apps/desktop/src-tauri/vendor/fuser/build.rs
@apps/desktop/package.json
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add build-desktop job to deploy-staging.yml</name>
  <files>.github/workflows/deploy-staging.yml</files>
  <action>
Add a new job `build-desktop` to `.github/workflows/deploy-staging.yml`. This job runs IN PARALLEL with the existing `build-api`, `build-tee`, and `build-web` jobs. It must NOT be added to the `deploy-vps.needs` array -- desktop build failure must not block server deploy.

**Job definition:**

```yaml
build-desktop:
  name: Build Desktop App (macOS)
  runs-on: macos-latest
  environment: staging
  permissions:
    contents: write # needed to create/update GitHub Release
  steps:
    - uses: actions/checkout@v4
      with:
        ref: ${{ inputs.staging_tag || github.ref_name }}

    - name: Install macFUSE headers
      run: brew install --cask macfuse

    - uses: pnpm/action-setup@v4
      with:
        version: 10

    - uses: actions/setup-node@v4
      with:
        node-version: '22'
        cache: 'pnpm'

    - name: Install dependencies
      run: pnpm install --frozen-lockfile

    - name: Build crypto package
      run: pnpm --filter @cipherbox/crypto build

    - uses: tauri-apps/tauri-action@v0
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        VITE_WEB3AUTH_CLIENT_ID: ${{ vars.VITE_WEB3AUTH_CLIENT_ID }}
        VITE_API_URL: ${{ vars.STAGING_API_URL }}
        VITE_ENVIRONMENT: staging
        VITE_GOOGLE_CLIENT_ID: ${{ vars.GOOGLE_CLIENT_ID }}
      with:
        projectPath: apps/desktop
        tauriScript: pnpm tauri
        tagName: ${{ inputs.staging_tag || github.ref_name }}
        releaseName: 'CipherBox Desktop ${{ inputs.staging_tag || github.ref_name }}'
        releaseBody: 'Staging build for ${{ inputs.staging_tag || github.ref_name }}. macOS only (unsigned - right-click > Open to launch).'
        releaseDraft: false
        prerelease: true
```

**Key decisions and rationale:**

1. **`macos-latest` runner**: Required for macOS .dmg build. GitHub-hosted macOS runners have Xcode + Rust pre-installed.

2. **`brew install --cask macfuse`**: The vendored fuser crate's `build.rs` uses `pkg_config::probe("fuse")` when the `libfuse` feature is enabled. macFUSE installs the required `fuse.pc` pkg-config file and headers. This is needed at compile time only (runtime uses FUSE-T on user machines).

3. **`contents: write` permission**: Required for `tauri-apps/tauri-action` to create/update the GitHub Release and upload assets.

4. **`tauriScript: pnpm tauri`**: The desktop app uses pnpm workspace, so the tauri CLI must be invoked via pnpm.

5. **Vite env vars**: Passed as `env` on the tauri-action step. Tauri's `beforeBuildCommand` runs `pnpm vite build` which reads `VITE_*` env vars. This bakes the staging API URL and Web3Auth client ID into the binary.

6. **NOT in deploy-vps.needs**: The existing `deploy-vps` job keeps `needs: [build-api, build-tee, build-web]` unchanged. The desktop build is completely independent.

7. **`tagName` matches deploy tag**: The release is created for the same tag that triggered the workflow, so the binary appears alongside the staging tag.

8. **No code signing**: This is a tech demo. The `releaseBody` tells users to right-click > Open on macOS to bypass Gatekeeper.

**Do NOT:**

- Add `build-desktop` to the `deploy-vps.needs` array
- Add any Rust toolchain setup step (tauri-action handles this)
- Set `bundleTargets` in tauri.conf.json (it already has `"targets": "all"` which produces .dmg on macOS)
- Add `includeUpdater` or auto-updater config (not needed for staging)
  </action>
  <verify>
  Validate the YAML is syntactically correct:

```bash
# Check YAML syntax (python is available on macOS)
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/deploy-staging.yml'))"
```

Verify the job structure:

```bash
# Confirm build-desktop job exists
grep -q 'build-desktop:' .github/workflows/deploy-staging.yml

# Confirm deploy-vps does NOT depend on build-desktop
grep -A1 'needs:' .github/workflows/deploy-staging.yml | grep -v 'build-desktop'

# Confirm macFUSE install step exists
grep -q 'macfuse' .github/workflows/deploy-staging.yml

# Confirm tauri-action is used
grep -q 'tauri-apps/tauri-action' .github/workflows/deploy-staging.yml

# Confirm prerelease is set
grep -q 'prerelease: true' .github/workflows/deploy-staging.yml
```

  </verify>
  <done>
The deploy-staging.yml workflow has a `build-desktop` job that:
- Runs on macos-latest with staging environment
- Installs macFUSE for FUSE compile headers
- Sets up pnpm + Node 22
- Builds the @cipherbox/crypto workspace dependency
- Runs tauri-apps/tauri-action@v0 with staging Vite env vars
- Creates/updates a GitHub pre-release with the .dmg artifact
- Runs in parallel with existing jobs (not in deploy-vps.needs)
  </done>
</task>

</tasks>

<verification>
1. YAML syntax is valid (python3 yaml.safe_load succeeds)
2. `build-desktop` job exists in the workflow
3. `deploy-vps.needs` array does NOT include `build-desktop`
4. macFUSE is installed before the Tauri build
5. `@cipherbox/crypto` is built before Tauri build
6. All four VITE_* env vars are passed to tauri-action
7. `prerelease: true` is set on the release
8. `tauriScript: pnpm tauri` is used for monorepo compatibility
</verification>

<success_criteria>
Pushing a `v*-staging*` tag triggers the deploy-staging workflow where the new `build-desktop` job runs in parallel with existing jobs, builds a macOS .dmg, and uploads it to a GitHub pre-release -- all without affecting the existing server deployment pipeline.
</success_criteria>

<output>
After completion, create `.planning/quick/017-desktop-binary-staging-release/017-SUMMARY.md`
</output>
