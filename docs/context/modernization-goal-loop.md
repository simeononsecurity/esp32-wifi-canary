# WiFi Canary modernization goal loop

Copy the prompt below into the implementing agent's task. This document records the task scope and the required review sequence. The related hardware and build facts are in `docs/context/target-devices-and-pins.md` and `docs/context/related-repo-platformio.md`.

## Prompt

You are modernizing ESP32 WiFi Canary. Work in the existing `codex/wifi-canary-productization` branch and compare it with `esp32-wifi-canary/main` before changing source. Read `esp32-wifi-canary/AGENTS.md`, this branch's `PROGRESS.md`, and the context documents. Preserve existing work when sound. Bring main's agent instructions into the branch.

Goal: deliver a usable local browser flasher and console, clear device support, and a maintainable firmware release while retaining the original WiFi Canary behavior.

Product boundary: offline passive 2.4 GHz WiFi awareness. Preserve the nine detection engines, score thresholds and decay, startup/normal/caution/alert LED meanings, Atom Lite button actions, DevKit binary LED, and readable `[canary]` serial output. Standard configuration must match the original behavior. Do not add frame transmission, network association, BLE, GPS, maps, remote telemetry, or unrelated detection targets. Keep test fixtures synthetic and free of captured network identifiers.

Keep Atom Echo and Atom Voice as separate products in the device catalog, flasher selection, documentation, and validation matrix. A shared firmware artifact is acceptable after both devices pass the relevant hardware checks. Do not collapse their product identities into one alias.

Use delegated agents for independent work when practical. Assign bounded ownership and separate files or read-only research. Prefer the lowest-cost capable model for source inventory, pin tables, and documentation checks. Use stronger reviewers for radio behavior, storage compatibility, and security-sensitive changes. Integrate and verify every delegated result yourself.

Run a repeated implementation cycle. First, inventory the branch and select the highest-impact in-scope gap. Next, make one coherent change and run focused tests. Record the change and test evidence in `PROGRESS.md`, then commit with a narrow message. After creating each commit, send its SHA and parent SHA through the reviewer series below, in order. Wait for each review. Resolve findings with a new commit, then review the new commit through the same full series. Do not start another feature until the current commit has completed the series. Keep post-commit reviewer results in the task report, keyed by SHA. Do not create a commit solely to record a review result.

Reviewer 1, behavior and scope. Independently inspect the commit diff and original contract. Check every original detector, scoring, serial line, LED state, button action, and passive receive-only radio behavior. Report concrete regressions with file and line evidence.

Reviewer 2, hardware and build. Check the board/profile mapping, pins, library declarations, partition offsets, manifest chip family, binary paths, and hardware claims against source documents. Mark source-only findings separately from physical checks.

Reviewer 3, browser and privacy. Check the install/config flow, Web Serial parsing, bounded line and event memory, safe DOM rendering, local-only data handling, recovery behavior, and release artifact integrity. Verify configuration is included in the selected flash operation. Check whether the installer dependency is pinned or bundled and whether the page's network requirement is accurate. Check for sensitive fixture data.

Reviewer 4, verification and support. Re-run or inspect applicable tests and board builds. Check release assembly, README, hardware matrix, quick start, troubleshooting, and status labels. Confirm each claim has evidence. Every reviewer examines every commit. For an irrelevant lens, record "no finding" with the reason instead of skipping the review.

The implementing agent owns fixes. Reviewers do not edit the branch. A reviewer finding is complete only after a fix commit passes all four reviewers. Preserve each reviewed SHA and result in the task report or an external review log. Do not treat a prior review of a superseded SHA as approval for a new SHA.

Complete the browser path: choose the exact board, select optional bounded settings, install matching bootloader/partition/application binaries plus a validated config part, confirm boot over USB, and view local events. Default install uses original settings. Check manifest offsets, versions, checksums, partition boundaries, and staged-file paths. Keep C5 experimental and avoid 5 GHz claims without device evidence.

Complete the console with live state, score, detector explanation, baseline progress, health, bounded history, and local JSON/CSV export. Keep readable serial output. Check keyboard use, narrow screens, and text-safe rendering. Update support documents and release packaging as behavior changes.

Run native, browser, parser, and release checks plus all claimed board builds. Distinguish compile results from physical checks. Flash hardware only when a device is attached and the owner has authorized the flash. End with a concise report of changes, exact test results, reviewer results for each commit, and remaining dependencies. Commit locally. Stop before pushing, publishing, deploying, selecting a license, or spending money until the owner approves the final action.
