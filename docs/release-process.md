# Release process

1. Run Python, browser, and native firmware tests.
2. Build every board environment.
3. Treat the ESP32-C5 target as experimental until live radio checks exist.
4. Confirm each manifest offset against generated binaries.
5. Open the staged web page and perform a rendered install-flow check.
6. Flash available boards and record fresh boot, status, button, alert-output, `dumplog`, and `clearlog` evidence.
7. Confirm production source contains no frame-injection calls or unrelated detector engines.
8. Update the changelog and hardware matrix.
9. Create release artifacts only after required CI jobs pass.

Publishing, deployment, pushing, and choosing a software license need direct maintainer approval.
