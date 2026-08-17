# Fuzz regression corpus

Minimized reproducer inputs for crashes/hangs/sanitizer reports the fuzz
targets actually found (plan 8.6). Empty until the first one lands — this
file exists only so the directory survives git (empty directories aren't
tracked).

Naming convention: `<target>-<short-description-or-hash>`, e.g.
`json_parse-deep-nesting-oom`. Each file here is fed back into every future
`make fuzz`/`make fuzz-smoke` run automatically (it's a read-only seed
source), so a bug found once can never silently regress.
