# Detection Rule Set

The detection engine ships with embedded defaults and can optionally load JSON rules from `detection-engine/internal/rules/default-rules.json`.

## Included examples

- `R-PS-001`: PowerShell encoded command execution, mapped to `T1059.001`
- `R-PS-002`: PowerShell download cradle behavior, mapped to `T1105`
- `R-CHAIN-001`: `winword.exe -> cmd.exe -> powershell.exe` process chain, mapped to `T1204.002`
- `R-CRED-001`: `rundll32.exe comsvcs.dll MiniDump` credential dumping, mapped to `T1003`
- `R-LOL-001`: LOLBin-based remote retrieval using `certutil`, `mshta`, `bitsadmin`, or `regsvr32`, mapped to `T1218`
