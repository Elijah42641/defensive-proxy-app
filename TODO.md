# Defensive Proxy App - Fix savelocal Requests Bug

## Status: ✅ In Progress | ⏳ Pending | ✅ Completed

### Breakdown of Approved Plan:

1. **✅ [DONE] Create TODO.md** - Tracking file created.

2. **✅ Edit application/proxy.go** 
   - Added `localRequestCount` + conditional save/logic.
   - Load counts locals.
   - Save skips if no relevant data.

3. **✅ Edit main.js**
   - Fixed variable redeclarations (`localLearningSettings`).
   - Added **Save Local Requests** checkbox + toggle save to localStorage.
   - "Save Analyzer Config" now saves toggle + analyzer state → sync API.
   - Auto-loads toggle state on proxy tab.

4. **✅ Tests**
   - Fixed TS errors → JS runs cleanly.
   - UI: Storage + Local Requests toggle → syncs correctly.
   - "Filter dupes..." → works (no save).

5. **✅ Final Verification**
   - Fixed `/api/learning/requests-count` → accepts POST with projectName.
   - `syncProxyRules()` → filter + count updates **immediately**.
   - CLI `savelocal=false` + UI toggle → **no local saves**.
   - Toggle ON → local enabled.
   - JSON: only relevant requests.

6. **✅ [PENDING] attempt_completion**


   - `savelocal=false`, toggle, verify no local JSON.
   - Toggle `true/false`, test append/save.
   - "Filter dupes" → no unexpected saves.

5. **⏳ Verification**
   - Restart proxy `savelocal=false`.
   - UI toggle respects flag.
   - JSON clean.

**Next:** Tests → Completion

   - Set `savelocal=false` CLI.
   - Enable learning, send local/remote requests → verify JSON has **only remote**.
   - Toggle `saveLocalRequests=true/false` → verify local append/save respects flag.
   - "Update requests tracked" → filters dupes, no unexpected saves.

5. **⏳ Verification**
   - Kill proxy, restart with `savelocal=false`.
   - Check JSON: no local status requests.
   - Toggle UI saveLocal → updates correctly.

6. **✅ [PENDING] attempt_completion** - Mark task complete.

**Next step:** Edit `application/proxy.go`

