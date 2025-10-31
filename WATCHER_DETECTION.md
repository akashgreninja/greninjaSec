# Stale Object Detection Feature

## What It Does

GreninjaSec now detects **two critical types of watcher leaks**:

### 1. **Watchers with Unconsumed Events** (CRITICAL)
When a watcher is created but its event channel is never read, events queue up indefinitely causing **memory leaks**.

```go
// ❌ BAD - Memory leak
watcher, _ := fsnotify.NewWatcher()
defer watcher.Close()
watcher.Add("/etc/config.yaml")
// Events channel never consumed! Memory grows unbounded.
```

### 2. **Watchers Monitoring Unused/Stale Paths** (HIGH)
When a watcher monitors a path that's never actually used in the code - wasted resources.

```go
// ❌ BAD - Wasted resources
deprecatedPath := "/old/config.yaml"  // This variable is never used again
watcher, _ := fsnotify.NewWatcher()
watcher.Add(deprecatedPath)  // Watching stale path!
```

## Real Production Issues Detected

### Issue #1: Deprecated Config Paths
```go
oldConfigPath := "/etc/app/old-config.yaml" // Migrated 6 months ago
watcher.Add(oldConfigPath)  // Still watching dead path!
```
**Detection**: `LEAK_WATCHER_MONITORING_UNUSED_PATH` (HIGH)

### Issue #2: Duplicate Watchers
```go
watcher1.Add(cachePath)
watcher2.Add(cachePath)  // Duplicate! Double the memory leak!
```
**Detection**: Both get `LEAK_WATCHER_EVENTS_NOT_CONSUMED` (CRITICAL)

### Issue #3: Global Watchers Never Closed
```go
var globalWatcher *fsnotify.Watcher

func init() {
    globalWatcher, _ = fsnotify.NewWatcher()
    globalWatcher.Add("/etc/config")
    // No Close() ever! No event consumption! Leaks forever!
}
```
**Detection**: 
- `LEAK_UNCLOSED_FILE_WATCHER` (CRITICAL)
- `LEAK_WATCHER_EVENTS_NOT_CONSUMED` (CRITICAL)
- `LEAK_WATCHER_MONITORING_UNUSED_PATH` (HIGH)

### Issue #4: Temp File Watchers
```go
tempFile := "/tmp/upload-12345.tmp"
watcher.Add(tempFile)
os.Remove(tempFile)  // File deleted elsewhere
// Watcher still monitoring non-existent file!
```
**Detection**: `LEAK_WATCHER_EVENTS_NOT_CONSUMED` (CRITICAL)

## How It Works

### Three-Pass AST Analysis:

1. **First Pass** - Find all watcher creations:
   - `fsnotify.NewWatcher()`
   - `NewWatcher()`, `Watch()`, `AddWatch()`
   - `Observe()`, `Subscribe()`, `AddEventListener()`
   - Track: variable name, line number

2. **Second Pass** - Extract watched paths:
   - Find `.Add(path)` or `.Watch(path)` calls
   - Extract path from arguments (string literal or variable)
   - Track: watched path, Add() line number

3. **Third Pass** - Check consumption and usage:
   - **Event consumption**: Look for `range watcher.Events` or `<-watcher.Events`
   - **Path usage**: Check if watched path variable is referenced after Add()
   - Report violations with specific line numbers and recommendations

## Test Results

### examples/production_watcher_issues.go
```
✅ Found 7 potential leaks
🔴 CRITICAL (5)
  - Line 62: globalWatcher never closed
  - Lines 30, 34: watcher1/watcher2 events not consumed
  - Line 62: globalWatcher events not consumed
  - Line 88: Infinite loop (bonus detection)

🟠 HIGH (2)
  - Line 36: watcher2 monitoring unused cachePath
  - Line 65: globalWatcher monitoring unused "/etc/system/config"
```

### examples/watcher_leaks.go
```
✅ Found 4 potential leaks
🔴 CRITICAL (2)
  - Lines 106-107: Multiple watchers with no event consumption

🟠 HIGH (2)
  - Line 81: Goroutine without cancellation
  - Line 113: Duplicate watcher on unused path
```

## The Fix Pattern

### ✅ GOOD - Proper Watcher Management
```go
configPath := "/etc/app/config.yaml"

watcher, err := fsnotify.NewWatcher()
if err != nil {
    log.Fatal(err)
}
defer watcher.Close()  // ✅ Properly closed

if err := watcher.Add(configPath); err != nil {
    log.Printf("Failed to watch %s: %v", configPath, err)
    return
}

// ✅ Events properly consumed
for {
    select {
    case event := <-watcher.Events:
        if event.Name == configPath {  // ✅ Path actively used!
            log.Printf("Config changed at %s", configPath)
            // Reload configuration...
        }
    case err := <-watcher.Errors:
        log.Printf("Watcher error: %v", err)
    }
}
```

## Usage

```bash
# Scan for watcher leaks
./greninjaSec --leaks --path examples/production_watcher_issues.go

# Verbose output shows all findings
./greninjaSec --leaks --path yourfile.go --verbose

# Scan entire project
./greninjaSec --leaks --path ./...
```

## Impact

This feature helps prevent:
- **Memory leaks** from unbounded event channel growth
- **Resource waste** from monitoring deprecated/unused paths
- **File descriptor leaks** from unclosed watchers
- **Production incidents** from accumulating watcher events

## Technical Details

- **AST-based detection**: Uses Go's `go/ast` and `go/parser` packages
- **Context-aware**: Tracks variable scope and usage across function bodies
- **Multi-pass analysis**: Separates creation, configuration, and consumption detection
- **Pattern matching**: Supports multiple watcher libraries (fsnotify, custom watchers, event listeners)

## What's Next

Potential enhancements:
- [ ] Detect scoped variables that go out of scope while still being watched
- [ ] Cross-function analysis for watchers passed as parameters
- [ ] Suggest automatic refactoring to proper watcher patterns
- [ ] Integration with AI remediation for automatic fixes

---

**Committed**: feat: Add stale object detection for watchers
**Status**: ✅ Pushed to GitHub
**Test Files**: 5 comprehensive examples with 20+ test cases
