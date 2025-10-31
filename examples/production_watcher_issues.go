package main

import (
	"github.com/fsnotify/fsnotify"
	"log"
)

// REAL PRODUCTION ISSUE #1: Watcher on deprecated config path
// The old path is still being watched even though system migrated to new path
func productionIssue1_DeprecatedPath() {
	oldConfigPath := "/etc/app/old-config.yaml" // Deprecated 6 months ago
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	
	// Still watching old path that's no longer used
	watcher.Add(oldConfigPath)
	
	// Events never consumed - old path never changes anyway
	// This watcher is completely dead weight!
}

// REAL PRODUCTION ISSUE #2: Multiple watchers on same resource
func productionIssue2_DuplicateWatchers() {
	cachePath := "/var/cache/app/data"
	
	watcher1, _ := fsnotify.NewWatcher()
	defer watcher1.Close()
	watcher1.Add(cachePath)
	
	watcher2, _ := fsnotify.NewWatcher()
	defer watcher2.Close()
	watcher2.Add(cachePath) // Duplicate! Wasteful
	
	// Neither consumes events
	// Double memory leak!
}

// REAL PRODUCTION ISSUE #3: Temp file watcher that outlives the temp file
func productionIssue3_TempFileWatcher() {
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()
	
	// Watch temp file
	tempFile := "/tmp/upload-12345.tmp"
	watcher.Add(tempFile)
	
	// Temp file gets deleted but watcher keeps running
	// (In real code, os.Remove(tempFile) happens elsewhere)
	// Watcher monitoring non-existent file = waste
	
	// No event consumption = memory leak
}

// REAL PRODUCTION ISSUE #4: Watcher in init() that never stops
var globalWatcher *fsnotify.Watcher

func init() {
	globalWatcher, _ = fsnotify.NewWatcher()
	
	// Watch system path
	globalWatcher.Add("/etc/system/config")
	
	// No event consumption anywhere!
	// No Close() call ever!
	// Leaks for entire application lifetime
}

// THE FIX: Proper watcher lifecycle management
func goodProduction_ProperWatcherManagement() {
	configPath := "/etc/app/current-config.yaml"
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	
	if err := watcher.Add(configPath); err != nil {
		log.Printf("Failed to watch %s: %v", configPath, err)
		return
	}
	
	// Properly consume events
	for {
		select {
		case event := <-watcher.Events:
			if event.Name == configPath {
				log.Printf("Config changed at %s, reloading...", configPath)
				// Reload configuration...
			}
		case err := <-watcher.Errors:
			log.Printf("Watcher error: %v", err)
		}
	}
}

func main() {
	// All the production issues demonstrated above
	// greninjaSec should catch them all!
}
