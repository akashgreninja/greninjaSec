package main

import (
	"log"
	"github.com/fsnotify/fsnotify"
)

// BAD: Watching a path that's defined but NEVER used anywhere
func badWatcherOnUnusedPath() {
	unusedPath := "/tmp/stale/config.yaml"
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	
	// Watching a path variable that is NEVER used after this
	watcher.Add(unusedPath)
	
	// Events are consumed (good), but the path itself is stale/unused (bad)
	for event := range watcher.Events {
		log.Println("Event:", event)
	}
}

// BAD: Watching a literal path string that doesn't exist and is never referenced
func badWatcherOnStalePath() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	
	// Watching a literal path that's never used in the codebase
	watcher.Add("/some/random/stale/path/nowhere.txt")
	
	// Events consumed but path is completely stale
	for event := range watcher.Events {
		log.Println("Event:", event)
	}
}

// WORSE: No event consumption AND watching unused path
func terribleWatcher() {
	stalePath := "/tmp/old/deprecated/file.json"
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	
	// Double whammy: unused path + no event consumption
	watcher.Add(stalePath)
	
	// Path 'stalePath' is never used again
	// Events are never consumed
	// This is a CRITICAL leak!
}

// GOOD: Path is actively used in the code
func goodWatcherUsesPath() {
	configPath := "/etc/app/config.yaml"
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	
	watcher.Add(configPath)
	
	// Path is actively used
	log.Println("Watching:", configPath)
	
	// Events are consumed
	for event := range watcher.Events {
		if event.Name == configPath { // Path used here!
			log.Println("Config changed:", configPath)
			// Reload from configPath...
		}
	}
}

// BAD: Watching variable that goes out of scope
func badWatcherScopedVariable() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	
	{
		tempPath := "/tmp/scoped.txt"
		watcher.Add(tempPath)
		// tempPath goes out of scope here
	}
	
	// Events consumed but watched variable is out of scope/stale
	for event := range watcher.Events {
		log.Println("Event:", event)
	}
}
