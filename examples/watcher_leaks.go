package main

import (
	"fmt"
	"log"
	"github.com/fsnotify/fsnotify"
)

// BAD: Watcher created for a path that's never actually used
func badUnusedWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Add watch on a path
	err = watcher.Add("/tmp/watched-file.txt")
	if err != nil {
		log.Fatal(err)
	}

	// PROBLEM: Path is watched but we never do anything with it!
	// The watcher is running but monitoring an unused object
	fmt.Println("Watcher created but path never used")
	// Missing: Any interaction with the watched path
}

// BAD: Watcher created but events never consumed
func badWatcherNoEvents() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add("/tmp/config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	// PROBLEM: Watcher created but we never read from watcher.Events channel!
	// This causes memory buildup as events queue up
	fmt.Println("Watcher running but events never consumed")
	// Missing: for event := range watcher.Events { ... }
}

// BAD: Watching a variable that goes out of scope
func badScopedWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	{
		tempPath := "/tmp/temp-file.txt"
		watcher.Add(tempPath)
		// tempPath goes out of scope here, but watcher is still active!
	}

	// PROBLEM: We're watching a path stored in a variable that no longer exists
	fmt.Println("Watching variable that went out of scope")
}

// GOOD: Proper watcher usage
func goodWatcherUsage() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	configPath := "/tmp/config.yaml"
	err = watcher.Add(configPath)
	if err != nil {
		log.Fatal(err)
	}

	// GOOD: Events are consumed
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Actually use the watched path
				fmt.Printf("Event on %s: %s\n", configPath, event.Op)
				
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("Watcher error:", err)
			}
		}
	}()

	// Do work with the watched path
	fmt.Printf("Monitoring %s for changes...\n", configPath)
}

// BAD: Multiple watchers on same unused object
func badMultipleWatchers() {
	watcher1, _ := fsnotify.NewWatcher()
	watcher2, _ := fsnotify.NewWatcher()
	defer watcher1.Close()
	defer watcher2.Close()

	unusedPath := "/tmp/never-used.txt"
	watcher1.Add(unusedPath)
	watcher2.Add(unusedPath) // Duplicate watch!

	// PROBLEM: Two watchers on the same unused path - double waste!
	fmt.Println("Multiple watchers on unused object")
}

func main() {
	badUnusedWatcher()
	badWatcherNoEvents()
	badScopedWatcher()
	badMultipleWatchers()
	goodWatcherUsage()
}
