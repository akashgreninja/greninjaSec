package main

import (
	"log"
	"github.com/fsnotify/fsnotify"
)

// BAD: Watcher created but events never consumed
func badWatcher1() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add("/tmp/file1.txt")
	if err != nil {
		log.Fatal(err)
	}
	
	// PROBLEM: Events never consumed!
}

// BAD: Another watcher, events not consumed
func badWatcher2() {
	w, e := fsnotify.NewWatcher()
	if e != nil {
		log.Fatal(e)
	}
	defer w.Close()

	w.Add("/tmp/file2.txt")
	
	// PROBLEM: Events never consumed!
}

func testMain() {
	badWatcher1()
	badWatcher2()
}
