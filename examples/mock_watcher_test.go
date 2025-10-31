package main

import "fmt"

type MockWatcher struct {
	Events chan string
}

func NewMockWatcher() (*MockWatcher, error) {
	return &MockWatcher{Events: make(chan string, 10)}, nil
}

func (w *MockWatcher) Close() error {
	close(w.Events)
	return nil
}

func (w *MockWatcher) Add(path string) error {
	fmt.Printf("Watching: %s\n", path)
	return nil
}

// BAD: Watcher created but events never consumed
func badWatcherSimple() {
	watcher, err := NewMockWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()

	watcher.Add("/tmp/test.txt")
	
	// PROBLEM: watcher.Events channel never read!
	fmt.Println("Watcher created but events ignored")
}

// GOOD: Events are consumed
func goodWatcherSimple() {
	watcher, _ := NewMockWatcher()
	defer watcher.Close()

	watcher.Add("/tmp/test.txt")
	
	// GOOD: Read from events channel
	go func() {
		for e := range watcher.Events {
			fmt.Println("Event:", e)
		}
	}()
}

func testWatchers() {
	badWatcherSimple()
	goodWatcherSimple()
}
