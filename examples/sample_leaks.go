package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"
)

// LEAK 1: File opened but never closed
func badFileHandling() {
	file, err := os.Open("test.txt") // Missing defer file.Close()
	if err != nil {
		return
	}
	fmt.Fprintf(file, "test")
}

// LEAK 2: HTTP response body not closed
func badHTTPHandling() {
	resp, err := http.Get("https://example.com") // Missing defer resp.Body.Close()
	if err != nil {
		return
	}
	_ = resp
}

// LEAK 3: Goroutine without cancellation
func badGoroutine() {
	go func() {
		for { // Infinite loop, no way to cancel
			fmt.Println("running forever")
			// Missing time.Sleep or exit condition
		}
	}()
}

// LEAK 4: Unbounded slice growth
func badSliceGrowth() {
	var data []string
	for {
		data = append(data, "more data") // No size limit!
	}
}

// LEAK 5: Regex compiled in loop
func badRegexUsage() {
	for i := 0; i < 1000; i++ {
		re := regexp.MustCompile(`\d+`) // Should be outside loop!
		_ = re.MatchString(fmt.Sprintf("%d", i))
	}
}

// LEAK 6: Timer never stopped
func badTimerUsage() {
	ticker := time.NewTicker(1 * time.Second) // Missing defer ticker.Stop()
	for range ticker.C {
		fmt.Println("tick")
	}
}

// LEAK 7: Context cancel function never called
func badContextUsage() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Missing defer cancel()
	_ = ctx
	_ = cancel
	// Do work but never call cancel() - leaks goroutine
}

// GOOD: Properly handled resources
func goodFileHandling() {
	file, err := os.Open("test.txt")
	if err != nil {
		return
	}
	defer file.Close() // Correct!
	fmt.Fprintf(file, "test")
}

func goodHTTPHandling() {
	resp, err := http.Get("https://example.com")
	if err != nil {
		return
	}
	defer resp.Body.Close() // Correct!
	fmt.Println(resp.Status)
}

func goodTimerUsage() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop() // Correct!
	for range ticker.C {
		fmt.Println("tick")
		break
	}
}

func goodContextUsage() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // Correct!
	_ = ctx
}
