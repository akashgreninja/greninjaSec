package scanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// LeakFinding represents a memory/resource leak
type LeakFinding struct {
	Type        string // "goroutine", "resource", "memory", "cpu"
	Category    string // Specific issue (e.g., "unclosed_file", "goroutine_without_context")
	File        string
	Line        int
	Severity    string
	Description string
	CodeSnippet string
	Fix         string // Suggested fix
}

// ScanForLeaks scans Go files for memory/resource leaks and CPU issues
func ScanForLeaks(path string) ([]LeakFinding, error) {
	var findings []LeakFinding

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories and non-Go files
		if info.IsDir() || !strings.HasSuffix(filePath, ".go") {
			return nil
		}

		// Skip vendor, test files for now
		if strings.Contains(filePath, "/vendor/") || strings.HasSuffix(filePath, "_test.go") {
			return nil
		}

		// Scan file
		leaks, err := scanGoFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Failed to scan %s: %v\n", filePath, err)
			return nil
		}

		findings = append(findings, leaks...)
		return nil
	})

	return findings, err
}

// scanGoFile scans a single Go file for leaks
func scanGoFile(filePath string) ([]LeakFinding, error) {
	var findings []LeakFinding

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	contentStr := string(content)

	// Parse Go file into AST
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, content, parser.ParseComments)
	if err != nil {
		// If parsing fails, fall back to regex-based detection
		return scanWithRegex(filePath, contentStr)
	}

	// AST-based detection (more accurate)
	findings = append(findings, detectGoroutineLeaks(fset, node, filePath, contentStr)...)
	findings = append(findings, detectResourceLeaks(fset, node, filePath, contentStr)...)
	findings = append(findings, detectMemoryLeaks(fset, node, filePath, contentStr)...)
	findings = append(findings, detectCPUIssues(fset, node, filePath, contentStr)...)

	return findings, nil
}// detectGoroutineLeaks finds goroutines that may never exit
func detectGoroutineLeaks(fset *token.FileSet, node *ast.File, filePath, content string) []LeakFinding {
	var findings []LeakFinding

	ast.Inspect(node, func(n ast.Node) bool {
		// Look for go statements
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}

		pos := fset.Position(goStmt.Pos())
		snippet := extractLine(content, pos.Line)

		// Check if goroutine has context or cancellation
		hasContext := strings.Contains(snippet, "context.") || strings.Contains(snippet, "ctx")
		hasSelect := checkFunctionHasSelect(goStmt.Call)
		hasReturn := checkFunctionHasReturn(goStmt.Call)

		if !hasContext && !hasSelect && !hasReturn {
			findings = append(findings, LeakFinding{
				Type:        "goroutine",
				Category:    "goroutine_without_cancellation",
				File:        filePath,
				Line:        pos.Line,
				Severity:    "HIGH",
				Description: "Goroutine may leak - no context, timeout, or exit condition detected",
				CodeSnippet: snippet,
				Fix:         "Add context.WithCancel() or context.WithTimeout() to allow goroutine cancellation",
			})
		}

		return true
	})

	return findings
}

// detectResourceLeaks finds resources that aren't properly closed
func detectResourceLeaks(fset *token.FileSet, node *ast.File, filePath, content string) []LeakFinding {
	var findings []LeakFinding

	// Track opened resources and their defer statements
	openedResources := make(map[int]string) // line -> resource type
	deferredLines := make(map[int]bool)

	ast.Inspect(node, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			// Check for resource-opening calls
			for _, expr := range stmt.Rhs {
				if call, ok := expr.(*ast.CallExpr); ok {
					pos := fset.Position(call.Pos())
					
					if isResourceOpenCall(call) {
						resourceType := getResourceType(call)
						openedResources[pos.Line] = resourceType
					}
				}
			}

		case *ast.DeferStmt:
			// Mark that this line has a defer
			pos := fset.Position(stmt.Pos())
			deferredLines[pos.Line] = true

			// Check if defer is for resource cleanup
			call := stmt.Call
			
			// Check for defer method calls (e.g., defer file.Close(), defer ticker.Stop())
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				cleanupMethods := []string{"Close", "Stop", "Cancel", "Shutdown", "Unsubscribe", "Remove"}
				isCleanup := false
				for _, method := range cleanupMethods {
					if sel.Sel.Name == method {
						isCleanup = true
						break
					}
				}
				
				if isCleanup {
					// Find the corresponding resource open
					for line := range openedResources {
						if line < pos.Line && pos.Line-line < 10 { // Increased window to 10 lines
							delete(openedResources, line)
						}
					}
				}
			}
			
			// Check for defer function variable calls (e.g., defer cancel())
			if ident, ok := call.Fun.(*ast.Ident); ok {
				// Common cleanup function names
				cleanupFuncs := []string{"cancel", "cleanup", "done", "finish"}
				isCleanup := false
				for _, fn := range cleanupFuncs {
					if ident.Name == fn {
						isCleanup = true
						break
					}
				}
				
				if isCleanup {
					// Find the corresponding resource open within 10 lines
					for line := range openedResources {
						if line < pos.Line && pos.Line-line < 10 {
							delete(openedResources, line)
						}
					}
				}
			}
		}
		return true
	})

	// Report resources without defer Close()
	for line, resourceType := range openedResources {
		snippet := extractLine(content, line)
		varName := getVariableName(snippet)
		
		// Determine correct cleanup method and fix
		var cleanupMethod, fix string
		switch resourceType {
		case "file_watcher":
			cleanupMethod = "Close"
			fix = fmt.Sprintf("Add: defer %s.Close() to prevent file descriptor leak", varName)
		case "timer", "timer_callback":
			cleanupMethod = "Stop"
			fix = fmt.Sprintf("Add: defer %s.Stop() to prevent timer leak", varName)
		case "context":
			cleanupMethod = "cancel function"
			fix = "Store cancel function and call: defer cancel()"
		case "event_listener":
			cleanupMethod = "Remove"
			fix = fmt.Sprintf("Add: defer obj.RemoveEventHandler(%s) to prevent listener leak", varName)
		case "message_queue_subscription":
			cleanupMethod = "Unsubscribe/Close"
			fix = fmt.Sprintf("Add: defer %s.Unsubscribe() or defer %s.Close()", varName, varName)
		case "network_connection":
			cleanupMethod = "Close"
			fix = fmt.Sprintf("Add: defer %s.Close() to prevent connection leak", varName)
		case "db_connection":
			cleanupMethod = "Close"
			fix = fmt.Sprintf("Add: defer %s.Close() or defer rows.Close() for query results", varName)
		case "http_response":
			cleanupMethod = "Body.Close"
			fix = fmt.Sprintf("Add: defer %s.Body.Close() - CRITICAL for connection pool!", varName)
		default:
			cleanupMethod = "Close"
			fix = fmt.Sprintf("Add: defer %s.Close()", varName)
		}
		
		findings = append(findings, LeakFinding{
			Type:        "resource",
			Category:    "unclosed_" + resourceType,
			File:        filePath,
			Line:        line,
			Severity:    "CRITICAL",
			Description: fmt.Sprintf("%s opened but never closed - will leak %s", resourceType, cleanupMethod),
			CodeSnippet: snippet,
			Fix:         fix,
		})
	}

	return findings
}

// detectMemoryLeaks finds unbounded memory growth
func detectMemoryLeaks(fset *token.FileSet, node *ast.File, filePath, content string) []LeakFinding {
	var findings []LeakFinding

	ast.Inspect(node, func(n ast.Node) bool {
		// Look for loops with append
		forStmt, ok := n.(*ast.ForStmt)
		if !ok {
			return true
		}

		pos := fset.Position(forStmt.Pos())

		// Check if loop contains unbounded append
		hasAppend := false
		hasBoundCheck := false

		ast.Inspect(forStmt.Body, func(inner ast.Node) bool {
			if call, ok := inner.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "append" {
					hasAppend = true
				}
			}

			// Check for length/capacity checks
			if binary, ok := inner.(*ast.BinaryExpr); ok {
				if ident, ok := binary.X.(*ast.CallExpr); ok {
					if fun, ok := ident.Fun.(*ast.Ident); ok {
						if fun.Name == "len" || fun.Name == "cap" {
							hasBoundCheck = true
						}
					}
				}
			}

			return true
		})

		if hasAppend && !hasBoundCheck {
			snippet := extractLine(content, pos.Line)
			findings = append(findings, LeakFinding{
				Type:        "memory",
				Category:    "unbounded_slice_growth",
				File:        filePath,
				Line:        pos.Line,
				Severity:    "HIGH",
				Description: "Slice grows unbounded in loop - potential memory leak",
				CodeSnippet: snippet,
				Fix:         "Add capacity limit check: if len(slice) > MAX_SIZE { break }",
			})
		}

		return true
	})

	return findings
}

// detectCPUIssues finds CPU-intensive patterns
func detectCPUIssues(fset *token.FileSet, node *ast.File, filePath, content string) []LeakFinding {
	var findings []LeakFinding

	ast.Inspect(node, func(n ast.Node) bool {
		// Infinite loops
		if forStmt, ok := n.(*ast.ForStmt); ok {
			if forStmt.Cond == nil {
				// for { ... } - infinite loop
				pos := fset.Position(forStmt.Pos())
				hasBreak := checkForBreakOrReturn(forStmt.Body)
				hasSleep := checkForSleep(forStmt.Body)

				if !hasBreak && !hasSleep {
					snippet := extractLine(content, pos.Line)
					findings = append(findings, LeakFinding{
						Type:        "cpu",
						Category:    "infinite_loop_no_sleep",
						File:        filePath,
						Line:        pos.Line,
						Severity:    "CRITICAL",
						Description: "Infinite loop without break/return/sleep - will consume 100% CPU",
						CodeSnippet: snippet,
						Fix:         "Add: time.Sleep(100*time.Millisecond) or proper exit condition",
					})
				}
			}
		}

		// regexp.Compile in loop
		if forStmt, ok := n.(*ast.ForStmt); ok {
			hasRegexpCompile := false
			ast.Inspect(forStmt.Body, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "regexp" {
							if sel.Sel.Name == "Compile" || sel.Sel.Name == "MustCompile" {
								hasRegexpCompile = true
							}
						}
					}
				}
				return true
			})

			if hasRegexpCompile {
				pos := fset.Position(forStmt.Pos())
				snippet := extractLine(content, pos.Line)
				findings = append(findings, LeakFinding{
					Type:        "cpu",
					Category:    "regex_compile_in_loop",
					File:        filePath,
					Line:        pos.Line,
					Severity:    "HIGH",
					Description: "Regular expression compiled in loop - very expensive operation",
					CodeSnippet: snippet,
					Fix:         "Move regexp.MustCompile() outside loop and reuse compiled pattern",
				})
			}
		}

		return true
	})

	return findings
}

// Helper functions

func isResourceOpenCall(call *ast.CallExpr) bool {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		// File/network operations
		resourceFuncs := []string{
			"Open", "OpenFile", "Create",           // os package
			"Get", "Post", "Do",                     // http package
			"Query", "Prepare", "Begin",             // sql package
			"Dial", "DialContext", "Listen",         // net package
			"NewWatcher",                             // fsnotify package
			"NewTicker", "NewTimer", "AfterFunc",    // time package
			"Subscribe", "Consume",                   // message queues
			"Watch", "AddEventHandler",              // kubernetes/event listeners
		}
		for _, fn := range resourceFuncs {
			if sel.Sel.Name == fn {
				return true
			}
		}
		
		// Context creation without cancellation
		if x, ok := sel.X.(*ast.Ident); ok {
			if x.Name == "context" && (sel.Sel.Name == "WithCancel" || 
				sel.Sel.Name == "WithTimeout" || sel.Sel.Name == "WithDeadline") {
				return true
			}
		}
	}
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if ident.Name == "os.Open" || ident.Name == "http.Get" {
			return true
		}
	}
	return false
}

func getResourceType(call *ast.CallExpr) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		funcName := sel.Sel.Name
		
		// Check by function name
		switch funcName {
		case "NewWatcher":
			return "file_watcher"
		case "NewTicker", "NewTimer":
			return "timer"
		case "AfterFunc":
			return "timer_callback"
		case "Subscribe", "Consume":
			return "message_queue_subscription"
		case "Watch", "AddEventHandler":
			return "event_listener"
		case "WithCancel", "WithTimeout", "WithDeadline":
			return "context"
		}
		
		// Check by package name
		if x, ok := sel.X.(*ast.Ident); ok {
			switch x.Name {
			case "os":
				return "file"
			case "http":
				return "http_response"
			case "sql":
				return "db_connection"
			case "net":
				return "network_connection"
			case "time":
				return "timer"
			case "context":
				return "context"
			default:
				return "resource"
			}
		}
	}
	return "resource"
}

func checkFunctionHasSelect(call *ast.CallExpr) bool {
	// Simplified - would need to inspect function body
	return false
}

func checkFunctionHasReturn(call *ast.CallExpr) bool {
	// Simplified - would need to inspect function body
	return false
}

func checkForBreakOrReturn(body *ast.BlockStmt) bool {
	hasExit := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.BranchStmt); ok {
			hasExit = true
		}
		if _, ok := n.(*ast.ReturnStmt); ok {
			hasExit = true
		}
		return !hasExit
	})
	return hasExit
}

func checkForSleep(body *ast.BlockStmt) bool {
	hasSleep := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "time" {
					if sel.Sel.Name == "Sleep" {
						hasSleep = true
					}
				}
			}
		}
		return !hasSleep
	})
	return hasSleep
}

func extractLine(content string, lineNum int) string {
	lines := strings.Split(content, "\n")
	if lineNum > 0 && lineNum <= len(lines) {
		return strings.TrimSpace(lines[lineNum-1])
	}
	return ""
}

func getVariableName(line string) string {
	// Extract variable name from assignment like: file, err := os.Open(...)
	parts := strings.Split(line, ":=")
	if len(parts) > 0 {
		vars := strings.Split(parts[0], ",")
		if len(vars) > 0 {
			return strings.TrimSpace(vars[0])
		}
	}
	return "resource"
}

// scanWithRegex provides fallback regex-based detection when AST parsing fails
func scanWithRegex(filePath, content string) ([]LeakFinding, error) {
	var findings []LeakFinding
	
	lines := strings.Split(content, "\n")
	
	// Pattern: os.Open without defer Close
	openPattern := regexp.MustCompile(`(?:file|f|fp)\s*,?\s*(?::=|=)\s*os\.Open`)
	deferClosePattern := regexp.MustCompile(`defer\s+.*\.Close\(\)`)
	
	for i, line := range lines {
		if openPattern.MatchString(line) {
			// Check next 5 lines for defer Close
			hasDefer := false
			for j := i; j < i+5 && j < len(lines); j++ {
				if deferClosePattern.MatchString(lines[j]) {
					hasDefer = true
					break
				}
			}
			
			if !hasDefer {
				findings = append(findings, LeakFinding{
					Type:        "resource",
					Category:    "unclosed_file",
					File:        filePath,
					Line:        i + 1,
					Severity:    "CRITICAL",
					Description: "File opened but never closed - file descriptor leak",
					CodeSnippet: strings.TrimSpace(line),
					Fix:         "Add: defer file.Close()",
				})
			}
		}
	}
	
	return findings, nil
}
