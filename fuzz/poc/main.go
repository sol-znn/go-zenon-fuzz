// Command poc demonstrates the four crashers the fuzz harness found in
// go-zenon release/0.0.9, each against the real exported node function, with a
// plain-language account of the mechanism and the operational impact.
//
//	go run ./poc            # run all four, report each, exit non-zero if any crashed
//	go run ./poc 1          # run one (1..4)
//	go run ./poc 3 --crash  # run one WITHOUT the recover, so the process dies
//	                        # for real (this is the actual DoS, not a simulation)
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/zenon-network/go-zenon-fuzz/internal/pocs"
)

func main() {
	crash := false
	var only int
	for _, a := range os.Args[1:] {
		if a == "--crash" {
			crash = true
			continue
		}
		if n, err := strconv.Atoi(a); err == nil {
			only = n
		}
	}

	all := pocs.All()
	ran, crashed := 0, 0
	for _, p := range all {
		if only != 0 && p.ID != only {
			continue
		}
		ran++
		if run(p, crash) {
			crashed++
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 72))
	fmt.Printf("%d proof(s) ran; %d crashed the call into the node.\n", ran, crashed)
	if crashed > 0 {
		os.Exit(1)
	}
}

func run(p *pocs.PoC, crash bool) (didCrash bool) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 72))
	fmt.Printf("PoC #%d  %s\n", p.ID, p.Title)
	fmt.Printf("%s\n", strings.Repeat("-", 72))
	fmt.Printf("class : %s\n", p.Class)
	fmt.Printf("reach : %s\n", p.Reach)
	fmt.Printf("sev   : %s\n", p.Severity)
	fmt.Printf("input : %s\n", p.Describe())
	fmt.Printf("impact: %s\n", strings.ReplaceAll(p.Impact, ". ", ".\n        "))

	if crash {
		fmt.Printf("\n>> calling the node (no recover; the process will now die)\n\n")
		p.Trigger()
		return false
	}

	fmt.Printf("\n>> calling the node ...\n")
	func() {
		defer func() {
			if r := recover(); r != nil {
				didCrash = true
				fmt.Printf("   PANIC: %v\n", r)
				fmt.Printf("   at   : %s\n", topNodeFrame(debug.Stack()))
			}
		}()
		p.Trigger()
	}()
	if !didCrash {
		fmt.Printf("   (no panic — the bug may be fixed in this checkout)\n")
	}
	return didCrash
}

// topNodeFrame pulls the first stack frame inside the node (not the runtime,
// this command, or reflect) out of a debug.Stack() dump: the crash site.
func topNodeFrame(stack []byte) string {
	lines := strings.Split(string(stack), "\n")
	for i, ln := range lines {
		if strings.Contains(ln, "go-zenon/") && !strings.Contains(ln, "go-zenon-fuzz") && i+1 < len(lines) {
			fn := strings.TrimPrefix(strings.TrimSpace(lines[i]), "github.com/zenon-network/go-zenon/")
			loc := strings.TrimSpace(lines[i+1])
			if idx := strings.Index(loc, "go-zenon/"); idx >= 0 {
				loc = strings.Fields(loc[idx+len("go-zenon/"):] + " ")[0]
			}
			return fn + "  (" + loc + ")"
		}
	}
	return "unknown"
}
