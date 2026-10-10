# Driver for the fuzz harness: thin wrappers over scripts/fuzz.sh for a dev box
# with Go installed.
SHELL := bash
FUZZTIME ?= 30s

# The concurrency-sensitive targets: the stateful chain program and every
# external (remote) surface. These share a node / process-global clock, so the
# runner forces -parallel=1 for them; -race then inspects the in-node
# concurrency (RPC handler goroutines, the pool lock hand-off).
RACE_TARGETS ?= chain:FuzzChainProgram remote:FuzzPeerTxRaw remote:FuzzPeerTxSigned remote:FuzzRPCRequest remote:FuzzRPCDispatch

# Node packages whose coverage the corpus-replay (`make cover`) measures. The
# leaf parsers and the reachable external pipeline live here.
COVERPKG ?= github.com/zenon-network/go-zenon/rpc/...,github.com/zenon-network/go-zenon/chain/...,github.com/zenon-network/go-zenon/vm/...,github.com/zenon-network/go-zenon/common/...

.PHONY: corpus vet sweep race race-soak cover regress clean list

## corpus: (re)generate the structure-aware seed corpus
corpus:
	go run ./cmd/seedgen -out ./corpus

## vet: type-check every harness
vet:
	go vet ./...

## sweep: fuzz every target for $(FUZZTIME) each, bucketing crashers
sweep: corpus
	FUZZTIME=$(FUZZTIME) bash scripts/fuzz.sh

## race: directed concurrency probe(s) under the race detector (fast, for CI).
## Drives one live node's pools from many reader goroutines against a writer
## (TestPoolConcurrentAccessRace), the lock hand-off no fuzz target exercises.
race:
	go test ./chain/ ./remote/ -race -run='Race' -count=1 -v

## race-soak: fuzz every concurrency-sensitive target under -race for FUZZTIME
## each (chain program + all external surfaces). Slower; this is the soak that
## would catch a data race reachable only on a specific adversarial input.
race-soak: corpus
	FUZZTIME=$(FUZZTIME) FUZZ_RACE=1 TARGETS="$(RACE_TARGETS)" bash scripts/fuzz.sh

## cover: absolute node-code coverage reached by the EXTERNAL corpus (the
## remote + chain seeds), replayed with the node packages instrumented. Scoped
## to those two because the leaf-parser packages (decode, abi) ship committed
## regression crashers that fail on replay by design. This number is the floor
## the seeds alone reach; the during-fuzzing coverage trajectory (the "verdict"
## column in the sweep SUMMARY) is the saturation signal for a live run.
cover:
	@mkdir -p findings
	go test ./remote/ ./chain/ \
	  -run='^Fuzz' -coverpkg='$(COVERPKG)' -coverprofile=findings/cover.out
	@echo "---- coverage of node packages reached by the external corpus ----"
	@go tool cover -func=findings/cover.out | tail -1

## regress: replay only the committed crashers (fast; no new fuzzing)
regress:
	go test ./... -run='Fuzz' 2>&1 | tail -30

## list: show discovered fuzz targets
list:
	@grep -rEl '^func Fuzz' --include='*_test.go' . | while read -r f; do \
	  d=$$(dirname $$f); grep -oE '^func (Fuzz[A-Za-z0-9_]+)' $$f | awk -v d=$$d '{print d":"$$2}'; \
	done

clean:
	rm -rf ./findings
	go clean -fuzzcache
