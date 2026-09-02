#!/usr/bin/env bash
#
# CI gate 02b: the integration suite has to have RUN, not merely reported green.
#
# tests/UserSvc.IntegrationTests skips itself when no Docker daemon answers, and it assigns that
# skip at xunit DISCOVERY time. On an agent without Docker the suite therefore passes having
# executed nothing at all, and "0 of 0 tests failed" is indistinguishable in the pipeline summary
# from a suite that ran. That is not a hypothetical: the 40 integration tests are the only coverage
# of the back-office sign-in door, whose configuration section was completely unbound while 1,281
# unit tests were green.
#
# The skip itself is worth keeping - a developer's laptop legitimately has no Docker, and paying a
# 30-second daemon timeout per test to learn that is worse than skipping. A CI agent never
# legitimately lacks Docker, so what CI needs is the assertion that the skip did not happen. This
# script makes it, from the test run's own result file: the count that actually executed, and zero
# skips. A skipped test for any other reason - a [Fact(Skip = "...")] left in over lunch, a
# collection fixture that failed to initialise - is caught by exactly the same check.
#
# USAGE
#   scripts/ci/assert-integration-tests-ran.sh [trx file or directory]
#
# With no argument it reads the newest .trx under tests/UserSvc.IntegrationTests/TestResults, which
# is where "dotnet test" puts it by default. Delete that directory before the test step so a stale
# result from an earlier run cannot be mistaken for this one.
#
# Exit codes: 0 the suite ran, 1 it did not (or skipped), 2 the check could not run.

set -euo pipefail

# The suite had 40 tests when this floor was written (wave 8). It is a floor, not an expectation:
# it exists to catch "the assembly ran but almost nothing in it did", which is what a broken
# collection fixture or a bad filter looks like. Adding tests never needs a change here. Lowering
# it is only ever correct in the same commit that removes tests, and that commit should say which.
readonly MINIMUM_EXECUTED_TESTS=40

readonly TEST_ASSEMBLY='UserSvc.IntegrationTests.dll'
readonly DEFAULT_RESULTS_DIRECTORY='tests/UserSvc.IntegrationTests/TestResults'

fail_setup() {
    echo "integration-ran check: $1" >&2
    exit 2
}

fail() {
    echo "" >&2
    echo "GATE FAILED: $1" >&2
    exit 1
}

# One attribute of the single <Counters .../> element.
#
# The whitespace before the name is what keeps "executed" from matching inside "notExecuted", and
# it has to come from [[:space:]] rather than a literal space after "<Counters", because "total" is
# the FIRST attribute: a pattern of "<Counters [^>]* total=" demands an attribute before the one it
# wants and so never matches it at all.
counter() {
    local name="$1" value
    value="$(sed -n "s/.*<Counters[^>]*[[:space:]]${name}=\"\([0-9]*\)\".*/\1/p" "$TRX" | head -1)"
    [[ -n "$value" ]] || fail_setup "the result file has no '${name}' counter: $TRX"
    printf '%s' "$value"
}

newest_trx() {
    local target="$1"

    if [[ -f "$target" ]]; then
        printf '%s' "$target"
        return
    fi

    [[ -d "$target" ]] || fail "no test results at $target, so the integration suite did not run
at all. Run 'dotnet test' with '--logger trx' before this check."

    local newest
    newest="$(find "$target" -name '*.trx' -type f -exec ls -t {} + 2> /dev/null | head -1 || true)"

    [[ -n "$newest" ]] || fail "no .trx file under $target, so the integration suite produced no
result file. It did not run: a suite that runs and fails still writes one."

    printf '%s' "$newest"
}

main() {
    local root
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    cd "$root"

    command -v sed > /dev/null || fail_setup "sed is not on PATH."

    TRX="$(newest_trx "${1:-$DEFAULT_RESULTS_DIRECTORY}")"
    echo "integration-ran check: reading $TRX"

    grep -q "$TEST_ASSEMBLY" "$TRX" \
        || fail_setup "$TRX is not a result file for $TEST_ASSEMBLY. Point this check at the
integration project's own TestResults directory."

    local total executed passed failed skipped
    total="$(counter total)"
    executed="$(counter executed)"
    passed="$(counter passed)"
    failed="$(counter failed)"
    skipped="$(counter notExecuted)"

    echo "integration-ran check: total=$total executed=$executed passed=$passed failed=$failed skipped=$skipped"

    if [[ "$skipped" -gt 0 ]]; then
        echo "" >&2
        echo "Skipped tests and their reasons:" >&2
        # Each skipped result carries its reason in the ErrorInfo/Message of its own element.
        tr '<' '\n' < "$TRX" \
            | sed -n 's/^Message>\(Docker is required[^&]*\)/  - \1/p' \
            | sort -u >&2
        sed -n 's/.*<UnitTestResult[^>]* testName="\([^"]*\)"[^>]* outcome="NotExecuted".*/  - \1/p' "$TRX" \
            | head -5 >&2

        fail "$skipped of $total integration tests were SKIPPED, so this run proves nothing about
them. On a CI agent that means Docker is missing (the suite skips itself at discovery when no
daemon answers) - install or start it on the agent. It can also mean a test was left with an
explicit Skip. Either way the pipeline must not report green: these tests are the only coverage of
the running service, its database and its Redis."
    fi

    if [[ "$failed" -gt 0 ]]; then
        fail "$failed integration test(s) failed. The test step should already have failed the
build; if it did not, its exit code is being swallowed."
    fi

    if [[ "$executed" -lt "$MINIMUM_EXECUTED_TESTS" ]]; then
        fail "only $executed integration test(s) executed, and this gate expects at least
$MINIMUM_EXECUTED_TESTS. Either the assembly ran a fraction of its tests - a collection fixture
that failed to initialise, or a filter left on the command line - or tests were deleted. If they
were deleted deliberately, lower MINIMUM_EXECUTED_TESTS in $(basename "${BASH_SOURCE[0]}") in the
same commit and say which tests went."
    fi

    echo "integration-ran check passed: $executed integration test(s) executed, none skipped."
}

main "$@"
