#!/usr/bin/env bash
#
# CI gate 04: the EF Core model must agree with the hand-written scripts in db/.
#
# db/*.sql is the source of truth (decision 14: the application never changes the database), and
# the model is what the running service believes. When the two drift, the service is wrong about
# the shape of its own data - a column the model thinks has a default gets NULL, a column it thinks
# is text gets rejected at 21 characters - and nothing says so until a request fails in production.
#
# HOW IT WORKS. Two scratch databases beside the CI database: db/*.sql is applied to one and the
# model's own generated DDL to the other. Both are then reduced to a sorted, normalised projection
# of information_schema.columns and pg_indexes, and the projections are diffed. Comparing databases
# rather than SQL text is what makes the diff meaningful: the two sides write the same schema in
# very different SQL (IF NOT EXISTS guards, ALTER-then-backfill, DO blocks), and PostgreSQL is the
# only honest arbiter of whether that ends up as the same schema.
#
# The projection deliberately leaves out what is legitimately different between two databases or
# invisible to the application: the catalog (database) name, oids, column order (every access goes
# through EF or a named column list), table and column comments, seed rows, triggers and grants.
# Sequence and schema names ARE compared - both sides derive them identically, so a difference is
# drift. Primary keys and unique constraints are compared through pg_indexes; FOREIGN KEY and
# CHECK constraints through pg_constraint, by name AND definition. Column defaults are compared
# separately and directionally - see compare_defaults for why they cannot share one diff.
#
# EXCEPTIONS. A difference is tolerated only if it is written down in the "gate 04" table in
# db/README.md, next to the explanation of why the model cannot express it. Keeping the list there
# instead of in this script is the point: an exception nobody can read the reason for stops being
# an exception and becomes drift with a permit. An entry that no longer differs also fails, so the
# table cannot outlive its reason.
#
# USAGE
#   DATABASE_URL=postgresql://user:pass@host:5432/postgres scripts/ci/gate04-ef-model-vs-ddl.sh
#
#   DATABASE_URL         libpq URI of any database on the target server. Only used to connect in
#                        order to CREATE the two scratch databases; it is never written to.
#   BUILD_CONFIGURATION  optional. When set (CI sets Release), the model script is generated with
#                        --configuration "$BUILD_CONFIGURATION" --no-build, which is what makes it
#                        find the assemblies an earlier Release-only build step produced. Without
#                        it dotnet-ef builds the project itself, which is what a hand run wants.
#   WORK_DIR             optional. Where the artefacts land (default: a temporary directory).
#
# Exit codes: 0 clean, 1 drift or a stale exception, 2 the gate could not run.

set -euo pipefail

fail_setup() {
    echo "gate 04: $1" >&2
    exit 2
}

repo_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

# The scratch databases are named from the base URL by replacing only the path component, so the
# credentials, host, port and any query parameters (sslmode, and so on) are carried over verbatim.
readonly URI_SHAPE='^([a-zA-Z0-9+]+://[^/?#]*)(/[^?#]*)?(\?[^#]*)?$'

scratch_url() {
    local database="$1"
    [[ "$BASE_URL" =~ $URI_SHAPE ]] || fail_setup "DATABASE_URL is not a libpq URI."
    printf '%s/%s%s' "${BASH_REMATCH[1]}" "$database" "${BASH_REMATCH[3]:-}"
}

psql_admin() {
    psql "$BASE_URL" --quiet --no-psqlrc --set ON_ERROR_STOP=1 "$@"
}

psql_in() {
    local database="$1"
    shift
    psql "$(scratch_url "$database")" --quiet --no-psqlrc --set ON_ERROR_STOP=1 "$@"
}

drop_scratch_databases() {
    psql_admin --command "DROP DATABASE IF EXISTS $DDL_DB WITH (FORCE)" > /dev/null 2>&1 || true
    psql_admin --command "DROP DATABASE IF EXISTS $MODEL_DB WITH (FORCE)" > /dev/null 2>&1 || true
}

# Reads the exception table out of db/README.md. Language-independent on purpose: the section is
# found by the heading that mentions this gate's number, and a row counts only when its first cell
# is a schema-qualified object name and its second cell actually says something.
read_exceptions() {
    awk '
        /^#+ / { in_section = ($0 ~ /04/) ? 1 : 0; if (in_section) sections++; next }
        !in_section { next }
        /^\|/ {
            line = $0
            gsub(/`/, "", line)
            n = split(line, cell, "|")
            if (n < 3) { next }
            object = cell[2]; reason = cell[3]
            gsub(/^[ \t]+|[ \t]+$/, "", object)
            gsub(/^[ \t]+|[ \t]+$/, "", reason)
            if (object !~ /^[a-z_][a-z0-9_]*\.[a-z0-9_]+$/) { next }
            if (length(reason) < 10) { next }
            print object
        }
        END { if (sections == 0) { exit 3 } }
    ' "$1"
}

main() {
    local root
    root="$(repo_root)"

    [[ -n "${DATABASE_URL:-}" ]] || fail_setup "DATABASE_URL is not set."
    [[ "$DATABASE_URL" =~ $URI_SHAPE ]] || fail_setup \
        "DATABASE_URL is not a libpq URI. This gate has to name a database of its own, so it needs
the URI form: postgresql://user:password@host:5432/somedatabase"
    command -v psql > /dev/null || fail_setup "psql is not on PATH."
    command -v dotnet > /dev/null || fail_setup "dotnet is not on PATH."

    BASE_URL="$DATABASE_URL"
    local run="$$_$(date +%s)"
    DDL_DB="usersvc_gate04_ddl_$run"
    MODEL_DB="usersvc_gate04_model_$run"

    local work="${WORK_DIR:-$(mktemp -d)}"
    mkdir -p "$work"

    local scripts=("$root"/db/*.sql)
    [[ -f "${scripts[0]}" ]] || fail_setup "no scripts found in $root/db - has the folder moved?"

    local exceptions="$work/exceptions.txt"
    if ! read_exceptions "$root/db/README.md" > "$exceptions"; then
        fail_setup "db/README.md has no heading mentioning gate 04, so the exception table could
not be found. This gate refuses to run rather than treat every recorded exception as drift."
    fi
    echo "gate 04: $(wc -l < "$exceptions" | tr -d ' ') recorded exception(s) read from db/README.md"

    trap drop_scratch_databases EXIT
    drop_scratch_databases
    psql_admin --command "CREATE DATABASE $DDL_DB" > /dev/null
    psql_admin --command "CREATE DATABASE $MODEL_DB" > /dev/null

    echo "gate 04: applying ${#scripts[@]} script(s) from db/ to $DDL_DB"
    local script
    for script in "${scripts[@]}"; do
        psql_in "$DDL_DB" --file "$script" > "$work/apply-ddl.log" 2>&1 \
            || { echo "gate 04: db/$(basename "$script") failed to apply:" >&2
                 tail -20 "$work/apply-ddl.log" >&2
                 exit 2; }
    done

    echo "gate 04: generating the model's DDL"
    local ef_arguments=(dbcontext script
        --project src/UserSvc.Infrastructure
        --startup-project src/UserSvc.Infrastructure
        --output "$work/model.sql")
    if [[ -n "${BUILD_CONFIGURATION:-}" ]]; then
        ef_arguments+=(--configuration "$BUILD_CONFIGURATION" --no-build)
    fi

    (cd "$root" && dotnet tool restore > /dev/null && dotnet dotnet-ef "${ef_arguments[@]}") \
        || fail_setup "dotnet-ef could not generate the model script."

    # dotnet-ef writes a UTF-8 BOM, which psql reports as a syntax error on the first statement.
    perl -i -pe 's/^\x{ef}\x{bb}\x{bf}// if $. == 1' "$work/model.sql"

    echo "gate 04: applying the model's DDL to $MODEL_DB"
    psql_in "$MODEL_DB" --file "$work/model.sql" > "$work/apply-model.log" 2>&1 \
        || { echo "gate 04: the model's own DDL failed to apply:" >&2
             tail -20 "$work/apply-model.log" >&2
             exit 2; }

    local side
    for side in ddl model; do
        local database="$DDL_DB"
        [[ "$side" == "model" ]] && database="$MODEL_DB"
        psql_in "$database" --tuples-only --no-align --command "$(columns_query)" > "$work/$side.txt"
        psql_in "$database" --tuples-only --no-align --command "$(indexes_query)" >> "$work/$side.txt"
        psql_in "$database" --tuples-only --no-align --command "$(constraints_query)" >> "$work/$side.txt"
        psql_in "$database" --tuples-only --no-align --command "$(defaults_query)" > "$work/$side-defaults.txt"
    done

    local ddl_lines model_lines
    ddl_lines=$(wc -l < "$work/ddl.txt" | tr -d ' ')
    model_lines=$(wc -l < "$work/model.txt" | tr -d ' ')
    echo "gate 04: comparing $ddl_lines projected object(s) from db/ against $model_lines from the model"

    if [[ "$ddl_lines" -eq 0 || "$model_lines" -eq 0 ]]; then
        fail_setup "one side projected nothing, so the comparison would pass on an empty schema."
    fi

    local defaults_failed=0
    compare_defaults "$work/ddl-defaults.txt" "$work/model-defaults.txt" || defaults_failed=1

    diff "$work/ddl.txt" "$work/model.txt" > "$work/diff.txt" || true
    local shape_failed=0
    report "$exceptions" "$work/diff.txt" || shape_failed=1

    if [[ "$defaults_failed" -ne 0 || "$shape_failed" -ne 0 ]]; then
        # Nothing reassuring may be printed here. A gate that says "passed" anywhere in a failing
        # run is a gate people learn to skim past.
        exit 1
    fi

    echo "gate 04 PASSED: the EF model agrees with db/*.sql."
}

# One line per column. Ordered in SQL so the diff is stable, and deliberately free of the catalog
# name, oids and ordinal_position - the first two differ between any two databases and the third is
# invisible to a caller that names its columns.
#
# The column DEFAULT is deliberately NOT part of this line. It is compared separately and
# DIRECTIONALLY by compare_defaults, because the two directions have opposite consequences and
# folding them into one diff would have forced a blanket exception that hides the dangerous one.
columns_query() {
    cat <<SQL
SELECT 'column ' || c.table_schema || '.' || c.table_name || '.' || c.column_name
    || ' type=' || c.data_type
    || ' length=' || coalesce(c.character_maximum_length::text, '-')
    || ' numeric=' || coalesce(c.numeric_precision::text, '-') || ',' || coalesce(c.numeric_scale::text, '-')
    || ' datetime=' || coalesce(c.datetime_precision::text, '-')
    || ' nullable=' || c.is_nullable
    || ' identity=' || c.is_identity || coalesce(':' || c.identity_generation, '')
    || ' generated=' || c.is_generated
FROM information_schema.columns c
JOIN information_schema.tables t
  ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
  AND c.table_schema NOT LIKE 'pg\\_toast%'
ORDER BY c.table_schema, c.table_name, c.column_name;
SQL
}

# One line per FOREIGN KEY and CHECK constraint, by definition rather than by name alone.
#
# THIS IS THE HOLE THAT LET THE DRIFT HAPPEN. Until wave 8 the projection compared only
# index-backed constraints, so three foreign-key differences sat unseen for eight waves:
# identity.user_passkeys' foreign key existed in db/*.sql and not in the model,
# identity.user_identities' existed on both sides under two DIFFERENT names (so a database built by
# applying both would carry the same foreign key twice), and identity.feedback's two were NO ACTION
# in db/*.sql against ON DELETE RESTRICT in the model.
#
# The name IS part of the line, deliberately. Two names for one relationship is the drift that
# produced the duplicate, and comparing definitions alone would have called that pair equal.
constraints_query() {
    cat <<SQL
SELECT 'constraint ' || n.nspname || '.' || rel.relname
    || ' ' || con.conname || ' ' || pg_get_constraintdef(con.oid)
FROM pg_constraint con
JOIN pg_class rel ON rel.oid = con.conrelid
JOIN pg_namespace n ON n.oid = rel.relnamespace
WHERE con.contype IN ('f', 'c')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY 1;
SQL
}

# One line per column that HAS a default. Compared directionally by compare_defaults.
defaults_query() {
    cat <<SQL
SELECT c.table_schema || '.' || c.table_name || '.' || c.column_name || ' ' || c.column_default
FROM information_schema.columns c
JOIN information_schema.tables t
  ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
  AND c.table_schema NOT LIKE 'pg\\_toast%'
  AND c.column_default IS NOT NULL
ORDER BY 1;
SQL
}

# Column defaults, compared by DIRECTION rather than by equality.
#
# WHY THIS IS NOT A PLAIN DIFF. A default that exists in db/*.sql and not in the model is harmless:
# EF has no reason to know about a value it never reads back, and not knowing simply makes it send
# the column explicitly on every INSERT. There are 52 of these and they are not drift.
#
# The other direction is a live defect, and it has already happened here. HasDefaultValueSql makes
# EF OMIT the column from an INSERT when the property holds its CLR default, on the understanding
# that the database will fill it in. iam.backend_identities.provider_details declared
# '{}'::jsonb in the model "with the live column's own default" - the live column had no default at
# all, so every row EF wrote silently landed on NULL instead of the object every reader expected.
# A blanket "ignore all defaults" exception would have let that class straight back in, which is
# the whole reason this is directional.
#
# So: model-only defaults and disagreeing defaults FAIL; db-only defaults are counted and reported
# so the number stays visible rather than becoming invisible.
compare_defaults() {
    local ddl_file="$1" model_file="$2"

    awk '
        NR == FNR { split($0, f, " "); ddl[f[1]] = substr($0, index($0, " ") + 1); next }
        {
            split($0, f, " ")
            column = f[1]
            model_default = substr($0, index($0, " ") + 1)

            if (!(column in ddl)) {
                bad++
                printf "  default declared by the model and absent from db/*.sql: %s = %s\n", column, model_default > "/dev/stderr"
            } else if (ddl[column] != model_default) {
                bad++
                printf "  default disagrees: %s is %s in db/*.sql and %s in the model\n", column, ddl[column], model_default > "/dev/stderr"
            }
            seen[column] = 1
        }
        END {
            for (column in ddl) { if (!(column in seen)) db_only++ }

            printf "gate 04: %d column default(s) exist in db/*.sql and not in the model, which is the harmless direction.\n", db_only + 0

            if (bad > 0) {
                printf "\ngate 04 FAILED: %d column default(s) the model declares and db/*.sql does not agree with.\n", bad > "/dev/stderr"
                print "This direction is a live defect, not a cosmetic difference: EF omits a column" > "/dev/stderr"
                print "from the INSERT when the property holds its CLR default and the model says the" > "/dev/stderr"
                print "database will supply one, so a default the database does not actually have" > "/dev/stderr"
                print "means the row lands on NULL. Remove the HasDefaultValue/HasDefaultValueSql, or" > "/dev/stderr"
                print "add the default to db/*.sql in a numbered script." > "/dev/stderr"
                exit 1
            }
        }
    ' "$ddl_file" "$model_file"
}

# One line per index, including the ones primary-key and unique constraints are built on.
# pg_get_indexdef normalises the expression, so two spellings of one index compare equal and two
# different indexes never do.
indexes_query() {
    cat <<SQL
SELECT 'index ' || schemaname || '.' || indexname || ' :: ' || indexdef
FROM pg_indexes
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND schemaname NOT LIKE 'pg\\_toast%'
ORDER BY schemaname, tablename, indexname;
SQL
}

report() {
    awk -v exceptions_file="$1" '
        BEGIN {
            while ((getline line < exceptions_file) > 0) {
                if (line != "") { count++; exception[count] = line; used[count] = 0 }
            }
        }
        /^[<>] / {
            payload = substr($0, 3)
            for (i = 1; i <= count; i++) {
                if (index(payload, exception[i]) > 0) { used[i]++; excused++; next }
            }
            drift++
            printf "  %s %s\n", (substr($0, 1, 1) == "<" ? "only in db/*.sql :" : "only in the model:"), payload > "/dev/stderr"
        }
        END {
            for (i = 1; i <= count; i++) {
                if (used[i] == 0) {
                    stale++
                    printf "  recorded exception no longer differs: %s\n", exception[i] > "/dev/stderr"
                }
            }

            if (drift > 0) {
                printf "\ngate 04 FAILED: %d difference(s) between the EF model and db/*.sql", drift > "/dev/stderr"
                printf " (%d excused).\n", excused > "/dev/stderr"
                print "db/*.sql is the source of truth: change the model to match it, or add a" > "/dev/stderr"
                print "numbered script and re-run. If the model genuinely cannot express the shape," > "/dev/stderr"
                print "record it in the gate 04 exception table in db/README.md with the reason." > "/dev/stderr"
            }

            if (stale > 0) {
                printf "\ngate 04 FAILED: %d recorded exception(s) in db/README.md no longer\n", stale > "/dev/stderr"
                print "correspond to a difference. Remove them: an exception that outlives its" > "/dev/stderr"
                print "reason makes this gate look tighter than it is." > "/dev/stderr"
            }

            if (drift > 0 || stale > 0) { exit 1 }
            printf "gate 04: shapes and indexes agree (%d excused difference(s)).\n", excused + 0
        }
    ' "$2"
}

main "$@"
