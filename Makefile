# PlatformService -- build
#
# Linux only (plan decision D2). C99 + OpenSSL + SQLite only (D1).
# Warnings are errors: this codebase does not accumulate warning debt.

BIN          := platformservice
BUILD_DIR    := build
SRC_DIR      := src

CC           ?= gcc

# _GNU_SOURCE rather than _POSIX_C_SOURCE: -std=c99 alone hides sigaction and
# clock_gettime behind feature-test macros, and since D2 makes this Linux-only
# there is no cost to taking the GNU set. It buys accept4(SOCK_CLOEXEC), which
# closes a real race -- with plain accept() the descriptor is briefly
# inheritable, so a concurrent fork/exec leaks a client socket into the child.
CPPFLAGS     := -D_GNU_SOURCE -I$(SRC_DIR)

WARNINGS     := -Wall -Wextra -Werror \
                -Wshadow -Wpointer-arith -Wcast-qual -Wwrite-strings \
                -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls \
                -Wswitch-enum -Wundef -Wvla

CFLAGS       ?= -O2 -g
CFLAGS       += -std=c99 $(WARNINGS) -fno-common -MMD -MP
LDFLAGS      :=
LDLIBS       := -pthread

# Optional sanitizer flags, e.g.:
#   make clean && make SANFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
#   make clean && make test SANFLAGS="-fsanitize=thread"
# ASan/UBSan and TSan are mutually exclusive in one binary, and build/ caches
# objects by path, not by flag set -- always `make clean` first when changing
# this between builds, or sanitized and plain objects get linked together.
SANFLAGS     ?=
CFLAGS       += $(SANFLAGS)
LDFLAGS      += $(SANFLAGS)

PKGS         := openssl sqlite3
CPPFLAGS     += $(shell pkg-config --cflags $(PKGS))
LDLIBS       += $(shell pkg-config --libs $(PKGS))

SRCS         := $(shell find $(SRC_DIR) -name '*.c')
OBJS         := $(SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS         := $(OBJS:.o=.d)

# Everything except main.o, so a test binary can link the real platform code
# and supply its own main() instead.
LIB_OBJS     := $(filter-out $(BUILD_DIR)/$(SRC_DIR)/main.o,$(OBJS))

# One binary per tests/unit/test_*.c, each a standalone translation unit with
# its own main() -- there is no shared test framework dependency (plan D1).
TEST_DIR     := tests/unit
TEST_SRCS    := $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS    := $(TEST_SRCS:$(TEST_DIR)/%.c=$(BUILD_DIR)/$(TEST_DIR)/%)

# libFuzzer targets (plan 8.6). Clang-only -- GCC has no -fsanitize=fuzzer
# equivalent -- so these use their own compiler and their own object
# directory, entirely separate from $(CC)/build/, never mixed with it.
# CI-only in practice (see plan 16.2); a contributor without Clang on PATH
# just doesn't run `make fuzz` locally.
FUZZ_CC       ?= clang
FUZZ_SANFLAGS := -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
                 -fno-omit-frame-pointer -g -O1
FUZZ_DIR      := tests/fuzz
FUZZ_OBJ_DIR  := $(BUILD_DIR)/fuzz-obj
FUZZ_SRCS     := $(wildcard $(FUZZ_DIR)/fuzz_*.c)
FUZZ_BINS     := $(FUZZ_SRCS:$(FUZZ_DIR)/%.c=$(BUILD_DIR)/$(FUZZ_DIR)/%)
FUZZ_LIB_SRCS := $(filter-out $(SRC_DIR)/main.c,$(SRCS))
FUZZ_LIB_OBJS := $(FUZZ_LIB_SRCS:%.c=$(FUZZ_OBJ_DIR)/%.o)

CERT_DIR     := certs
CERT         := $(CERT_DIR)/dev-cert.pem
KEY          := $(CERT_DIR)/dev-key.pem

# Black-box pytest harness (plan 8.1): runs the real compiled binary as a
# subprocess and talks real TLS to it -- its own pinned venv, never the
# system Python packages.
HARNESS_DIR  := tests/harness
HARNESS_VENV := $(HARNESS_DIR)/.venv

.PHONY: all clean run check-config dev-cert dev-env check-banned memcheck test fuzz fuzz-smoke harness help

all: $(BUILD_DIR)/$(BIN)

$(BUILD_DIR)/$(BIN): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
	@echo "built $@"

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

-include $(DEPS)

# Test binaries link the real object files, so they exercise the same code
# `make all` produces -- never a separately-compiled copy that could drift.
$(BUILD_DIR)/$(TEST_DIR)/%: $(TEST_DIR)/%.c $(LIB_OBJS)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -I$(TEST_DIR) $< $(LIB_OBJS) $(LDLIBS) -o $@

test: $(TEST_BINS)
	@if [ -z "$(TEST_BINS)" ]; then \
	    echo "no unit tests in $(TEST_DIR)"; \
	    exit 0; \
	fi; \
	status=0; \
	for t in $(TEST_BINS); do \
	    echo "-- $$t --"; \
	    ./$$t || status=1; \
	done; \
	exit $$status

$(FUZZ_OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(FUZZ_CC) $(CPPFLAGS) -std=c99 $(WARNINGS) -fno-common $(FUZZ_SANFLAGS) -c $< -o $@

$(BUILD_DIR)/$(FUZZ_DIR)/%: $(FUZZ_DIR)/%.c $(FUZZ_LIB_OBJS)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(CPPFLAGS) -std=c99 $(WARNINGS) -fno-common $(FUZZ_SANFLAGS) \
	    $< $(FUZZ_LIB_OBJS) $(LDLIBS) -o $@

## fuzz -- build the libFuzzer targets (Clang required; see plan 8.6, 16.2).
fuzz: $(FUZZ_BINS)
	@echo "built fuzz targets: $(FUZZ_BINS)"

## fuzz-smoke -- 60s per target, seeded from the tracked corpus (plan 8.6).
## New corpus entries land in the ignored tests/fuzz/corpus/queue/<target>/;
## seed/ and regressions/ are read-only inputs, tracked in git.
fuzz-smoke: $(FUZZ_BINS)
	@if [ -z "$(FUZZ_BINS)" ]; then \
	    echo "no fuzz targets in $(FUZZ_DIR)"; \
	    exit 0; \
	fi; \
	status=0; \
	for f in $(FUZZ_BINS); do \
	    name=$$(basename $$f); \
	    target=$${name#fuzz_}; \
	    queue="$(FUZZ_DIR)/corpus/queue/$$target"; \
	    mkdir -p "$$queue"; \
	    echo "-- $$f (60s smoke) --"; \
	    "./$$f" -max_total_time=60 -close_fd_mask=3 \
	        "$$queue" "$(FUZZ_DIR)/corpus/seed" "$(FUZZ_DIR)/corpus/regressions" \
	        || status=1; \
	done; \
	exit $$status

clean:
	rm -rf $(BUILD_DIR)
	@echo "cleaned"

run: all
	./$(BUILD_DIR)/$(BIN) --dev

check-config: all
	./$(BUILD_DIR)/$(BIN) --check-config

## dev-cert -- self-signed certificate for local development.
## The 0600 mode is not cosmetic: startup refuses a world-readable key (plan 7.1).
dev-cert:
	@mkdir -p $(CERT_DIR)
	@if [ -f $(KEY) ]; then \
	    echo "$(KEY) already exists; refusing to overwrite"; \
	else \
	    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
	        -keyout $(KEY) -out $(CERT) \
	        -subj "/CN=localhost/O=PlatformService Dev" \
	        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null; \
	    chmod 600 $(KEY); \
	    chmod 644 $(CERT); \
	    echo "wrote $(CERT) and $(KEY) (key mode 600)"; \
	fi

## dev-env -- generate an untracked .env with a strong secret and bootstrap admin.
## There is deliberately no default password anywhere in this project.
dev-env:
	@if [ -f .env ]; then \
	    echo ".env already exists; refusing to overwrite"; \
	else \
	    { \
	      echo "# Generated by 'make dev-env'. Untracked. Do not commit."; \
	      echo "PS_JWT_SECRET=$$(openssl rand -base64 48)"; \
	      echo "BOOTSTRAP_ADMIN_USERNAME=admin"; \
	      echo "BOOTSTRAP_ADMIN_EMAIL=admin@example.com"; \
	      echo "BOOTSTRAP_ADMIN_PASSWORD=$$(openssl rand -base64 24)"; \
	    } > .env; \
	    chmod 600 .env; \
	    echo "wrote .env (mode 600). Load it with:  set -a; . ./.env; set +a"; \
	fi

## check-banned -- CI gate for unbounded string functions (plan 7.2).
check-banned:
	@./tools/check_banned_functions.sh

memcheck: all
	valgrind --leak-check=full --show-leak-kinds=definite,indirect \
	         --error-exitcode=1 ./$(BUILD_DIR)/$(BIN) --check-config

## harness -- black-box Python tests against the real binary (plan 8.1).
## Builds its own venv on first run; re-run to pick up requirements.txt changes.
harness:
	@if [ ! -x $(HARNESS_VENV)/bin/python3 ]; then \
	    python3 -m venv $(HARNESS_VENV); \
	    $(HARNESS_VENV)/bin/pip install --quiet --upgrade pip; \
	fi
	$(HARNESS_VENV)/bin/pip install --quiet -r $(HARNESS_DIR)/requirements.txt
	$(HARNESS_VENV)/bin/python3 -m pytest $(HARNESS_DIR) $(HARNESS_ARGS)

help:
	@echo "PlatformService"
	@echo "  make               build"
	@echo "  make run           build and run in dev mode"
	@echo "  make check-config  build and validate configuration, then exit"
	@echo "  make dev-cert      generate a self-signed dev certificate"
	@echo "  make dev-env       generate an untracked .env with secrets"
	@echo "  make check-banned  fail on banned unbounded string functions"
	@echo "  make memcheck      run under valgrind"
	@echo "  make test          build and run C unit tests (tests/unit/)"
	@echo "  make fuzz          build libFuzzer targets (needs Clang; CI-only in practice)"
	@echo "  make fuzz-smoke    run each fuzz target for 60s against the tracked corpus"
	@echo "  make harness       run the Python black-box test harness (tests/harness/)"
	@echo "  make clean         remove build output"
