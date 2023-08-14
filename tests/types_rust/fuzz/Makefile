all:
	cargo fuzz run -j30 fuzz_target_1

cov:
	cargo fuzz coverage fuzz_target_1
	$(eval DEFAUTL_TARGET := $(shell rustup show | grep 'Default host' | grep -o ': .*' | sed 's/: //'))
	cargo-cov -- \
		show target/$(DEFAUTL_TARGET)/coverage/$(DEFAUTL_TARGET)/release/fuzz_target_1 \
    --format=html \
    -instr-profile=coverage/fuzz_target_1/coverage.profdata \
    > coverage.html

# Only when the data length reaches a minimum value can verify be passed. To speed up testing, shorter values will be discarded.
all_2:
	cargo fuzz run -j30 fuzz_target_2

cov_2:
	cargo fuzz coverage fuzz_target_2
	$(eval DEFAUTL_TARGET := $(shell rustup show | grep 'Default host' | grep -o ': .*' | sed 's/: //'))
	cargo-cov -- \
		show target/$(DEFAUTL_TARGET)/coverage/$(DEFAUTL_TARGET)/release/fuzz_target_2 \
    --format=html \
    -instr-profile=coverage/fuzz_target_2/coverage.profdata \
    > coverage.html

install:
	rustup component add llvm-tools-preview
	cargo install cargo-fuzz
	cargo install cargo-binutils

.PHONY:
	all cov install