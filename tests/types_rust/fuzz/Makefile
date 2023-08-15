all:
	cargo fuzz run -j30 fuzz_target_1

cov:
	cargo fuzz coverage fuzz_target_1
	$(eval DEFAUTL_TARGET := $(shell rustup show | grep 'Default host' | grep -o ': .*' | sed 's/: //'))
	cargo-cov -- \
		show target/$(DEFAUTL_TARGET)/coverage/$(DEFAUTL_TARGET)/release/fuzz_target_1 \
    --format=html \
		--ignore-filename-regex="(\/.*\/registry\/*)|(\/rustc\/*)" \
    -instr-profile=coverage/fuzz_target_1/coverage.profdata \
    > coverage.html

all-3:
	cargo fuzz run -j30 fuzz_target_3

cov-3:
	cargo fuzz coverage fuzz_target_3
	$(eval DEFAUTL_TARGET := $(shell rustup show | grep 'Default host' | grep -o ': .*' | sed 's/: //'))
	cargo-cov -- \
		show target/$(DEFAUTL_TARGET)/coverage/$(DEFAUTL_TARGET)/release/fuzz_target_3 \
		--format=html \
		--ignore-filename-regex="(\/.*\/registry\/*)|(\/rustc\/*)|(\/types_api.rs)" \
		-instr-profile=coverage/fuzz_target_3/coverage.profdata \
			> coverage.html

install:
	rustup component add llvm-tools-preview
	cargo install cargo-fuzz
	cargo install cargo-binutils

.PHONY:
	all cov install