alias bk := build_ksud
alias bm := build_manager
alias ki := kernel_install
alias kit := kernel_install_test

build_ksud:
    cross build --target aarch64-linux-android --release --manifest-path ./userspace/ksud/Cargo.toml

build_manager: build_ksud
    cp userspace/ksud/target/aarch64-linux-android/release/ksud manager/app/src/main/jniLibs/arm64-v8a/libksud.so
    cd manager && ./gradlew aDebug

# Install an AnyKernel3 kernel onto the connected device over ADB.
# Windows platform-tools are used through WSL interop; fastboot is only
# reached from the gated boot-failure recovery branch.
kernel_install:
    python3 ./tools/kernel_install.py

kernel_install_test:
    python3 ./tools/test_kernel_install.py

clippy:
    cargo fmt --manifest-path ./userspace/ksud/Cargo.toml
    cross clippy --target x86_64-pc-windows-gnu --release --manifest-path ./userspace/ksud/Cargo.toml
    cross clippy --target aarch64-linux-android --release --manifest-path ./userspace/ksud/Cargo.toml

