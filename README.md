# ebpfapp

## To develop in visual studio code

1. Run `vagrant up` to boot a VM with BPF enabled in the kernel.
2. Run `vagrant ssh-config > .vagrant_ssh_config` to generate an ssh config.
3. Open the ssh config in vscode, following these [instructions](https://code.visualstudio.com/blogs/2019/10/03/remote-ssh-tips-and-tricks#:~:text=To%20use%20an%20SSH%20config,ssh%2Fconfig%22.&text=There%20are%20many%20more%20configuration,the%20SSH%20config%20file%20format.).
4. Open `/vagrant` folder in the remote vsCode.
5. Run the code `cargo xtask build-ebpf && cargo build && cargo xtask run` in the remote vsCode terminal.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```
