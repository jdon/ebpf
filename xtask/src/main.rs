mod build_ebpf;
mod codegen;
mod run;
use std::process::exit;
use Command::*;

use structopt::StructOpt;
#[derive(StructOpt)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Codegen,
    Run(run::Options),
}

fn main() {
    let opts = Options::from_args();

    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Run(opts) => run::run(opts),
        Codegen => codegen::generate(),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        exit(1);
    }
}
