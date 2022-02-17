# -*- mode: ruby -*-
# vi: set ft=ruby :

# To generate ssh config for container run:
# vagrant ssh-config > .vagrant_ssh_config


$script = <<-SCRIPT
  echo "Provisioning..."
  sudo apt update
  sudo apt install build-essential -y
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  source $HOME/.cargo/env
  rustup install stable
  rustup toolchain install nightly --component rust-src
  cargo install bpf-linker
SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-20.04"
  config.vm.provision "shell", inline: $script, privileged: false
  config.vm.provider "virtualbox" do |v|
    v.memory = 8048
    v.cpus = 8
  end
end