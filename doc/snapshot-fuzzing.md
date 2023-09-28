# Snapshot fuzzing Bitcoin Core using AFL++'s nyx-mode

## Hardware & Software requirements

* Supported architectures: 64-bit x86
* Bare metal (can't be run on a VPS or any other virualised environment)
* Linux kernel 5.15 or newer

## Quickstart guide

```sh
# Enable required kvm settings
sudo modprobe -r kvm-intel # or kvm-amd for AMD processors
sudo modprobe -r kvm
sudo modprobe kvm enable_vmware_backdoor=y
sudo modprobe kvm-intel # or kvm-amd for AMD processors

# Build the nyx-bitcoin-core docker image
DOCKER_BUILDKIT=1 docker build \
  --ssh default=$HOME/.ssh/<your_key> \
  --build-arg=TARGET=<your_target_name> \
  --tag nyx-bitcoin-core .

# Start the container (--privileged for kvm)
docker run --privileged \
  --name nyx-bitcoin-core-0 \
  --detach --interactive --tty \
  nyx-bitcoin-core /bin/sh

# Drop into a shell in the container
docker exec -it nyx-bitcoin-core-0 bash

# In the container:

# Create afl input/output dirs
mkdir /tmp/out
mkdir /tmp/in
# afl++ requires at least one pre-existing input
echo "AAA" > /tmp/in/A

# Execute the afl_runner
AFL_BIN_PATH="./AFLplusplus" ./bitcoin/test/fuzz/afl_runner.py \
  --input="/tmp/in" --output="/tmp/out" \
  --nyx --cores=5 \
  --log_file=./log.txt \
  fuzz /tmp/nyx_bitcoin

# Outside the container:

# Get a summary of fuzzing stats
docker exec -it nyx-bitcoin-core-0 sh -c "./AFLplusplus/afl-whatsup -s /tmp/out"
```
