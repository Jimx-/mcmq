# MCMQ

## Prerequisites
Building MCMQ requires a RISC-V toolchain ([riscv-gnu-toolchain](https://github.com/riscv/riscv-gnu-toolchain)). It can be downloaded and built with:
```sh
export RISCV=$HOME/riscv
git clone https://github.com/riscv/riscv-gnu-toolchain.git
cd riscv-gnu-toolchain
./configure --prefix=$RISCV --with-abi=lp64d --with-cmodel=medany
make -j
```

After that, the toolchain will be installed to `$HOME/riscv`. Please make sure that the environment variable `$RISCV` is set to the installation directory of the toolchain because the make script relies on this variable to locate the toolchain.

You also need to install `qemu-system-riscv64` for running the flash firmware:
```sh
git clone https://github.com/qemu/qemu
cd qemu
git checkout v6.0.0
./configure --target-list=riscv64-softmmu
make -j
sudo make install
```
You can run `qemu-system-riscv64` after the build to check whether it is installed successfully.

## Building the firmware
After the toolchain is installed, the firmware can be built using:
```sh
git clone https://github.com/abc70182984/mcmq.git
cd mcmq
chmod +x gen_image.sh
make image
```

This will create a `bbl` in the current directory. This is the compiled firmware with the bootloader which can be run with the virtual machine.

## Running the firmware
To run the firmware, build and start the [frontend driver](https://github.com/abc70182984/mcmqhost) first. After that, run:
```sh
make qemu
```

You should see the detailed configuration sent by the frontend driver in the virtual machine console if the firmware starts successfully.
