wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.15.tar.gz -P ~
echo "download kernel"
tar -xvf ~/linux-4.15.tar.gz -C ~
echo "decompress kernel"
sudo apt-get update
apt install build-essential libncurses-dev libssl-dev libelf-dev bison flex dwarves zstd -y
echo "install make tools"
cp -Rf 32bit/hubert ~/linux-4.15/hubert
cp -Rf 32bit/getms ~/linux-4.15/getms
cp -Rf 32bit/get_phy_addr ~/linux-4.15/get_phy_addr
echo "copy system call source code"

cp 32bit/cp_file/Makefile      ~/linux-4.15/Makefile
cp 32bit/cp_file/.config        ~/linux-4.15/.config
cp 32bit/cp_file/uts.h          ~/linux-4.15/include/linux/uts.h
cp 32bit/cp_file/syscall_32.tbl ~/linux-4.15/arch/x86/entry/syscalls/syscall_32.tbl
cp 32bit/cp_file/syscalls.h     ~/linux-4.15/include/linux/syscalls.h

echo "copy system file"

cp 32bit/cp_file/grub /etc/default/grub
echo "copy grub setting"

make -C ~/linux-4.15  -j6
make -C ~/linux-4.15 modules_install -j6
make -C ~/linux-4.15 install -j6
