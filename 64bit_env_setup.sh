wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.tar.gz -P ~
echo "download kernel"
tar -xvf ~/linux-5.15.tar.gz -C ~
echo "decompress kernel"
sudo apt-get update
apt install build-essential libncurses-dev libssl-dev libelf-dev bison flex dwarves zstd -y
echo "install make tools"
cp -Rf 64bit/hubert ~/linux-5.15/hubert
cp -Rf 64bit/getms ~/linux-5.15/getms
cp -Rf 64bit/get_phy_addr ~/linux-5.15/get_phy_addr
echo "copy system call source code"

cp 64bit/cp_file/Makefile      ~/linux-5.15/Makefile
cp 64bit/cp_file/.config        ~/linux-5.15/.config
cp 64bit/cp_file/uts.h          ~/linux-5.15/include/linux/uts.h
cp 64bit/cp_file/syscall_64.tbl ~/linux-5.15/arch/x86/entry/syscalls/syscall_64.tbl
cp 64bit/cp_file/syscalls.h     ~/linux-5.15/include/linux/syscalls.h

echo "copy system file"

cp 64bit/cp_file/grub /etc/default/grub
echo "copy grub setting"

make -C ~/linux-5.15  -j6
make -C ~/linux-5.15 modules_install -j6
make -C ~/linux-5.15 install -j6
