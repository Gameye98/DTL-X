apt install python git ncurses-utils apksigner openjdk-17 unzip zip
apt install aapt aapt2 -y
python -m pip install progressbar
cp assets/aapt $PREFIX/bin
cp assets/aapt2 $PREFIX/bin
chmod +x $PREFIX/bin/aapt
chmod +x $PREFIX/bin/aapt2
echo -e "\x1b[1;92m[+] custom patched aapt & aapt2 installed\x1b[0m"
# dexRepair installation
#if test -e dexRepair; then
#	rm -rf dexRepair
#fi
#git clone https://github.com/Gameye98/dexRepair
#rm dexRepair/Readme.md
#mv dexRepair/* .
#rm -rf dexRepair
#bash make.sh
#echo -e "\x1b[1;92m[+] dexRepair installed\x1b[0m"
