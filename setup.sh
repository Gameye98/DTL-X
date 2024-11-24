dpkg -i assets/apktool_2.6.1_aarch64.deb
apt install python git ncurses-utils apksigner openjdk-17 unzip zip
apt install aapt aapt2 -y
python -m pip install progressbar
cp assets/aapt $PREFIX/bin
cp assets/aapt2 $PREFIX/bin
chmod +x $PREFIX/bin/aapt
chmod +x $PREFIX/bin/aapt2
