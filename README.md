[![GitHub stars](https://img.shields.io/github/stars/Gameye98/DTL-X.svg)](https://github.com/Gameye98/DTL-X/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Gameye98/DTL-X.svg)](https://github.com/Gameye98/DTL-X/network/members)
[![GitHub issues](https://img.shields.io/github/issues/Gameye98/DTL-X.svg)](https://github.com/Gameye98/DTL-X/issues)
[![GitHub watchers](https://img.shields.io/github/watchers/Gameye98/DTL-X.svg)](https://github.com/Gameye98/DTL-X/watchers)
[![Python](https://img.shields.io/badge/language-Python%203-blue.svg)](https://www.python.org)
[![Bash](https://img.shields.io/badge/language-Bash-blue.svg)](https://www.gnu.org/software/bash/)
[![MIT](https://img.shields.io/badge/license-MIT-red.svg)](https://opensource.org/licenses/MIT)
[![BlackHole Security](https://img.shields.io/badge/team-BlackHole%20Security-ocean.svg)](https://github.com/BlackHoleSecurity)
[![Gameye98/DedSecTL](https://img.shields.io/badge/author-Gameye98/DedSecTL-red.svg)](https://github.com/Gameye98)

[![ForTheBadge built-by-developers](http://ForTheBadge.com/images/badges/built-by-developers.svg)](https://github.com/Gameye98)  

[![BlackHole Security](assets/gitbhs.svg)](https://github.com/BlackHoleSecurity)

# DTL-X
An Advanced Python APK Reverser and Patcher Tool.  
--rmads1: target=AndroidManifest.xml,replace=com.google.android.gms.ad  
--rmads2: No Internet (remove the required permission to do so)  
--rmads3: Search using regex and replace string ("ca-app-pub) with ("noads)  
--rmads4: (Powerful) Disable all kind of ads loader base on the dictionary list  
--rmnop: Remove all nop instruction found on the smali file  
--rmunknown: Remove all unknown files (.properties, etc)  
--customfont: Update and replace all font files with user recommended file  
--rmcopy: Remove AppCloner Copy Protection  
--rmprop: Remove only .properties file  

**• note 1: remove any whitespace found on the apk file name before patching**  
**• note 2: you can use multiple method in a single run:**  
`python dtlx.py --rmprop --rmads4 file.apk`  
**• note 3: remember the execution of method start from left to right, based on the above command: remove .properties then remove ads**  
**• note 4: if you want to update to the latest version just type:**  
`git pull .`

## Screenshot
<img src="assets/screenshot.png">

### Requirements
• python 3.x  
• apktool v2.6.1-dirty  
• smali v2.5.2 and baksmali v2.5.2  
• aapt & aapt2 (patched version, could be found on assets/)
• apksigner
• openjdk

### Installation
```bash
apt install python git apktool apksigner openjdk-17
git clone https://github.com/Gameye98/DTL-X
python -m pip install loguru
cd DTL-X
# Btw you need to replace the old/regular aapt with the patched version
# The old/regular version could not handle filename with symbol
# You can find the patched version of aapt on directory assets/
cp assets/aapt "$(command -v aapt)"
cp assets/aapt2 "$(command -v aapt2)"
python dtlx.py
```

#### Follow Our Channel or Join Our Discussion
- [BlackHole Security Org](https://github.com/BlackHoleSecurity)  
- [Schadenfreude Discussion](https://t.me/schdenfreude)  
- [Schadenfreude Channel](https://t.me/schdnfrd)

#### Credits
- **aapt & aapt2 (patched version) from Apktool M**