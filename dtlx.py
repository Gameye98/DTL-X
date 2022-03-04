import os, sys, re
import hashlib
import subprocess
from loguru import logger

isconsole = False
endl = "\012"

@logger.catch
class patcher:
	def __init__(self, fin, args):
		self.endl = "\012"
		self.isneutralize = False
		self.ismodified = False
		self.fin = fin
		self.fnm = fin.split("/")[fin.split("/")[-1]] if "/" in fin else fin
		if not os.path.isfile(self.fin):
			raise FileNotFoundError(f"{self.fin}: No such file or directory")
		self.fout = self.fnm
		if self.fout.endswith(".apk"):
			self.fout = self.fout[0:len(self.fout)-4]
		else:
			self.fout = self.fout+".out"
		while os.path.isdir(self.fout):
			self.fout = self.fout+".out"
		self.raw = self.fout
		# Decompile APK file
		print("\x1b[92m+++++ Decompile APK into Project\x1b[0m")
		os.system(f"apktool d {self.fin}")
		self.manifestxml = open(f"{self.fout}/AndroidManifest.xml","r").read()
		# Fixing bug where the manifest copy content itself many times
		if len(self.manifestxml.split("</manifest>")) > 1:
			self.manifestxml = self.manifestxml.split("</manifest>")[0]+"</manifest>"
		self.smalidir = list(filter(lambda x: x.startswith("smali"), os.listdir(self.fout)))
		self.smalidir = list(map(lambda x: self.fout+"/"+x, self.smalidir))
		self.args = args
		for args_iter in self.args:
			# Switch Operator
			if args_iter=="rmads1":self.removeAds1()
			elif args_iter=="rmads2":self.removeAds2()
			elif args_iter=="rmads3":self.removeAds3()
			elif args_iter=="rmads4":self.removeAds4()
			elif args_iter=="rmnop":self.removeNop()
			elif args_iter=="rmnown":self.removeUnknown()
			elif args_iter=="customfont":self.customFont()
			elif args_iter=="rmscrnrestrict":self.removeSetsecure()
			elif args_iter=="rmcopy":self.bypassCopyProtection()
			elif args_iter=="rmprop":self.removeProperties()
		if not isconsole:
			# Compile Project
			print("\x1b[92m+++++ Compile Project into APK\x1b[0m")
			os.system(f"apktool b -f -d {self.fout}")
			print("\x1b[1;92m[+] Signing APK file... \x1b[0m",end="")
			os.system(f"apksigner sign --ks assets/user.keystore --ks-key-alias user --ks-pass pass:12345678 {self.fout}/dist/{self.fnm}")
			print("\x1b[1;92mOK\x1b[0m")
			print("\x1b[1;92m[+] Verifying APK file... \x1b[0m",end="")
			os.system(f"apksigner verify {self.fout}/dist/{self.fnm}")
			print("\x1b[1;92mOK\x1b[0m")
			self.signed = self.fnm
			if self.signed.endswith(".apk"):
				self.signed = self.signed[0:len(self.signed)-4]+"_sign.apk"
			else:
				self.signed = self.signed+"_sign.apk"
			os.rename(self.fout+"/dist/"+self.fnm, self.fout+"/dist/"+self.signed)
	def warning(self,content):
		print(f"\x1b[1;41;93m{content}\x1b[0m")
		__import__("time").sleep(0.2)
	def success(self,content):
		print(f"\x1b[1;92m{content}\x1b[0m")
		__import__("time").sleep(0.2)
	def writeManifestXML(self):
		if len(self.manifestxml.split("</manifest>")) > 1:
			self.manifestxml = self.manifestxml.split("</manifest>")[0]+"</manifest>"
		open(self.fout+"/AndroidManifest.xml","w").write(self.manifestxml)
	def writeNeutralize(self):
		if not self.isneutralize:
			os.system(f"mkdir -p {self.fout}/smali/sec/blackhole/dtlx")
			open(self.fout+"/smali/sec/blackhole/dtlx/Schadenfreude.smali","w").write(neutralize)
			self.isneutralize = True
	def removeAds1(self):
		self.gms_ad = [x for x in self.manifestxml.split(self.endl) if x.strip().startswith("<activity") and "com.google.android.gms.ad" in x and x.strip().endswith(">")]
		for gmsx in self.gms_ad:
			print(f"\x1b[1;92m[+] Found {len(self.gms_ad)} result(s) related to the com.google.android.gms.ad\x1b[0m")
			self.manifestxml = self.manifestxml.replace(gmsx,"")
		self.writeManifestXML()
		print(f"\x1b[1;92m[+] AndroidManifest.xml has been updated\x1b[0m")
	def removeAds2(self):
		manifesttmp = ""
		self.no_inet = ["android.permission.INTERNET","android.permission.ACCESS_NETWORK_STATE","android.permission.ACCESS_WIFI_STATE","android.permission.RECEIVE_BOOT_COMPLETED","com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE"]
		for inetx in self.no_inet:
			for f_iter in self.manifestxml.split(self.endl):
				if f_iter.strip().startswith("<uses-permission") and inetx in f_iter:
					self.warning(f_iter.strip())
				else:
					manifesttmp += f_iter+endl
		self.manifestxml = manifesttmp
		self.writeManifestXML()
		print(f"\x1b[1;92m[+] AndroidManifest.xml has been updated\x1b[0m")
	def removeAds3(self):
		for x in self.smalidir:
			self.f_ls = subprocess.run(f"find {x}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			self.f_ls = list(filter(lambda x: not x.startswith(".") and x.strip() != "", self.f_ls))
			self.f_ls = list(filter(lambda x: os.path.isfile(x) and x.endswith(".smali"), self.f_ls))
			for fx in self.f_ls:
				self.ffx = open(fx,"r").read()
				if "\"ca-app-pub" in self.ffx:
					self.success(f"[+] Found (\"ca-app-pub): {fx}... ",end="")
					self.ffx = self.ffx.replace("\"ca-app-pub","\"noads")
					self.success("FIXED")
					open(fx,"w").write(self.ffx)
	def removeAds4(self):
		for x in self.smalidir:
			self.f_ls = subprocess.run(f"find {x}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			self.f_ls = list(filter(lambda x: not x.startswith(".") and x.strip() != "", self.f_ls))
			for fx in self.f_ls:
				if os.path.isfile(fx) and "/ads/" in fx and fx.endswith(".smali"):
					self.ffx = open(fx,"r").read()
					self.readperline = self.ffx.strip().split(endl)
					while "" in self.readperline:
						self.readperline.remove("")
					self.modifiedsourcefile = ""
					for rpl_iterx in self.readperline:
						if "invoke" in rpl_iterx:
							for rpl_itery in strmatch["adloader"]:
								if rpl_itery in rpl_iterx:
									if rpl_iterx.strip().endswith(")V"):
										print("*"*int(system("tput cols")))
										self.success(f"[+] Patch (invoke~()V): {fx}")
										self.warning(rpl_iterx)
										rpl_iterx = rpl_iterx.replace(rpl_iterx.strip(),"invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()V")
										self.success(rpl_iterx)
									elif rpl_iterx.strip().endswith(")Z"):
										print("*"*int(system("tput cols")))
										self.success(f"[+] Patch (invoke~()Z): {fx}")
										self.warning(rpl_iterx)
										rpl_iterx = rpl_iterx.replace(rpl_iterx.strip(),"invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()Z")
										self.success(rpl_iterx)
						elif "const-string-still-fix-issue" in rpl_iterx:
							print(f"\x1b[1;92m[+] Patch (const-string): {fx}... \x1b[0m")
							self.constvar = re.findall(r"const-string\s(v[0-9]+|p[0-9]+),\s\"(.*?)\"", rpl_iterx)[0][0]
							rpl_iterx = rpl_iterx.replace(rpl_iterx.strip(),f"const-string {self.constvar}, \"null\"")
						self.modifiedsourcefile += rpl_iterx+endl
					open(fx,"w").write(self.modifiedsourcefile)
					self.ismodified = True
		if self.ismodified: self.writeNeutralize()
	def removeNop(self):
		for x in self.smalidir:
			self.f_ls = subprocess.run(f"find {x}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			self.f_ls = list(filter(lambda x: not x.startswith("."), self.f_ls))
			for fx in self.f_ls:
				if os.path.isfile(fx) and fx.endswith(".smali"):
					self.ffx = open(fx,"r").read()
					# Read Per Line
					self.rpl = self.ffx.strip().split("\n")
					while "" in self.rpl: self.rpl.remove("")
					self.modifiedsourcefile = ""
					for rpl_i in self.rpl:
						if rpl_i.strip() != "nop":
							self.modifiedsourcefile += rpl_i+endl
					open(fx,"w").write(self.modifiedsourcefile)
	def removeUnknown(self):
		self.unknown = self.fout+"/unknown"
		if os.path.isdir(self.fout+"/unknown"):
			os.system(f"rm -rf {self.unknown}")
	def customFont(self):
		fontPath = input("+++++ fontfile: ")
		if os.path.isfile(fontPath):
			# Generate user font hash
			fontHash = hashlib.md5(open(fontPath,"rb").read()).hexdigest()
			self.f_ls = subprocess.run(f"find {self.fout}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			# Remove empty item
			self.f_ls = list(filter(lambda x: x != "", self.f_ls))
			# Filter: If item ends with ".ttf" only
			self.f_ls = list(filter(lambda x: x.endswith(".ttf"), self.f_ls))
			# Filter: If user font hash is different with item hash only
			self.f_ls = list(filter(lambda x: hashlib.md5(open(x,"rb").read()).hexdigest() != fontHash, self.f_ls))
			# Copy self.f_ls for other task
			tmp_fls = self.f_ls
			# Map: Make copy of user font to each destination found
			list(map(lambda x: __import__("shutil").copyfile(fontPath,x),self.f_ls))
			# Print all item, stdout
			list(map(lambda x: self.warning(x),tmp_fls))
	def bypassCopyProtection(self):
		# Retrieve list of files pertains to copy protection
		self.f_ls = list(protection["copy"])
		# Map: Rename item, starts with directoryName
		self.f_ls = list(map(lambda x: self.fout+"/"+x,self.f_ls))
		# Filter: If file exists only
		self.f_ls = list(filter(lambda x: os.path.exists(x),self.f_ls))
		if len(self.f_ls) > 0: self.success("+++++ appcloner copy protection detected")
		# Copy self.f_ls for other task
		tmp_fls = self.f_ls
		# Delete all files that linked to copy protection
		list(map(lambda x: os.system(f"rm -rf \"{x}\""),self.f_ls))
		# Print all item, stdout
		list(map(lambda x: self.warning(x),tmp_fls))
		# Check all possible protections smali code
		self.f_ls = list(filter(lambda x: x[0].startswith(self.fout+"/smali"), list(__import__("itertools").permutations(self.smalidir+["andhook","com/applisto","com/swift/sandhook"], 2))))
		self.f_ls = list(map(lambda x: "/".join(x), self.f_ls))
		self.f_ls = list(filter(lambda x: os.path.isdir(x), self.f_ls))
		tmp_fls = self.f_ls
		list(map(lambda x: os.system(f"rm -rf \"{x}\""),self.f_ls))
		list(map(lambda x: self.warning(x),tmp_fls))
		# SENSITIVE: Remove all smali file that make an invoke to com/applisto
		for iterx in self.smalidir:
			self.f_ls = subprocess.run(f"find {iterx}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			self.f_ls = list(filter(lambda x: x.endswith(".smali"), self.f_ls))
			self.f_ls = list(filter(lambda x: "com/applisto" in open(x,"r").read(), self.f_ls))
			tmp_fls = self.f_ls
			list(map(lambda x: os.system(f"rm -rf \"{x}\""), self.f_ls))
			list(map(lambda x: self.warning(x), tmp_fls))
		# Clean apktool.yml
		self.f_ls = list(filter(lambda x: not "com/applisto" in x, open(self.fout+"/apktool.yml","r").read().split(self.endl)))
		self.f_ls = list(filter(lambda x: x.strip() != "", self.f_ls))
		open(self.fout+"/apktool.yml","w").write("\012".join(self.f_ls))
		# Remove leftover from AndroidManifest.xml
		# Try 1: Using regex
		reg = re.findall(r"(<.*? android:name=\"com.applisto.appcloner.*?/>)", self.manifestxml)
		for iterx in reg:
			self.warning(iterx)
			self.manifestxml = self.manifestxml.replace(iterx,"")
		# Try 2: Iterate and filter through each lines
		cpmanifest = list(filter(lambda x: x.strip() != "", self.manifestxml.strip().split(self.endl)))
		isreceiver = False
		self.manifestxml = ""
		for iterx in cpmanifest:
			iterz = iterx.strip()
			if iterz.startswith("<receiver android:name=\"com.applisto"):
				self.warning(iterx)
				isreceiver = True
			elif iterz.startswith("</receiver>"):
				isreceiver = False
			elif not isreceiver:
				self.manifestxml += iterx+self.endl
		self.writeManifestXML()
	def removeProperties(self):
		# List Files and Filter Filename Ends With (.properties)
		self.f_ls = subprocess.run(f"find {self.fout}/unknown/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
		self.f_ls = list(filter(lambda x: x.endswith(".properties"), self.f_ls))
		self.f_ls = list(filter(lambda x: os.path.isfile(x), self.f_ls))
		fls_name = list(map(lambda x: x.split("/")[-1], self.f_ls))
		tmp_fls = self.f_ls
		# Remove all .properties files
		list(map(lambda x: os.system(f"rm -rf \"{x}\""), self.f_ls))
		list(map(lambda x: self.warning(x), tmp_fls))
		# Clean apktool.yml
		self.f_ls = open(self.fout+"/apktool.yml","r").read().split(self.endl)
		self.f_ls = list(filter(lambda x: x.strip() != "", self.f_ls))
		tmp_fls = []
		self.modifiedsourcefile = ""
		for iterx in self.f_ls:
			isProperty = False
			isPropertyName = None
			for iterz in fls_name:
				itery = iterx.strip()
				if itery.startswith(iterz):
					isProperty = True
					isPropertyName = iterx
					break
			if isProperty:
				tmp_fls.append(isPropertyName)
			else:
				self.modifiedsourcefile += iterx+self.endl
		list(map(lambda x: self.warning(x), tmp_fls))
		open(self.fout+"/apktool.yml","w").write(self.modifiedsourcefile)
	def removeSetsecure(self):
		print("Still working on")
	###



helpbanner = """     __ __   __              
 ,__|  |  |_|  |___ __ __
 |  _  |   _|  |___|_ ` _| author: Gameye98 (1.0-dev)
 |_____|____|__|   |__.__| APK REVERSER & PATCHER

--rmads1: target=AndroidManifest.xml,replace=com.google.android.gms.ad
--rmads2: No Internet (remove the required permission to do so)
--rmads3: Search using regex and replace string ("ca-app-pub) with ("noads)
--rmads4: (Powerful) Disable all kind of ads loader base on the dictionary list
--rmnop: Remove all nop instruction found on the smali file
--rmunknown: Remove all unknown files (.properties, etc)
--customfont: Update and replace all font files with user recommended file
--rmcopy: Bypass AppCloner Copy Protection
--rmprop: Remove only .properties file
"""
mainbanner = """                                                  
\x1b[1;92m@@@@@@@   @@@@@@@  @@@                  @@@  @@@  \x1b[0m
\x1b[1;92m@@@@@@@@  @@@@@@@  @@@                  @@@  @@@  \x1b[0m
\x1b[1;92m@@!  @@@    @@!    @@!                  @@!  !@@  \x1b[0m
\x1b[1;92m!@!  @!@    !@!    !@!                  !@!  @!!  \x1b[0m
\x1b[1;92m@!@  !@!    @!!    @!!       @!@!@!@!@   !@@!@!   \x1b[0m
\x1b[1;92m!@!  !!!    !!!    !!!       !!!@!@!!!    @!!!    \x1b[0m
\x1b[1;92m!!:  !!!    !!:    !!:                   !: :!!   \x1b[0m
\x1b[1;92m:!:  !:!    :!:     :!:                 :!:  !:!  \x1b[0m
\x1b[1;92m :::: ::     ::     :: ::::              ::  :::  \x1b[0m
\x1b[1;92m:: :  :      :     : :: : :              :   ::   \x1b[0m

\x1b[1;41;93mAPK REVERSER & PATCHER - author by Gameye98 (BHSec)\x1b[0m
"""
strmatch = {
	"adloader": (
		"loadAd",
		"load",
		"show",
		"loadAdFromBid",
		"loadAds",
		"requestBannerAd",
		"requestInterstitialAd",
		"showInterstitial",
		"isLoading",
		"addView",
		"loadUrl",
		"loadDataWithBaseURL",
		"hasVideoContent",
		"loadData",
		"showVideo",
		"showAd",
		"loadBannerAd",
		"loadInterstitialAd",
		"loadNativeAd"
	)
}

protection = {
	"copy": (
		"__launcher_icon.png",
		"assets/app_cloner_branding.png",
		"assets/natives_sec_blob.dat",
		"unknown/andhook",
		"unknown/com/applisto",
		"lib/arm64-v8a/libappcloner.so",
		"lib/arm64-v8a/libsandhook-native.so",
		"lib/arm64-v8a/libsandhook.so",
		"lib/armeabi-v7a/libappcloner.so",
		"lib/armeabi-v7a/libsandhook-native.so",
		"lib/armeabi-v7a/libsandhook.so"
	)
}
kamusregex = (
	("matchall_invoke","(invoke-.*\s\{.*\},\s)"),
	("matchall_conststring","const-string\s(v[0-9]),\s\"(.*?)\"")
)

neutralize = """.class public Lsec/blackhole/dtlx/Schadenfreude;
.super Ljava/lang/Object;
.source "Schadenfreude"

.method public static neutralize()V
    .locals 0
    return-void
.end method

.method public static neutralize()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
"""

def system(cmd):
	try:
		sysExec = subprocess.run(cmd,shell=True,check=True,stdout=subprocess.PIPE).stdout.decode()
		return sysExec
	except Exception as e:
		print(e)
		return None

def main():
	print(mainbanner)
	global isconsole
	c = 0
	p = sys.argv
	p.remove(p[0])
	if len(p) >= 2:
		funcls = []
		ftarget = p[-1]
		if os.path.isfile(ftarget):
			p = p[0:len(p)-1]
		else:
			print(helpbanner)
			return None
		for px in p:
			if px == "--rmads1":
				funcls.append("rmads1")
			elif px == "--rmads2":
				funcls.append("rmads2")
			elif px == "--rmads3":
				funcls.append("rmads3")
			elif px == "--rmads4":
				funcls.append("rmads4")
			elif px == "--rmnop":
				funcls.append("rmnop")
			elif px == "--rmunknown":
				funcls.append("rmnown")
			elif px == "--customfont":
				funcls.append("customfont")
			elif px == "--rmcopy":
				funcls.append("rmcopy")
			elif px == "--rmprop":
				funcls.append("rmprop")
		patcher(ftarget,funcls)

if __name__ == "__main__":
	if len(sys.argv) >= 2:
		main()
	else:
		print(helpbanner)