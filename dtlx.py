#!/usr/bin/python3
import os, sys, re
import random, json
import hashlib, glob
import shutil
import subprocess
import readline, copy
import progressbar
import xml.etree.ElementTree as et
from assets.dexRepair import repair_dex, DexRepairError

endl = "\012"
civis = lambda: os.system("tput civis")
cnorm = lambda: os.system("tput cnorm")
cols = os.get_terminal_size().columns
loading = ["|","/","-","\\"]
dtlxhistory = ".dtlx_history"
ascii_letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ascii_letters = [x for x in ascii_letters]

def rnd_wordlist():
	with open("randomlist.txt","r") as f:
		contents = f.read().splitlines()
		contents = list(map(lambda x: x.strip(), contents))
		return contents

def randomid():
	randomstr = ""
	while len(randomstr) < 6:
		randomstr += str(random.choice(list(range(0,10))))
	return randomstr

def randomletters():
	randomstr = ""
	while len(randomstr) < 6:
		randomstr += str(random.choice(ascii_letters))
	return randomstr

def delete_recursively(path):
	if os.path.exists(path):
		if os.path.isdir(path):
			for i in glob.iglob(path+"/**", include_hidden=True):
				delete_recursively(i)
		if os.path.isdir(path):
			os.rmdir(path)
			print(f"\x1b[1;94mdelete folder '{path}'\x1b[0m")
		else:
			os.remove(path)
			print(f"\x1b[1;93mdelete file '{path}'\x1b[0m")

def check_class(dexfile, classname):
	data = os.popen(f"dexdump -d {dexfile} | grep -A 1000 \"{classname}\"").read()
	if data.strip() == "":
		return None
	return data

def respath(project_name, engine):
	if engine == "apktool":
		return project_name+"/res"
	ls = list(glob.iglob("**/res", recursive=True))
	ls = list(filter(lambda x: x.startswith(project_name+"/resources"), ls))
	return ls[0]

def parse_smali_head(contents):
	"""
	Extracts general information like the class name, the implemented interfaces,
	and whether the class actually represents an interface from a Smali file.
	"""
	CLASS_PATTERN = re.compile(r"\.class(?P<keywords>.+)? L(?P<name>[^\s]+);")
	IMPLEMENTS_PATTERN = re.compile(r"\.implements L(?P<name>[^\s]+);")
	class_match = CLASS_PATTERN.search(contents)
	class_groups = class_match.groupdict() if class_match else {}
	implements_matches = IMPLEMENTS_PATTERN.finditer(contents)
	implemented_interfaces = [match.group("name") for match in implements_matches]
	keywords = class_groups.get("keywords", "")
	is_interface = "interface" in keywords.strip().split() if keywords else False
	return {
		"name": class_groups.get("name"),
		"implements": implemented_interfaces,
		"isInterface": is_interface,
	}

def finditem(dataset, kw, val):
	value = None
	for k, v in enumerate(dataset):
		if kw in v.keys():
			if v[kw] == val:
				return [v[kw], True]
			value = v[kw]
	return [value, False]

class patcher:
	def __init__(self, fin, args,patchfile=None):
		self.endl = "\012"
		self.isneutralize = False
		self.ismodified = False
		self.isclean = False
		self.iscompile = True
		self.fin = fin
		self.patchfile = patchfile
		#if not os.path.isfile(self.fin):
			#raise FileNotFoundError(f"{self.fin}: No such file or directory")
		self.isproject = False
		if os.path.isfile(self.fin):
			with open(self.fin, "rb") as f:
				stream = f.read()
				if stream[0:4] != b"PK\x03\x04":
					raise FileNotFoundError(f"dtlx: '{self.fin}': Not detected as an APK")
		elif os.path.isdir(self.fin):
			while self.fin.endswith("/"):
				self.fin = self.fin[0:len(self.fin)-1]
			if not os.path.isdir(self.fin+"/smali"):
				raise FileNotFoundError(f"dtlx: '{self.fin}': Not detected as a project because of the missing 'smali' directory")
			self.isproject = True
		self.fnm = fin.split("/")[-1] if "/" in fin else fin
		self.fout = self.fnm
		if not self.isproject:
			# isselfout = False
			if self.fout.endswith(".apk"):
				self.fout = self.fout[0:len(self.fout)-4]
			else:
				self.fout = self.fout+".out"
				# isselfout = True
			# if isselfout:
			while os.path.isdir(self.fout):
				self.fout = self.fout+".out"
		self.raw = self.fout
		if not self.isproject:
			# Decompile APK file
			print("\x1b[92m+++++ Decompile APK into Project\x1b[0m")
			os.system(f"java -jar apkeditor.jar d -i {self.fin} -o {self.fout}")
			self.manifestxml = open(f"{self.fout}/AndroidManifest.xml","r").read()
			## Fixing bug where the manifest copy content itself many times
			#if len(self.manifestxml.split("</manifest>")) > 1:
				#self.manifestxml = self.manifestxml.split("</manifest>")[0]+"</manifest>"
		# decom_ng
		# 0 -> apktool
		# 1 -> apkeditor
		self.decom_ng = 1
		if os.path.isfile(f"{self.fout}/archive-info.json") and os.path.isdir(f"{self.fout}/smali/classes"):
			self.decom_ng = 1
			self.smalidir = list(glob.iglob(f"{self.fout}/smali/*"))
		else:
			self.decom_ng = 0
			self.smalidir = list(filter(lambda x: x.startswith("smali"), os.listdir(self.fout)))
			self.smalidir = list(map(lambda x: self.fout+"/"+x, self.smalidir))
		self.args = args
		# Remove split apks attribute from AndroidManifest.xml
		self.cleanSplitApks()
		for args_iter in self.args:
			# Switch Operator
			if args_iter=="rmads1":self.removeAds1()
			elif args_iter=="rmads2":self.removeAds2()
			elif args_iter=="rmads3":self.removeAds3()
			elif args_iter=="rmads4":self.removeAds4()
			elif args_iter=="rmads5":self.removeAds5()
			elif args_iter=="rmnop":self.removeNop()
			elif args_iter=="rmnown":self.removeUnknown()
			elif args_iter=="customfont":self.customFont()
			elif args_iter=="rmcopy":self.removeCopyProtection()
			elif args_iter=="rmprop":self.removeProperties()
			elif args_iter=="rmtrackers":self.removeTrackers()
			elif args_iter=="cleanrun":self.isclean=True
			elif args_iter=="nokill":self.nokill()
			elif args_iter=="findstr":self.findstr()
			elif args_iter=="paidkw":self.paidkw()
			elif args_iter=="nocompile":self.iscompile=False
			elif args_iter=="patch":self.patchApp()
			elif args_iter=="rmpairip":self.removePairip()
			elif args_iter=="bppairip":self.bypassPairip()
			elif args_iter=="rmvpndet":self.removeSmaliByRegex(regex_for_vpn_detection)
			elif args_iter=="rmusbdebug":self.removeSmaliByRegex(regex_for_usb_debugging)
			elif args_iter=="rmssrestrict":self.removeSmaliByRegex(regex_for_screenshot_restriction_removal)
			elif args_iter=="rmrootxposedvpn":self.removeSmaliByRegex(regex_for_root_xposed_and_vpn_removal)
			elif args_iter=="sslbypass":self.simpleSslBypass()
			elif args_iter=="rmexportdata":self.removeExportDataNotification()
			elif args_iter=="fixinstall":self.removeSmaliByRegex(regex_for_fix_installer)
			elif args_iter=="il2cppdumper":self.il2cppdumper()
			elif args_iter=="obfuscatemethods":self.obfuscateMethods()
			elif args_iter=="mergeobb":self.mergeObb()
			elif args_iter=="injectdocsprovider":self.injectDocumentsProvider()
			elif args_iter=="changeactivity":self.changeActivity()
			elif args_iter=="changepackagename":self.changePkgName()
			elif args_iter=="cloneapk":self.cloneApk()
		# Compile Project
		if self.iscompile:
			if os.path.isdir(f"{self.fout}/resources"):
				self.compilecmd = f"java -jar apkeditor.jar b -i {self.fout} -o {self.fout}_dtlx.apk"
				self.compiled = f"{self.fout}_dtlx.apk"
			elif os.path.isdir(f"{self.fout}/res"):
				self.compilecmd = f"java -jar apktool-v2.9.3.jar b -f --use-aapt2 -a assets/aapt2 -d {self.fout}"
				self.compiled = f"{self.fout}/dist/{self.fout}.apk"
			else:
				raise FileNotFoundError(f"dtlx: '{self.fout}': Not identified as project directory because of the missing resource directory")
			print("\x1b[92m+++++ Compile Project into APK\x1b[0m")
			os.system(self.compilecmd)
			print("\x1b[1;92m[+] Signing APK file... \x1b[0m",end="")
			os.system(f"apksigner sign --ks assets/testkey.keystore --ks-key-alias testkey --ks-pass pass:android {self.compiled}")
			print("\x1b[1;92mOK\x1b[0m")
			print("\x1b[1;92m[+] Verifying APK file.... \x1b[0m",end="")
			os.system(f"apksigner verify {self.compiled}")
			print("\x1b[1;92mOK\x1b[0m")
			self.signed = self.compiled
			if self.signed.endswith(".apk"):
				self.signed = self.signed[0:len(self.signed)-4]+"_sign.apk"
			else:
				self.signed = self.signed+"_sign.apk"
			self.signed = whereapkfrom() + "/" + self.signed
			shutil.copy(self.compiled, self.signed)
			os.remove(self.compiled)
			print("✅ Success! The file has been generated.")
			print(f"📂 Location: {self.signed}")
		# Delete Project if isclean = True
		if self.isclean: os.system(f"rm -rf {self.fout}")
	def values(self, typename, attribname, val):
		resdir = respath(self.fout, "apktool" if self.decom_ng == 0 else "apkeditor")
		destdir = resdir+"/"+typename
		if not os.path.isdir(destdir):
			os.mkdir(destdir)
		# Modify res/values/public.xml
		tree = et.parse(resdir+"/values/public.xml")
		root = tree.getroot()
		isexists = any(list(filter(lambda x: x.attrib.get("type").strip() == typename and x.attrib.get("name") == attribname, root)))
		if isexists:
			return
		lasthex = list(map(lambda x: x.attrib.get("id"), root))
		#lasthex = hex(int(lasthex[-1], 16) + 65536)
		lasthex = hex(int(lasthex[-1], 16) + 1)
		element = et.Element("public", attrib={
			"id": lasthex,
			"type": typename,
			"name": attribname
		})
		root.append(element)
		updatedxml = et.tostring(root, encoding="unicode", method="xml")
		with open(resdir+"/values/public.xml","w") as f:
			f.write(updatedxml)
		typename = ""
		if typename == "raw":
			tree = et.parse(resdir+"/values/raws.xml")
			root = tree.getroot()
			isexists = any(list(filter(lambda x: x.attrib.get("name") == attribname, root)))
			if isexists:
				return
			element = et.Element("raw", attrib={
				"name": attribname,
			})
			element.text = val
			root.append(element)
			updatedxml = et.tostring(root, encoding="unicode", method="xml")
			with open(resdir+"/values/raws.xml","w") as f:
				f.write(updatedxml)
	def warning(self,content):
		print(f"\x1b[1;41;93m{content}\x1b[0m")
		__import__("time").sleep(0.1)
	def success(self,content):
		print(f"\x1b[1;92m{content}\x1b[0m")
		__import__("time").sleep(0.1)
	def writeManifestXML(self):
		if len(self.manifestxml.split("</manifest>")) > 1:
			self.manifestxml = self.manifestxml.split("</manifest>")[0]+"</manifest>"
		open(self.fout+"/AndroidManifest.xml","w").write(self.manifestxml)
	def writeNeutralize(self):
		if not self.isneutralize:
			if self.decom_ng == 0:
				os.system(f"mkdir -p {self.fout}/smali/sec/blackhole/dtlx")
				with open(self.fout+"/smali/sec/blackhole/dtlx/Schadenfreude.smali","w") as f:
					f.write(neutralize)
					self.isneutralize = True
			elif self.decom_ng == 1:
				os.system(f"mkdir -p {self.fout}/smali/classes/sec/blackhole/dtlx")
				with open(self.fout+"/smali/classes/sec/blackhole/dtlx/Schadenfreude.smali","w") as f:
					f.write(neutralize)
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
					self.success(f"[+] Found (\"ca-app-pub): {fx}... ")
					self.ffx = self.ffx.replace("\"ca-app-pub","\"noads")
					self.success("FIXED")
					open(fx,"w").write(self.ffx)
	def removeAds4(self):
		for x in self.smalidir:
			# self.f_ls = subprocess.run(f"find {x}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			# self.f_ls = list(filter(lambda x: not x.startswith(".") and x.strip() != "", self.f_ls))
			self.f_ls = list(glob.iglob(f"{x}/**/*.smali",recursive=True))
			for fx in self.f_ls:
				if os.path.isfile(fx) and fx.endswith(".smali"):
					self.ffx = open(fx,"r").read()
					self.readperline = self.ffx.strip().split(endl)
					while "" in self.readperline:
						self.readperline.remove("")
					self.modifiedsourcefile = ""
					for rpl_iterx in self.readperline:
						if "invoke" in rpl_iterx and "gms" in rpl_iterx:
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
	def removeAds5(self):
		for x in self.smalidir:
			self.f_ls = subprocess.run(f"find {x}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			self.f_ls = list(filter(lambda x: not x.startswith(".") and x.strip() != "", self.f_ls))
			self.f_ls = list(filter(lambda x: os.path.isfile(x) and x.endswith(".smali"), self.f_ls))
			for fx in self.f_ls:
				self.ffx = open(fx,"r").read()
				if "\"ca-app-pub" in self.ffx:
					ca_id = re.findall(r"(ca\-app\-pub\-[0-9][0-9][0-9][0-9])", self.ffx)
					for i in ca_id: 
						print("\x1b[1;41;93m[+] Found (\"ca-app-pub): {fx}... \x1b[0m",end="")
						self.ffx = self.ffx.replace(i,"ca-app-pub-0000")
						self.success("FIXED")
					open(fx,"w").write(self.ffx)
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
		readline.write_history_file(dtlxhistory)
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
	def removeCopyProtection(self):
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
	def removeTrackers(self):
		class_list = copy.deepcopy(trackers)
		class_orig = copy.deepcopy(class_list)
		class_list = list(map(lambda x: x[1], class_list))
		for smalixdir in self.smalidir:
			for class_name in class_list:
				if os.path.isdir(smalixdir+"/"+class_name.replace(".","/")):
					os.system(f"rm -rf {smalixdir}/"+class_name.replace(".","/"))
		# check AndroidManifest.xml
		manifestxml = open(f"{self.fout}/AndroidManifest.xml","r").read()
		class_xml = []
		for class_name in class_list:
			if class_name in manifestxml:
				class_xml.append(class_name)
		class_list = copy.deepcopy(class_xml)
		if len(class_list) == 0:
			print("\x1b[1;93mNo known trackers detected\x1b[0m")
		else:
			print("\x1b[1;92mDetected:\x1b[0m")
			for class_name in class_list:
				print(f"\x1b[1;92m ✓ {class_name}\x1b[0m")
		# new class_list with regex
		class_reg = []
		opcodes = ["move-result", "new-instance", "iget", "iput", "const-string"]
		for class_name in class_list:
			class_name = re.escape(class_name)
			class_reg.append([
				rf'.*invoke.*{class_name}.*\)Z',
				'invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()Ljava/lang/Object;'
			])
			class_reg.append([
				rf'.*invoke.*{class_name}.*\)V',
				'invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()V'
			])
			class_reg.append([
				rf'.*invoke.*{class_name}.*\)Ljava/lang/Object;',
				'invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()Z'
			])
			for opcode in opcodes:
				opcode = re.escape(opcode)
				class_reg.append([rf'.*{opcode}.*{class_name}.*',""])
		civis()
		for smalixdir in self.smalidir:
			self.f_ls = list(glob.iglob(f"{smalixdir}/**/*.smali",recursive=True))
			totalpbar = len(self.f_ls)
			counter = 0
			ldc = 0
			for file in self.f_ls:
				counter += 1
				print(f"\r\x1b[1;93m[{loading[ldc]}] scan dirs: {smalixdir} ({counter}/{totalpbar} files)\x1b[0m   ",end="")
				sys.stdout.flush()
				ldc += 1
				if ldc >= len(loading):
					ldc = 0
				smalicodes = open(file,"r").read()
				for regex in class_reg:
					reg = re.findall(regex[0],smalicodes)
					if len(reg) > 0:
						regtext = f"\x1b[1;94m[*] regex: {regex[0]}\x1b[0m"
						if len(regtext) < cols():
							print(regtext+" "*(cols()-len(regtext)))
						print(f"\x1b[1;92m[+] found: {file}\x1b[0m")
						smalicodes = re.sub(regex[0],regex[1],smalicodes)
						print(f"\x1b[1;41;93m[!] result: {reg[0]}\x1b[0m")
						print(f"\x1b[1;93m[~] replacement: '{regex[1]}'\x1b[0m\n")
						print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
				with open(file,"w") as sw:
					sw.write(smalicodes)
		cnorm()
		self.writeNeutralize()
		self.cleanManifest(class_name)
	def cleanSplitApks(self):
		manifestxml = open(self.fout+"/AndroidManifest.xml","r").read()
		rmattrbs = ["requiredSplitTypes", "splitTypes", "isSplitRequired"]
		for kw in rmattrbs:
			m = re.findall(rf'(android:{kw}\=\"(.*?)\")', manifestxml)
			if len(m) > 0 and len(m[0]) > 0:
				m = m[0][0]
			else:
				continue
			if m in manifestxml:
				print(f"\x1b[1;92m[+] remove \x1b[1;93m{m} \x1b[1;92mfrom AndroidManifest.xml... \x1b[0m",end="")
				manifestxml = manifestxml.replace(m, "")
				print("\x1b[1;93mOK\x1b[0m")
		with open(self.fout+"/AndroidManifest.xml","w") as f:
			f.write(manifestxml)
	def cleanManifest(self, targetClass):
		# Remove leftover from AndroidManifest.xml
		# Try 1: Using regex
		reg = re.findall(r"(<.*? android:name=\""+targetClass+".*?/>)", self.manifestxml)
		for iterx in reg:
			self.warning(iterx)
			self.manifestxml = self.manifestxml.replace(iterx,"")
		# Try 2: Using regex
		primarydata = {"meta-data","receiver","service"}
		cpmanifest = list(filter(lambda x: x.strip() != "", self.manifestxml.strip().split(self.endl)))
		isreceiver = False
		ismetadata = False
		isservice = False
		allmatch = []
		for xmltagi in primarydata:
			reg = re.findall(rf'(<{xmltagi}((.|\n|\r)*?)</{xmltagi}>)', self.manifestxml)
			if len(reg) != 0:
				allmatch.append([x[0] for x in reg])
		for regxi in allmatch:
			if targetClass in regxi:
				self.warning(regxi)
				self.manifestxml = self.manifestxml.replace(regxi,"")
		self.writeManifestXML()
	def nokill(self):
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
						isexitcalled = False
						for exiti in kamusexit:
							if exiti in rpl_i:
								self.warning(rpl_i)
								isexitcalled = True
								break
						if not isexitcalled: self.modifiedsourcefile += rpl_i+endl
					open(fx,"w").write(self.modifiedsourcefile)
	def findstr(self):
		texttofind = input("[*] Text to find: ")
		readline.write_history_file(dtlxhistory)
		self.searchresults = []
		for f in self.smalidir:
			f_ls = os.popen(f"find {f}/").read().splitlines()
			while "" in f_ls: f_ls.remove("")
			f_ls = list(map(lambda x: x.strip(), f_ls))
			f_ls = list(filter(lambda x: os.path.isfile(x), f_ls))
			totalpbar = len(f_ls)
			countpbar = 0
			print(f"\x1b[1;96m[*] Scan dirs: {f} ({totalpbar} files)\x1b[0m")
			pbar = progressbar.ProgressBar(totalpbar).start()
			civis()
			for fx in f_ls:
				countpbar += 1
				pbar.update(countpbar)
				with open(fx,"r") as smalifile:
					lines = [x.strip() for x in smalifile.read().splitlines()]
					classname = lines[0]
					ismethod = False
					methodname = None
					for line in lines:
						if line.startswith(".method"):
							methodname = line
							ismethod = True
						elif line.startswith(".end method"):
							ismethod = False
						else:
							if texttofind in line:
								if line.startswith(".field"):
									smaliobj = {}
									smaliobj.update({"class": classname})
									smaliobj.update({"path": fx})
									smaliobj.update({"line": lines.index(line)})
									smaliobj.update({"method": "None"})
									smaliobj.update({"code": line})
									self.searchresults.append(smaliobj)
								elif ismethod:
									smaliobj = {}
									smaliobj.update({"class": classname})
									smaliobj.update({"path": fx})
									smaliobj.update({"line": lines.index(line)})
									smaliobj.update({"method": methodname})
									smaliobj.update({"code": line})
									self.searchresults.append(smaliobj)
			pbar.finish()
			cnorm()
		outfile = f"{self.fnm}_findstring_{randomid()}.txt"
		with open(f"{self.fnm}_findstring_{randomid()}.txt", "w") as f:
			for k, v in enumerate(self.searchresults):
				pathfiletext = f"PathFile: {v['path']}"
				classnametext = f"ClassName: {v['class']}"
				methodnametext = f"MethodName: {v['method']}"
				linetext = f"Line: {v['line']}"
				codetext = f"{v['code']}"
				f.write(pathfiletext+"\n")
				f.write(classnametext+"\n")
				f.write(methodnametext+"\n")
				f.write(linetext+"\n")
				f.write("="*20+"\n")
				f.write(codetext+"\n")
				f.write("="*20+"\n\n")
				print(f"\x1b[1;92m{pathfiletext}\x1b[0m")
				print(f"\x1b[1;92m{classnametext}\x1b[0m")
				print(f"\x1b[1;92m{methodnametext}\x1b[0m")
				print(f"\x1b[1;92m{linetext}\x1b[0m")
				print(f"\x1b[1;41;93m{codetext}\x1b[0m\n")
		print("✅ Success! The file has been generated.")
		print(f"📂 Location: {outfile}")
	def paidkw(self):
		print(f"\x1b[1;41;93m[!] Total of {len(paidkeywords)} keywords loaded\x1b[0m")
		kwsplit = [keyword.split("|") if "|" in keyword else [keyword] for keyword in paidkeywords]
		self.searchkwresults = []
		for f in self.smalidir:
			f_ls = os.popen(f"find {f}/").read().splitlines()
			while "" in f_ls: f_ls.remove("")
			f_ls = list(map(lambda x: x.strip(), f_ls))
			f_ls = list(filter(lambda x: os.path.isfile(x), f_ls))
			totalpbar = len(f_ls)
			countpbar = 0
			print(f"\x1b[1;96m[*] Scan dirs: {f} ({totalpbar} files)\x1b[0m")
			pbar = progressbar.ProgressBar(totalpbar).start()
			civis()
			for fx in f_ls:
				countpbar += 1
				pbar.update(countpbar)
				if any([xxr in fx for xxr in ["/androidx/","/com/google/"]]):
					continue
				#print(f"\x1b[1;93m{fx}\x1b[0m")
				with open(fx,"r") as smalifile:
					lines = [x.strip() for x in smalifile.read().splitlines()]
					classname = lines[0]
					ismethod = False
					methodname = None
					for line in lines:
						if line.startswith(".method"):
							methodname = line
							ismethod = True
						elif line.startswith(".end method"):
							ismethod = False
						else:
							for keyword in kwsplit:
								if all(kwsx in line.lower() for kwsx in keyword):
									if line.startswith(".field"):
										smaliobj = {}
										smaliobj.update({"class": classname})
										smaliobj.update({"path": fx})
										smaliobj.update({"line": lines.index(line)})
										smaliobj.update({"method": "None"})
										smaliobj.update({"code": line})
										self.searchkwresults.append(smaliobj)
									elif ismethod:
										smaliobj = {}
										smaliobj.update({"class": classname})
										smaliobj.update({"path": fx})
										smaliobj.update({"line": lines.index(line)})
										smaliobj.update({"method": methodname})
										smaliobj.update({"code": line})
										self.searchkwresults.append(smaliobj)
			pbar.finish()
			cnorm()
		outfile = f"{self.fnm}_paidkeywords_{randomid()}.txt"
		with open(outfile, "w") as f:
			for k, v in enumerate(self.searchkwresults):
				pathfiletext = f"PathFile: {v['path']}"
				classnametext = f"ClassName: {v['class']}"
				methodnametext = f"MethodName: {v['method']}"
				linetext = f"Line: {v['line']}"
				codetext = f"{v['code']}"
				f.write(pathfiletext+"\n")
				f.write(classnametext+"\n")
				f.write(methodnametext+"\n")
				f.write(linetext+"\n")
				f.write("="*20+"\n")
				f.write(codetext+"\n")
				f.write("="*20+"\n\n")
				print(f"\x1b[1;92m{pathfiletext}\x1b[0m")
				print(f"\x1b[1;92m{classnametext}\x1b[0m")
				print(f"\x1b[1;92m{methodnametext}\x1b[0m")
				print(f"\x1b[1;92m{linetext}\x1b[0m")
				print(f"\x1b[1;41;93m{codetext}\x1b[0m\n")
		print("✅ Success! The file has been generated.")
		print(f"📂 Location: {outfile}")
	def patchApp(self):
		self.tmp_patchdir = os.getenv("PWD")+"/"+randomid()
		os.system(f"unzip -d {self.tmp_patchdir} {self.patchfile}")
		self.tmp_dexdir = os.getenv("PWD")+"/"+randomid()
		os.system(f"unzip -d {self.tmp_dexdir} {self.fin}")
		ls = os.listdir(self.tmp_patchdir)
		if not "patch.txt" in ls:
			print(f"\x1b[1;41;93m[!] dtlx: '{self.patchfile}': No patch.txt found\x1b[0m")
			return
		with open(self.tmp_patchdir+"/patch.txt") as f:
			content = f.read().splitlines()
			content = list(map(lambda x: x.strip(), content))
			content = list(filter(lambda x: x != "", content))
			isbegin = False
			isend = False
			isclasses = False
			isaddfile = False
			isdelfile = False
			isdelfolder = False
			isrenfile = False
			ispatchlib = False
			ismodify = False
			modifyfile = ""
			modifymatch = ""
			modifyreplace = ""
			srcfile = None
			dstfile = None
			bakfile = None
			for line in content:
				if line == "[BEGIN]":
					isbegin = True
				elif line == "[END]":
					isend = True
					isbegin = False
				elif isbegin:
					if line == "[ADD_FILE]":
						isaddfile = True
						isclasses = False
						isdelfile = False
						isdelfolder = False
						isrenfile = False
						ispatchlib = False
						ismodify = False
						srcfile = None
						dstfile = None
						bakfile = None
					elif line == "[DELETE_FILE_IN_APK]":
						isaddfile = False
						isclasses = False
						isdelfile = True
						isdelfolder = False
						isrenfile = False
						ispatchlib = False
						ismodify = False
						srcfile = None
						dstfile = None
						bakfile = None
					elif line == "[DELETE_FOLDER_IN_APK]":
						isaddfile = False
						isclasses = False
						isdelfile = False
						isdelfolder = True
						isrenfile = False
						ispatchlib = False
						ismodify = False
						srcfile = None
						dstfile = None
						bakfile = None
					elif line == "[RENAME_FILE_IN_APK]":
						isaddfile = False
						isclasses = False
						isdelfile = False
						isdelfolder = False
						isrenfile = True
						ispatchlib = False
						ismodify = False
						srcfile = None
						dstfile = None
						bakfile = None
					elif line == "[CLASSES]":
						isaddfile = False
						isclasses = True
						isdelfile = False
						isdelfolder = False
						isrenfile = False
						ispatchlib = False
						ismodify = False
						srcfile = None
						dstfile = None
						bakfile = None
					elif line == "[PATCHLIB]":
						isaddfile = False
						isclasses = False
						isdelfile = False
						isdelfolder = False
						isrenfile = False
						ispatchlib = True
						ismodify = False
						srcfile = None
						dstfile = None
						bakfile = None
					elif line == "[MODIFY]":
						isaddfile = False
						isclasses = False
						isdelfile = False
						isdelfolder = False
						isrenfile = False
						ispatchlib = False
						ismodify = True
						srcfile = None
						dstfile = None
						bakfile = None
					elif isaddfile:
						if all(char in line for char in ["{",":"]):
							try:
								data = json.loads(line)
								if not all([srcfile, dstfile]):
									if "file_name" in data:
										srcfile = data["file_name"]
										srcfile = self.tmp_patchdir+"/"+srcfile if srcfile.strip() != "" else None
									elif "to" in data:
										dstfile = data["to"]
										dstfile = self.tmp_dexdir+"/"+dstfile if dstfile.strip() != "" else None
								if all([srcfile, dstfile]):
									shutil.copy(srcfile, dstfile)
							except json.decoder.JSONDecodeError as e:
								print(f"\x1b[1;41;93m[!] dtlx: '{self.tmp_patchdir}/patch.txt': {e}\x1b[0m")
						else:
							self.patchstdout(line)
					elif isdelfile:
						if all(char in line for char in ["{",":"]):
							try:
								data = json.loads(line)
								if "file_name" in data:
									srcfile = data["file_name"]
									srcfile = self.tmp_dexdir+"/"+srcfile if srcfile.strip() != "" else None
								if srcfile:
									delete_recursively(srcfile)
							except json.decoder.JSONDecodeError as e:
								print(f"\x1b[1;41;93m[!] dtlx: '{self.tmp_patchdir}/patch.txt': {e}\x1b[0m")
						else:
							self.patchstdout(line)
					elif isdelfolder:
						if all(char in line for char in ["{",":"]):
							try:
								data = json.loads(line)
								if "folder_name" in data:
									srcfile = data["folder_name"]
									srcfile = self.tmp_dexdir+"/"+srcfile if srcfile.strip() != "" else None
								if srcfile:
									delete_recursively(srcfile)
							except json.decoder.JSONDecodeError as e:
								print(f"\x1b[1;41;93m[!] dtlx: '{self.tmp_patchdir}/patch.txt': {e}\x1b[0m")
						else:
							self.patchstdout(line)
					elif isrenfile:
						if all(char in line for char in ["{",":"]):
							try:
								data = json.loads(line)
								if not all([srcfile, dstfile]):
									if "file_name" in data:
										srcfile = data["file_name"]
										srcfile = self.tmp_dexdir+"/"+srcfile if srcfile.strip() != "" else None
									elif "to" in data:
										dstfile = data["to"]
										dstfile = self.tmp_dexdir+"/"+dstfile if dstfile.strip() != "" else None
								if all([srcfile, dstfile]):
									os.rename(srcfile, dstfile)
							except json.decoder.JSONDecodeError as e:
								print(f"\x1b[1;41;93m[!] dtlx: '{self.tmp_patchdir}/patch.txt': {e}\x1b[0m")
						else:
							self.patchstdout(line)
					elif isclasses:
						if all(char in line for char in ["{",":"]):
							try:
								data = json.loads(line)
								if not all([srcfile, dstfile]):
									if "class_name" in data:
										srcfile = data["class_name"]
										srcfile = srcfile if srcfile.strip() != "" else None
									elif "replaced" in data:
										dstfile = data["replaced"]
										dstfile = dstfile if dstfile.strip() != "" else None
								if all([srcfile, dstfile]):
									replaced = bytes.fromhex(dstfile.replace(" ",""))
									for dex in glob.iglob(self.tmp_dexdir+"/*.dex"):
										dexname = dex.split("/")[-1] if "/" in dex else dex
										classdata = check_class(dex, srcfile)
										offset = None
										if classdata:
											classdata = classdata.splitlines()
											classdata = list(map(lambda x: x.strip(), classdata))
											classdata = list(filter(lambda x: "|" in x, classdata))
											if len(classdata) < 2:
												continue
											offset = classdata[1]
											if not ":" in offset:
												continue
											offset = offset.strip().split(":")[0]
										if offset:
											with open(dex,"r+b") as bwrite:
												bwrite.seek(int(offset, 16))
												bwrite.write(replaced)
											self.patchstdout(f"write {replaced} to {dexname} @ {offset}")
							except json.decoder.JSONDecodeError as e:
								print(f"\x1b[1;41;93m[!] dtlx: '{self.tmp_patchdir}/patch.txt': {e}\x1b[0m")
						else:
							self.patchstdout(line)
					elif ispatchlib:
						if all(char in line for char in ["{",":"]):
							try:
								data = json.loads(line)
								if not all([srcfile, dstfile]):
									if "file_name" in data:
										srcfile = data["file_name"]
										srcfile = self.tmp_dexdir+"/"+srcfile if srcfile.strip() != "" else None
									elif "replaced" in data:
										dstfile = data["replaced"]
										dstfile = dstfile if dstfile.strip() != "" else None
									elif "offset" in data:
										bakfile = data["offset"]
										bakfile = bakfile if bakfile.strip() != "" else None
								if all([srcfile, dstfile, bakfile]):
									replaced = bytes.fromhex(dstfile.replace(" ",""))
									for dex in glob.iglob(self.tmp_dexdir+"/*.dex"):
										dexname = dex.split("/")[-1] if "/" in dex else dex
										classdata = check_class(dex, srcfile)
										offset = int(bakfile, 16)
										with open(dex,"r+b") as bwrite:
											bwrite.seek(offset)
											bwrite.write(replaced)
										self.patchstdout(f"write {replaced} to {dexname} @ {offset}")
							except json.decoder.JSONDecodeError as e:
								print(f"\x1b[1;41;93m[!] dtlx: '{self.tmp_patchdir}/patch.txt': {e}\x1b[0m")
						else:
							self.patchstdout(line)
				else:
					self.patchstdout(line)
		delete_recursively(self.tmp_patchdir)
		os.chdir(self.tmp_dexdir)
		outpatchfile = f"{self.fnm}.patch.apk"
		is_dex_repaired = False
		ls = os.listdir()
		ls = list(filter(lambda x: os.path.isfile(x) and x.endswith(".dex"), ls))
		for dex in ls:
			repaireddex = dex.replace(".dex","_repaired.dex")
			try:
				repair_dex(dex, output_dex_path=repaireddex)
				os.rename(repaireddex, dex)
				self.success(f"[+] {dex} is repaired")
			except DexRepairError as e:
				print(f"Error during DEX repair: {e}")
		is_dex_repaired = True
		os.system(f"zip -r {outpatchfile} .")
		os.rename(f"{outpatchfile}",os.getenv("PWD")+f"/{outpatchfile}")
		os.chdir("..")
		delete_recursively(self.tmp_dexdir)
		print("\x1b[1;92m[+] Signing PATCHED APK file... \x1b[0m",end="")
		os.system(f"apksigner sign --ks assets/testkey.keystore --ks-key-alias testkey --ks-pass pass:android {outpatchfile}")
		print("\x1b[1;92mOK\x1b[0m")
		print("\x1b[1;92m[+] Verifying PATCHED APK file.... \x1b[0m",end="")
		os.system(f"apksigner verify {outpatchfile}")
		print("\x1b[1;92mOK\x1b[0m")
		if not is_dex_repaired:
			print("\x1b[1;91m[!] REMEMBER TO REPAIR THE MODIFIED DEX IN PATCHED APK\x1b[0m")
		print(f"📂 Location: {outpatchfile}")
	def patchstdout(self,text):
		if text.strip().startswith("*"):
			print(f"\x1b[1;93m{text}\x1b[0m")
		elif text.strip().startswith("#"):
			print(f"\x1b[1;94m{text}\x1b[0m")
		elif text.strip().startswith("?"):
			print(f"\x1b[1;95m{text}\x1b[0m")
		elif text.strip().startswith("&"):
			print(f"\x1b[1;96m{text}\x1b[0m")
		elif text.strip().startswith("~"):
			print(f"\x1b[1;97m{text}\x1b[0m")
		elif text.strip().startswith("@"):
			print(f"\x1b[1;91m{text}\x1b[0m")
		elif text.strip().startswith("!"):
			print(f"\x1b[1;41;93m{text}\x1b[0m")
		else:
			print(f"\x1b[1;92m{text}\x1b[0m")
	def removePairip(self):
		print("\x1b[1;92m[+] Remove Pairip\x1b[0m")
		civis()
		for f in self.smalidir:
			f_ls = list(glob.iglob(f"{f}/**/*.smali", recursive=True))
			totalpbar = len(f_ls)
			print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
			counter = 0
			pbar = progressbar.ProgressBar(totalpbar).start()
			for file in f_ls:
				counter += 1
				pbar.update(counter)
				smalicodes = open(file,"r").read()
				for regex in regex_for_pairip:
					reg = re.findall(regex[0],smalicodes)
					if len(reg) > 0:
						regtext = f"\x1b[1;94m[*] regex: {regex[0]}\x1b[0m"
						if len(regtext) < cols():
							print(regtext+" "*(cols()-len(regtext)))
						print(f"\x1b[1;92m[+] found: {file}\x1b[0m")
						smalicodes = re.sub(regex[0],regex[1],smalicodes)
						print(f"\x1b[1;41;93m[!] result: {reg[0]}\x1b[0m")
						print(f"\x1b[1;93m[~] replacement: '{regex[1]}'\x1b[0m\n")
						print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
				with open(file,"w") as sw:
					sw.write(smalicodes)
			pbar.finish()
			cnorm()
		# change the class back to the default
		pairip_application = list(glob.iglob(f"{self.fout}/smali/**/com/pairip/application/Application.smali"))
		if len(pairip_application) == 0:
			print(f"\x1b[1;41;93m[!] dtlx: 'com.pairip.application.Application' is not detected\x1b[0m")
			return
		pairip_application = open(pairip_application[0],"r").read().splitlines()
		pairip_application = list(map(lambda x: x.strip(), pairip_application))
		while "" in pairip_application: pairip_application.remove("")
		classname = list(filter(lambda x: x.startswith(".super"), pairip_application))[0]
		classname = classname.split()[1][1:]
		while classname.endswith(";"):
			classname = classname[0:len(classname)-1]
		classname = classname.replace("/",".")
		manifest = open(self.fout+"/AndroidManifest.xml","r").read()
		reg = re.findall(r'".*pairip.*"', manifest)
		for m in reg:
			print(f"\x1b[1;92m[+] update AndroidManifest.xml ({m} => \"{classname}\")\x1b[0m")
			manifest = manifest.replace(m, f"\"{classname}\"")
		with open(f"{self.fout}/AndroidManifest.xml","w") as f:
			f.write(manifest)
		# remove pairip classes from dex
		for f in glob.iglob(f"{self.fout}/smali/**/com/pairip",recursive=True):
			delete_recursively(f)
		# remove pairip shared object library
		for f in glob.iglob(f"{self.fout}/**/lib/**/libpairipcore.so",recursive=True):
			print(f"\x1b[1;92m[+] remove {f}\x1b[0m")
			os.remove(f)
		self.writeNeutralize()
	def removeSmaliByRegex(self, regexList):
		civis()
		for smalixdir in self.smalidir:
			self.f_ls = list(glob.iglob(f"{smalixdir}/**/*.smali",recursive=True))
			totalpbar = len(self.f_ls)
			counter = 0
			ldc = 0
			for file in self.f_ls:
				counter += 1
				print(f"\r\x1b[1;93m[{loading[ldc]}] scan dirs: {smalixdir} ({counter}/{totalpbar} files)\x1b[0m   ",end="")
				sys.stdout.flush()
				ldc += 1
				if ldc >= len(loading):
					ldc = 0
				smalicodes = open(file,"r").read()
				for regex in regexList:
					reg = re.findall(regex[0],smalicodes)
					if len(reg) > 0:
						regtext = f"\x1b[1;94m[*] regex: {regex[0]}\x1b[0m"
						if len(regtext) < cols():
							print(regtext+" "*(cols()-len(regtext)))
						print(f"\x1b[1;92m[+] found: {file}\x1b[0m")
						smalicodes = re.sub(regex[0],regex[1],smalicodes)
						print(f"\x1b[1;41;93m[!] result: {reg[0]}\x1b[0m")
						print(f"\x1b[1;93m[~] replacement: '{regex[1]}'\x1b[0m\n")
						print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
				with open(file,"w") as sw:
					sw.write(smalicodes)
			print()
		cnorm()
		self.writeNeutralize()
	def bypassSSL(self):
		print("\x1b[1;92m[+] Bypass SSL Pinning\x1b[0m")
		patchedsmali = []
		for f in self.smalidir:
			f_ls = list(glob.iglob(f"{f}/**/*.smali", recursive=True))
			totalpbar = len(f_ls)
			print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
			counter = 0
			civis()
			pbar = progressbar.ProgressBar(totalpbar).start()
			for file in f_ls:
				counter += 1
				pbar.update(counter)
				smalicodes = open(file,"r").read()
				lines = [x.strip() if x.strip()=="" else x for x in smalicodes.splitlines()]
				if " interface " in lines[0]:
					continue
				for reg in regex_for_ssl_pinning:
					escaped_signature = re.escape(reg[0])
					pattern = re.compile(rf"(\.method public (?:final )?{escaped_signature})\n([\s\S]+?)\n(\.end method)", re.MULTILINE)
					matches = pattern.findall(smalicodes)
					for match in matches:
						smalicodes = smalicodes.replace(match[0],reg[1])
						patchedsmali.append(file)
			pbar.finish()
			cnorm()
		patchedsmali = list(set(patchedsmali))
		for i in patchedsmali:
			print("patch", i)
		print("\x1b[1;92m[+] \x1b[1;97mModifying AndroidManifest.xml... \x1b[0m",end="")
		manifest = open(self.fout+"/AndroidManifest.xml","r").read()
		# Check for android:usesCleartextTraffic="true"
		if "android:usesCleartextTraffic" in manifest:
			if "android:usesCleartextTraffic=\"false\"" in manifest:
				manifest = manifest.replace("android:usesCleartextTraffic=\"false\"","android:usesCleartextTraffic=\"true\"")
		else:
			manifest = [x.strip() for x in open(self.fout+"/AndroidManifest.xml","r").read().splitlines()]
			manifestxml = []
			isapplication = False
			for v in manifest:
				if isapplication:
					manifestxml.append("android:usesCleartextTraffic=\"true\"")
					manifestxml.append(v)
					isapplication = False
				else:
					if "<application" in v:
						isapplication = True
					manifestxml.append(v)
			manifest = "\n".join(manifestxml)
		manifest = [x.strip() for x in manifest.splitlines()]
		manifestxml = []
		# Check networkSecurityConfig
		isapplication = False
		isnetworksecurityconfig = False
		isnetsecconfadded = False
		if "android:networkSecurityConfig" in manifest:
			isnetworksecurityconfig = True
		for v in manifest:
			if isapplication:
				if not isnetworksecurityconfig:
					manifestxml.append("android:networkSecurityConfig=\"@xml/schadenfreude_mitm\"")
					manifestxml.append(v)
					isnetsecconfadded = True
					isnetworksecurityconfig = True
				elif "android:networkSecurityConfig" in v and not isnetsecconfadded:
						manifestxml.append("android:networkSecurityConfig=\"@xml/schadenfreude_mitm\"")
						isnetsecconfadded = True
				elif ">" in v:
					manifestxml.append(v)
					isapplication = False
				else:
					manifestxml.append(v)
			else:
				if "<application" in v:
					isapplication = True
				manifestxml.append(v)
		manifest = "\n".join(manifestxml)
		with open(self.fout+"/AndroidManifest.xml","w") as f:
			f.write(manifest)
		print("\x1b[1;93mOK\x1b[0m")
		print("\x1b[1;92m[+] \x1b[1;97mSet up network security configuration... \x1b[0m",end="")
		resdir = respath(self.fout, "apktool" if self.decom_ng == 0 else "apkeditor")
		if not os.path.isdir(resdir+"/xml"):
			os.mkdir(resdir+"/xml")
		#if not os.path.isdir(resdir+"/raw"):
			#os.mkdir(resdir+"/raw")
		shutil.copy("assets/schadenfreude_mitm.xml",resdir+"/xml/schadenfreude_mitm.xml")
		#shutil.copy("assets/HttpCanary.pem",resdir+"/raw/HttpCanary.pem")
		#if self.decom_ng ==	1:
			#if not os.path.isdir(self.fout+"/root/res/raw"):
				#os.mkdir(self.fout+"/root/res/raw")
			#shutil.copy("assets/HttpCanary.pem",self.fout+"/root/res/raw/HttpCanary.pem")
		print("\x1b[1;93mOK\x1b[0m")
		#self.values("raw", "HttpCanary", "res/raw/HttpCanary.pem")
		self.values("xml","schadenfreude_mitm","res/xml/schadenfreude_mitm.xml")
	def removeExportDataNotification(self):
		for f in self.smalidir:
			f_ls = list(glob.iglob(f"{f}/**/*.smali", recursive=True))
			totalpbar = len(f_ls)
			print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
			counter = 0
			civis()
			pbar = progressbar.ProgressBar(totalpbar).start()
			for file in f_ls:
				counter += 1
				pbar.update(counter)
				smalicodes = open(file,"r").read()
				ismodify = False
				for i in re.findall(r'invoke-.*\s{1,}Landroid/app/NotificationManager;->notify.*', smalicodes):
					if i in smalicodes:
						smalicodes = smalicodes.replace(i,"")
					pathfile = f"\x1b[1;92m[+] found: {file}\x1b[0m"
					while len(pathfile) < cols():
						pathfile = pathfile+" "
					print(pathfile)
					ismodify = True
					print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
				if ismodify:
					with open(file,"w") as fw:
						fw.write(smalicodes)
			pbar.finish()
			cnorm()
	def simpleSslBypass(self):
		print("\x1b[1;92m[+] Bypass SSL Pinning\x1b[0m")
		patchedsmali = []
		for f in self.smalidir:
			f_ls = list(glob.iglob(f"{f}/**/*.smali", recursive=True))
			totalpbar = len(f_ls)
			print(f"\x1b[1;96m[*] scan dirs: {f} ({totalpbar} files)\x1b[0m")
			counter = 0
			civis()
			pbar = progressbar.ProgressBar(totalpbar).start()
			for file in f_ls:
				counter += 1
				pbar.update(counter)
				smalicodes = open(file,"r").read()
				lines = [x.strip() if x.strip()=="" else x for x in smalicodes.splitlines()]
				if " interface " in lines[0]:
					continue
				for reg in regex_for_ssl_pinning:
					escaped_signature = re.escape(reg[0])
					pattern = re.compile(rf"(\.method public (?:final )?{escaped_signature})\n([\s\S]+?)\n(\.end method)", re.MULTILINE)
					matches = pattern.findall(smalicodes)
					for match in matches:
						smalicodes = smalicodes.replace(match[0],reg[1])
						patchedsmali.append(file)
			pbar.finish()
			cnorm()
		patchedsmali = list(set(patchedsmali))
		for i in patchedsmali:
			print("patch", i)
		print("\x1b[1;92m[+] \x1b[1;97mModifying AndroidManifest.xml... \x1b[0m",end="")
		manifest = open(self.fout+"/AndroidManifest.xml","r").read()
		# Check for android:usesCleartextTraffic="true"
		if "android:usesCleartextTraffic" in manifest:
			if "android:usesCleartextTraffic=\"false\"" in manifest:
				manifest = manifest.replace("android:usesCleartextTraffic=\"false\"","android:usesCleartextTraffic=\"true\"")
		else:
			manifest = [x.strip() for x in open(self.fout+"/AndroidManifest.xml","r").read().splitlines()]
			manifestxml = []
			isapplication = False
			for v in manifest:
				if isapplication:
					manifestxml.append("android:usesCleartextTraffic=\"true\"")
					manifestxml.append(v)
					isapplication = False
				else:
					if "<application" in v:
						isapplication = True
					manifestxml.append(v)
			manifest = "\n".join(manifestxml)
		nsc = []
		# Check networkSecurityConfig
		if "android:networkSecurityConfig" in manifest:
			reg = re.findall(r'android:networkSecurityConfig="(.*?)"', manifest)
			for m in reg:
				nsc.append(m)
		with open(self.fout+"/AndroidManifest.xml","w") as f:
			f.write(manifest)
		print("\x1b[1;93mOK\x1b[0m")
		print("\x1b[1;92m[+] \x1b[1;97mSet up network security configuration... \x1b[0m",end="")
		if len(nsc) < 1:
			print("\x1b[1;91mFAIL\x1b[0m")
			return
		for config in nsc:
			config = config.replace("@","")
			resdir = respath(self.fout, "apktool" if self.decom_ng == 0 else "apkeditor")
			while resdir.endswith("/"):
				resdir = resdir[0:len(resdir)-1]
			while config.startswith("/"):
				config = config[1:]
			if not config.lower().endswith(".xml"):
				config = config+".xml"
			with open("assets/schadenfreude_mitm.xml","r") as trustedcert:
				cert = trustedcert.read()
				if os.path.isfile(resdir+"/"+config):
					with open(resdir+"/"+config,"w") as confwriter:
						confwriter.write(cert)
		print("\x1b[1;93mOK\x1b[0m")
	def bypassPairip(self):
		isinject = False
		isinjectfile = None
		for d in self.smalidir:
			if isinject:
				pbar.finish()
				cnorm()
				break
			self.f_ls = list(glob.iglob(f"{d}/**/*.smali", recursive=True))
			totalpbar = len(self.f_ls)
			print(f"\x1b[1;96m[*] scan dirs: {d} ({totalpbar} files)\x1b[0m")
			counter = 0
			pbar = progressbar.ProgressBar(totalpbar).start()
			civis()
			for smalifile in self.f_ls:
				if isinject:
					counter += (totalpbar - counter)
					pbar.update(counter)
					break
				counter += 1
				pbar.update(counter)
				with open(smalifile,"r") as f:
					content = f.read()
				if "pairipcoree" in content:
					return
				if "pairipcore" in content and "loadLibrary" in content:
					content = content.splitlines()
					for k, line in enumerate(content):
						if all(any(m in x for x in content[k+1:k+5]) for m in ["pairipcore","loadLibrary"]):
							content.insert(k, "    const-string v0, \"pairipcoree\"")
							content.insert(k+1, "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")
							with open(smalifile,"w") as fw:
								for index,data in enumerate(content):
									fw.write(data+"\n")
							isinject = True
							isinjectfile = smalifile
							break
			pbar.finish()
			cnorm()
		if isinject:
			print("\x1b[1;92m[+] bppairip: \x1b[1;93mpairipcoree code has been injected!\x1b[0m")
			# remove pairip shared object library
			for f in glob.iglob(f"{self.fout}/**/lib/arm64-v8a/libpairipcore.so",recursive=True):
				f = f.strip()
				filename = f.split("/")[-1]
				pathfile = f[0:len(f)-len(filename)]
				shutil.copy("assets/chunk00.bin", pathfile+"libpairipcoree.so")
				print("\x1b[1;92m[+] bppairip: \x1b[1;93mlibpairipcoree.so has been added!\x1b[0m")
				break
	def searchMainClass(self):
		android_ns = "http://schemas.android.com/apk/res/android"
		et.register_namespace("android", android_ns)
		tree = et.parse(self.fout+"/AndroidManifest.xml")
		root = tree.getroot()
		application = root.find("application")
		activities = application.findall("activity")
		for activity in activities:
			if activity.find("intent-filter") is not None:
				if activity.find("intent-filter").find("action") is not None:
					if activity.find("intent-filter").find("action").get(f"{{{android_ns}}}name") == "android.intent.action.MAIN":
						mainclass = activity.get(f"{{{android_ns}}}name")
						if mainclass.startswith("."):
							return self.getPackageName()+mainclass
						return mainclass
	def il2cppdumper(self):
		mainclass = self.searchMainClass()
		mainclass = mainclass.replace(".","/")
		mainfile = list(glob.iglob(f"{self.fout}/smali/**/{mainclass}.smali", recursive=True))[0]
		with open(mainfile,"r") as f:
			content = f.read()
		data = content.splitlines()
		isoncreate = False
		isconstructor = False
		smalicodes = []
		print("\x1b[1;92m[+] \x1b[1;97mwrite invoker of il2cppdumper ... \x1b[0m", end="")
		if "onCreate(" in content:
			for k, v in enumerate(data):
				if v.strip().startswith(".method") and "onCreate(" in v:
					isoncreate = True
				if isoncreate:
					#if v.strip().startswith(".register"):
					smalicodes.append(v)
					smalicodes.append("const-string v0, \"il2cppdumper\"")
					smalicodes.append("invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")
					isoncreate = False
					continue
				smalicodes.append(v)
			list(map(lambda x: print(f"\x1b[1;92m{x}\x1b[0m"), smalicodes))
		else:
			for k, v in enumerate(data):
				if v.strip().startswith(".method") and "constructor <init>()" in v:
					isconstructor = True
				if isconstructor:
					#if v.strip().startswith(".register"):
					smalicodes.append(v)
					smalicodes.append("const-string p0, \"il2cppdumper\"")
					smalicodes.append("invoke-static {p0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")
					isconstructor = False
					continue
				smalicodes.append(v)
			list(map(lambda x: print(f"\x1b[1;92m{x}\x1b[0m"), smalicodes))
		with open(mainfile, "w") as f:
			f.write("\n".join(smalicodes))
		print("\x1b[1;92mOK\x1b[0m")
		print("\x1b[1;92m[+] \x1b[1;97madd libil2cppdumper.so ... \x1b[0m", end="")
		armv8 = list(glob.iglob(f"{self.fout}/**/lib/arm64-v8a/libil2cpp.so", recursive=True))
		armv7 = list(glob.iglob(f"{self.fout}/**/lib/armeabi-v7a/libil2cpp.so", recursive=True))
		#armv8 = list(filter(lambda x: "v8a" in x, pathlib))
		armv8 = armv8[0] if len(armv8) > 0 else None
		#armv7 = list(filter(lambda x: "v7a" in x, pathlib))
		armv7 = armv7[0] if len(armv7) > 0 else None
		if armv7:
			pathlib = armv7.strip()
		elif armv8:
			pathlib = armv8.strip()
		while not pathlib.endswith("lib"):
			lastname = pathlib.split("/")[-1]
			pathlib = pathlib[0:len(pathlib)-len(lastname)]
			while pathlib.endswith("/"):
				pathlib = pathlib[0:len(pathlib)-1]
		while pathlib.endswith("/"):
			pathlib = pathlib[0:len(pathlib)-1]
		armv8 = pathlib+"/arm64-v8a"
		armv7 = pathlib+"/armeabi-v7a"
		if not os.path.isdir(armv8):
			os.mkdir(armv8)
		if not os.path.isdir(armv7):
			os.mkdir(armv7)
		shutil.copy("assets/chunk01.bin", armv8+"/libil2cppdumper.so")
		shutil.copy("assets/chunk02.bin", armv7+"/libil2cppdumper.so")
		print("\x1b[1;92mOK\x1b[0m")
	def obfuscateMethods(self):
		packagename = input("[*] package name: ")
		readline.write_history_file(dtlxhistory)
		pkgname = packagename.replace(".","/")
		lstfiles = []
		for xdir in self.smalidir:
			if os.path.isdir(f"{xdir}/{pkgname}"):
				for file in glob.iglob(f"{xdir}/{pkgname}/*.smali",recursive=True):
					lstfiles.append(file)
		cycle = ["/","-","\\","|"]
		kcycle = 0
		civis()
		classlist = []
		prevlen = 0
		putaran = []
		randlst = rnd_wordlist()
		for k,v in enumerate(lstfiles):
			if kcycle >= len(cycle):
				kcycle = 0
			textstr = f"{cycle[kcycle]} register methods - {lstfiles[k]}"
			prevlen = len(textstr) if len(textstr) > prevlen else prevlen
			#textstr = textstr+" "*(cols()-len(textstr) if cols() > len(textstr) else 0)
			textstr = textstr+" "*prevlen
			textctr = len(textstr)//cols() if len(textstr) > cols() else 0
			textctr = textctr if textctr > textstr.count("\012") else textctr + textstr.count("\012")
			sys.stdout.write("\x1b[F"*textctr)
			sys.stdout.write(f"\r{textstr}")
			sys.stdout.flush()
			with open(v, "r") as f:
				contents = f.read().splitlines()
			classname = list(filter(lambda x: x.strip().startswith(".class"), contents))[0]
			classname = list(filter(lambda x: x.startswith("L") and ";" in x, classname.split()))[0]
			classname = classname.strip()
			for kline, line in enumerate(contents):
				if line.strip().startswith(".method"):
					methodname = line.strip().split()[-1]
					frameworkmethod = [
						"onStartCommand(",
						"onBind(",
						"onUnbind(",
						"onDestroy(",
						"start(",
						"run(",
						"join(",
						"interrupt(",
						"onCreate(",
						"onStart(",
						"onResume(",
						"onPause(",
						"onStop(",
						"onDestroy(",
						"onRestart(",
					]
					if "<" in methodname and "init" in methodname:
						continue
					if any([x in methodname for x in frameworkmethod]):
						continue
					has_successed = False
					while not has_successed:
						for xk,xv in enumerate(randlst):
							if len(putaran) >= len(randlst):
								randlst = list(map(lambda x: x+x, randlst))
								break
							newname = xv
							resp = finditem(classlist, "assigned", newname)
							if resp[1]:
								if not resp[0] in putaran:
									putaran.append(resp[0])
								continue
							tmpdata = {"class":classname,"method":methodname,"assigned":newname,"name":classname+"->"+methodname,"rename":classname+"->"+newname+"("+methodname.split("(")[1]}
							classlist.append(tmpdata)
							methodname = methodname.split("(")[0]
							contents[kline] = line.replace(" "+methodname+"("," "+newname+"(")
							has_successed = True
							break
			with open(v,"w") as f:
				f.write("\012".join(contents))
			kcycle += 1
		for xdir in self.smalidir:
			lstfiles = list(glob.iglob(f"{xdir}/**/*.smali", recursive=True))
			totalpbar = len(lstfiles)
			if kcycle >= len(cycle):
				kcycle = 0
			counter = 0
			for smalifile in lstfiles:
				counter += 1
				if kcycle >= len(cycle):
					kcycle = 0
				print(f"\r{cycle[kcycle]} scanning {xdir}... {counter//totalpbar*100}",end="")
				sys.stdout.flush()
				with open(smalifile,"r") as smaliread:
					codes = smaliread.read().splitlines()
				for wk, wv in enumerate(codes):
					for xk, xv in enumerate(classlist):
						if xv["name"] in wv:
							codes[wk] = wv.replace(xv["name"], xv["rename"])
				with open(smalifile,"w") as smaliwrite:
					smaliwrite.write("\012".join(codes))
				kcycle += 1
			print()
			kcycle += 1
		cnorm()
	def writeStoragePermissions(self):
		new = []
		print("[*] writing storage permissions in AndroidManifest.xml... ",end="")
		with open(f"{self.fout}/AndroidManifest.xml","r") as fd:
			content = fd.read().splitlines()
			isread = any(["android.permission.READ_EXTERNAL_STORAGE" in x for x in content])
			iswrite = any(["android.permission.WRITE_EXTERNAL_STORAGE" in x for x in content])
			ismanage = any(["android.permission.MANAGE_EXTERNAL_STORAGE" in x for x in content])
			requestlegacy = any(["requestLegacyExternalStorage" in x for x in content])
			ismanifest = False
			closetag = False
			for k, v in enumerate(content):
				new.append(v)
				if ismanifest and not closetag:
					if ">" in v:
						closetag = True
						if not isread:
							new.append("<uses-permission android:name=\"android.permission.READ_EXTERNAL_STORAGE\"/>")
							isread = True
						if not iswrite:
							new.append("<uses-permission android:name=\"android.permission.WRITE_EXTERNAL_STORAGE\"/>")
							iswrite = True
						if not ismanage:
							new.append("<uses-permission android:name=\"android.permission.MANAGE_EXTERNAL_STORAGE\"/>")
							ismanage = True
					continue
				if v.strip().startswith("<manifest"):
					ismanifest = True
				if ismanifest and closetag:
					if v.strip().startswith("<application"):
						if not requestlegacy:
							new.append("android:requestLegacyExternalStorage=\"true\"")
		with open(self.fout+"/AndroidManifest.xml","w") as fd:
			fd.write("\012".join(new))
		print("OK")
	def getPackageName(self):
		tree = et.parse(self.fout+"/AndroidManifest.xml")
		root = tree.getroot()
		return root.get("package")
	def mergeObb(self):
		try:
			print("\x1b[1;96m[i] Merge OBB and APK Tips\x1b[0m")
			print("\x1b[1;96m[i] You can Ctrl+C and to cancel this operation\x1b[0m")
			print("\x1b[1;96m[i] Remember to compress the .obb file with zip'\x1b[0m")
			obbfile = input("[*] obb path: ")
			readline.write_history_file(dtlxhistory)
			if not os.path.isfile(obbfile):
				self.warning(f"dtlx: '{obbfile}': No such file exists!")
				return
			self.writeStoragePermissions()
			destdir = self.smalidir[0]
			while destdir.endswith("/"):
				destdir = destdir[0:len(destdir)-1]
			if not os.path.isdir(destdir+"/com"):
				os.mkdir(destdir+"/com")
			print(f"[*] copying com/save.smali to {destdir}/com... ",end="")
			shutil.copy("assets/save.smali",destdir+"/com")
			print("OK")
			mainclass = self.searchMainClass()
			self.success(f"[+] main class: {mainclass}")
			mainclass = mainclass.replace(".","/")
			mainfile  = list(glob.iglob(f"{self.fout}/**/{mainclass}.smali", recursive=True))[0]
			self.success(f"[+] main class file: {mainfile}")
			print("[*] writing invoke-static to trigger the merging of obb and apk... ",end="")
			with open(mainfile,"r") as fd:
				content = fd.read().splitlines()
				isoncreate = False
				for k, v in enumerate(content):
					if isoncreate:
						if "move" in v or "invoke" in v:
							context = v.split()[1].replace("{","").replace("}","").replace(",","")
							content.insert(k+1,f"invoke-static {{{context}}}, Lcom/save;->a(Landroid/content/Context;)V")
							break
					if v.strip().startswith(".method") and "onCreate(" in v:
						isoncreate = True
				with open(mainfile,"w") as fd:
					fd.write("\012".join(content))
				print("OK")
			assetsdir = self.fout+"/assets"
			if self.decom_ng == 1:
				assetsdir = self.fout+"/root/assets"
			if not os.path.isdir(assetsdir):
				os.mkdir(assetsdir)
			print(f"[*] copying '{obbfile}' to '{assetsdir}/res2'... ",end="")
			shutil.copy(obbfile, assetsdir+"/res2")
			print("OK")
		except KeyboardInterrupt:
			self.warning("\n[!] merge obb operation is cancelled by the user...")
	def injectDocumentsProvider(self):
		self.writeStoragePermissions()
		classes = self.smalidir[0]
		while classes.endswith("/"):
			classes = classes[0:len(classes)-1]
		if not os.path.isdir(classes+"/org"):
			os.mkdir(classes+"/org")
		if not os.path.isdir(classes+"/org/revengi"):
			os.mkdir(classes+"/org/revengi")
		print("[*] injecting FilesProvider.smali... ",end="")
		shutil.copy("assets/FilesProvider.smali",classes+"/org/revengi")
		print("OK")
		print("[*] injecting FilesWakeUpActivity.smali... ",end="")
		shutil.copy("assets/FilesWakeUpActivity.smali",classes+"/org/revengi")
		print("OK")
		new = []
		print("[*] writing the corresponding contract")
		tree = et.parse(self.fout+"/AndroidManifest.xml")
		root = tree.getroot()
		android_ns = "http://schemas.android.com/apk/res/android"
		et.register_namespace("android",android_ns)
		application = root.find("application")
		activity = et.Element("activity")
		activity.set(f"{{{android_ns}}}name","org.revengi.FilesWakeUpActivity")
		activity.set(f"{{{android_ns}}}exported","true")
		activity.set(f"{{{android_ns}}}taskAffinity",self.getPackageName()+".FilesWakeUp")
		activity.set(f"{{{android_ns}}}excludeFromRecents","true")
		activity.set(f"{{{android_ns}}}noHistory","true")
		application.append(activity)
		provider = et.Element("provider")
		provider.set(f"{{{android_ns}}}name","org.revengi.FilesProvider")
		provider.set(f"{{{android_ns}}}permission","android.permission.MANAGE_DOCUMENTS")
		provider.set(f"{{{android_ns}}}exported","true")
		provider.set(f"{{{android_ns}}}authorities",self.getPackageName()+".FilesProvider")
		provider.set(f"{{{android_ns}}}grantUriPermissions","true")
		action = et.Element("action")
		action.set(f"{{{android_ns}}}name","android.content.action.DOCUMENTS_PROVIDER")
		intentfilter = et.Element("intent-filter")
		intentfilter.append(action)
		provider.append(intentfilter)
		application.append(provider)
		tree.write(self.fout+"/AndroidManifest.xml", encoding="utf-8", xml_declaration=True)
		self.success("[+] contract written.")
	def changeActivity(self):
		android_ns = "http://schemas.android.com/apk/res/android"
		et.register_namespace("android", android_ns)
		tree = et.parse(self.fout+"/AndroidManifest.xml")
		root = tree.getroot()
		application = root.find("application")
		activities = application.findall("activity")
		self.success(f"[+] Main Activity: "+self.searchMainClass())
		for k, v in enumerate(activities):
			print(f" [{k}] "+v.get(f"{{{android_ns}}}name"))
		while True:
			pickactivity = input("[*] Pick activity to replace current main activity: ")
			try:
				pickactivity = int(pickactivity)
				break
			except TypeError:
				self.warning(f"[!] dtlx: '{pickactivity}': Input should be an Integer or Number")
		print("[*] changing activity ...")
		haschanged = False
		for k, activity in enumerate(activities):
			if activity.find("intent-filter") is not None:
				if activity.find("intent-filter").find("action") is not None:
					action = activity.find("intent-filter").find("action")
					action = action.get(f"{{{android_ns}}}name")
					if action == "android.intent.action.MAIN":
						mainactivity = activity.get(f"{{{android_ns}}}name")
						activity.set(f"{{{android_ns}}}name",activities[pickactivity].get(f"{{{android_ns}}}name"))
						activities[pickactivity].set(f"{{{android_ns}}}name", mainactivity)
						haschanged = True
						break
		if haschanged:
			tree.write(self.fout+"/AndroidManifest.xml", encoding="utf-8", xml_declaration=True)
			self.success("[+] activity changed.")
		else:
			self.warning("[!] something went unexpected!")
	def changePackageName(self,packagename):
		oldpkgname = self.getPackageName()
		oldclassname = oldpkgname.replace(".","/")
		newclassname = packagename.replace(".","/")
		f_ls = list(glob.iglob(f"{self.fout}/**/*.*",recursive=True))
		totalpbar = len(f_ls)
		pbar = progressbar.ProgressBar(totalpbar).start()
		counter = 0
		civis()
		for ffile in f_ls:
			counter += 1
			pbar.update(counter)
			try:
				with open(ffile,"r") as f:
					content = f.read().splitlines()
					for k, v in enumerate(content):
						if oldpkgname in v:
							content[k] = v.replace(oldpkgname,packagename)
						elif oldclassname in v:
							content[k] = v.replace(oldclassname,newclassname)
				with open(ffile,"w") as f:
					f.write("\012".join(content))
			except UnicodeDecodeError:
				pass
		pbar.finish()
		cnorm()
	def changePkgName(self):
		userpkg = input("[*] new package name: ")
		print("[*] changing package name...")
		readline.write_history_file(dtlxhistory)
		self.changePackageName(userpkg)
	def cloneApk(self):
		packagename = self.getPackageName()
		randtext = randomletters()
		packagename = packagename+"."+randtext
		# if packagename.count(".") < 2:
			# packagename = packagename+"."+randtext
		# else:
			# while not packagename.endswith("."):
				# packagename = packagename[0:len(packagename)-1]
			# packagename = packagename+"."+randtext
		print("[*] cloning apk...")
		self.changePackageName(packagename)

helpbanner = """     __ __   __              
 ,__|  |  |_|  |___ __ __
 |  _  |   _|  |___|_ ` _| author: Gameye98 (1.0-dev)
 |_____|____|__|   |__.__| APK REVERSER & PATCHER

--rmads1: target=AndroidManifest.xml,replace=com.google.android.gms.ad
--rmads2: No Internet (remove the required permission to do so)
--rmads3: Search using regex and replace string ("ca-app-pub) with ("noads)
--rmads4: (Powerful) Disable all kind of ads loader base on the dictionary list
--rmads5: Randomize first 4 digits of the 16 digits Admob Adunit and App ID
--rmnop: Remove all nop instruction found on the smali file
--rmunknown: Remove all unknown files (.properties, etc)
--customfont: Update and replace all font files with user recommended file
--rmcopy: Remove AppCloner Copy Protection
--rmprop: Remove only .properties file
--rmtrackers: Remove Trackers
--nokill: No Kill
--cleanrun: Remove the decompiled project after done patching
--findstring: Find string / Search Text
--paidkw: Search for InApp Purchased of Pro/Premium Features
--noc: No compile/build the working project
--patch <PATCHFILE>: APK PATCHER (read README_PATCH.MD for more information)
--rmpairip: Remove Google Pairip Protection (Old Method)
--bppairip: Simple Bypass Google Pairip Protection 2024 (credit: 0xdeadc0de)
--rmvpndet: Remove VPN Detection (credit: t.me/toyly_s)
--rmusbdebug: Remove USB Debugging
--rmssrestrict: Remove ScreenShot Restriction
--rmxposedvpn: Remove ROOT XPosed and VPN Packages
--sslbypass: Bypass SSL Pinning
--rmexportdata: Remove AppCloner Export Data Notification
--fixinstall: Fix Installer (credit: t.me/toyly_s)
--il2cppdumper: Il2Cpp Dumper (credit: androeed.ru)
--obfuscatemethods: Methods Identifier Obfuscation
--mergeobb: Merge OBB and APK (credit: t.me/toyly_s)
--injectdocsprovider: Inject Documents Provider (credit: RevEngi)
--changeactivity: Change Main Activity
--changepkgname: Change Package Name
--cloneapk: Clone APK
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
# `return void;` in Smali. */
RETURN_VOID_SMALI = ['.locals 0', 'return-void'];
# `return true;` in Smali. */
RETURN_TRUE_SMALI = ['.locals 1', 'const/4 v0, 0x1', 'return v0'];
# `return new java.security.cert.X509Certificate[] {};` in Smali. */
RETURN_EMPTY_CERT_ARRAY_SMALI = [
    '.locals 1',
    'const/4 v0, 0x0',
    'new-array v0, v0, [Ljava/security/cert/X509Certificate;',
    'return-object v0',
];
regex_for_ssl_pinning = [
	[
		'checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
		".locals 0\nreturn-void",
	],
	[
		'checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V',
		".locals 0\nreturn-void",
	],
	[
		'getAcceptedIssuers()[Ljava/security/cert/X509Certificate;',
		".locals 1\nconst/4 v0, 0x0\nnew-array v0, v0, [Ljava/security/cert/X509Certificate;\nreturn-object v0",
	],
	[
		'verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z',
		".locals 1\nconst/4 v0, 0x1\nreturn v0",
	],
	[
		'check(Ljava/lang/String;Ljava/util/List;)V',
		".locals 0\nreturn-void",
	],
	[
		'check(Ljava/lang/String;Ljava/util/List;)V',
		".locals 0\nreturn-void",
	],
	[
		'check$okhttp(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V',
		".locals 0\nreturn-void",
	]
]

regex_for_root_xposed_and_vpn_removal = [
	[
		r'const-string (.*), "(com.koushikdutta.rommanager.license|com.ramdroid.appquarantinepro|com.noshufou.android.su.elite|com.zhiqupk.root.global|com.alephzain.framaroot|com.noshufou.android.su|com.noshufou.android.su.elite|eu.chainfire.supersu|com.thirdparty.superuser|com.koushikdutta.superuser|com.kingo.root|com.yellowes.su|com.topjohnwu.magisk|com.kingroot.kinguser|com.smedialink.oneclickroot|com.charles.lpoqasert|catch_.me_.if_.you_.can_|com.koushikdutta.rommanager|com.dimonvideo.luckypatcher|com.koushikdutta.rommanager.license|com.chelpus.lackypatch|com.ramdroid.appquarantine|supersu|com.ramdroid.appquarantinepro|com.android.vending.billing.InAppBillingService.COIN|com.android.vending.billing.InAppBillingService.LUCK|com.chelpus.luckypatcher|com.blackmartalpha|org.blackmart.market|com.allinone.free|com.repodroid.app|org.creeplays.hack|com.baseappfull.fwd|com.zmapp|com.dv.marketmod.installer|org.mobilism.android|com.android.wp.net.log|com.android.camera.update|cc.madkite.freedom|com.solohsu.android.edxp.manager|org.meowcat.edxposed.manager|com.xmodgame|com.cih.game_cih|/su/bin/|/system/usr/we-need-root/|/system/bin/failsafe/su|/data/local/su|/su/bin/su|/system/sd/xbin/su|/data/local/bin/su|/sbin/su|/data/local/xbin/su|magisk|/system/bin/su|/system/xbin/su|/system/app/Superuser.apk|/system/app/SuperSU.apk|/su/bin/su|com.guoshi.httpcanary|app.greyshirts.sslcapture|com.guoshi.httpcanary.premium|com.minhui.networkcapture|com.minhui.networkcapture.pro|com.egorovandreyrm.pcapremote|com.packagesniffer.frtparlak|jp.co.taosoftware.android.packetcapture|com.emanuelef.remote_capture|com.minhui.wifianalyzer|com.evbadroid.proxymon|com.evbadroid.wicapdemo|com.evbadroid.wicap|com.luckypatchers.luckypatcherinstaller|ru.UbLBBRLf.jSziIaUjL|me.weishu.kernelsu|com.topjohnwu.magisk|com.ramdroid.appquarantine|com.zachspong.temprootremovejb|com.koushikdutta.superuser|com.noshufou.android.su|eu.chainfire.supersu|/su/bin/su|com.minhui.networkcapture.pro|com.guoshi.httpcanary.premium|/data/local/tmp/frida-server|/data/local/tmp/frida-server|de.robv.android.xposed.installer|/su/bin/su|.thirdparty.superuser|.koushikdutta.superuser|.ramdroid.appquarantine|devadvance.rootcloak|.robv.android.xposed.installer|.saurik.substrate|.devadvance.rootcloakplus|.zachspong.temprootremovejb|.amphoras.hidemyroot|.formyhm.hideroot|.chelpus.lackypatch|.dimonvideo.luckypatcher|.koushikdutta.rommanager|.devadvance.rootcloakplus|/system/app/Superuser.apk|/system/xbin/which|com.phoneinfo.changerpro|com.VTechno.androididchanger|com.vivek.imeichanger|com.device.emulator|com.phoneinfo.changer|com.formyhm.hideroot|com.formyhm.hiderootPremium|com.amphoras.hidemyrootadfree|com.amphoras.hidemyroot|com.zachspong.temprootremovejb|com.saurik.substrate|com.devadvance.rootcloak|com.devadvance.rootcloakplus|com.chelpus.luckypatcher|com.ramdroid.appquarantine|com.ramdroid.appquarantinepro|com.joeykrim.rootcheck|/magisk/.core/bin/su|/system/xbin/busybox|/system/etc/init.d/99SuperSUDaemon|/dev/com.koushikdutta.superuser.daemon|/system/xbin/daemonsu|net.csu333.surrogate|fi.razerman.bancontactrootbypasser|me.phh.superuser|com.kingouser.com|/system/sd/xbin/|/system/bin/failsafe/|/sbin/|busybox|/system/app/Superuser|/system/app/SuperSU).*"'
		r'const-string \1, ""'
	]
]
regex_for_screenshot_restriction_removal = [
	[
		r'const/16 ([pv]\d+), 0x2000\n\n    invoke-virtual \{([pv]\d+), ([pv]\d+), ([pv]\d+)\}, Landroid/view/Window;->setFlags\(II\)V'
		r'const/4 \1, 0x0\n\n    invoke-virtual {\2, \3, \4}, Landroid/view/Window;->setFlags(II)V'
	],
	[
		r'invoke-virtual (\{.*\}), Landroid/view/Window;->setFlags\(II\)V'
		r'#\0'
	],
	[
		r'invoke-virtual (\{.*\}), Landroid/view/Window;->addFlags\(I\)V'
		r'#\0'
	],
	[
		r'const/16 (.*), 0x2000\s+invoke-virtual \{(.*), (.*), (.*)\}, Landroid/view/Window;->setFlags\(II\)V'
		r'const/16 \1, 0x0\n\n    invoke-virtual {\2, \1, \1}, Landroid/view/Window;->setFlags\(II\)V'
	],
	[
		r'invoke-static \{([pv]\d+)}, Lorg/telegram/messenger/FlagSecureReason;->isSecuredNow\(Landroid/view/Window;\)Z\n\n    move-result ([pv]\d+)\n\n    const/16 (.*), 0x2000'
		r'invoke-static {\1}, Lorg/telegram/messenger/FlagSecureReason;->isSecuredNow\(Landroid/view/Window;\)Z\n\n    move-result \2\n\n    const/16 \3, 0x0'
	],
	[
		r'iget ([pv]\d+, [pv]\d+), Landroid/view/(.*);->flags:I\n\n    or-int/lit16 ([pv]\d+, [pv]\d+), 0x2000'
		r'iget \1, Landroid/view/\2;->flags:I      or-int/lit16 \3, 0x0'
	]
]
regex_for_vpn_detection = [
	[
		r'(invoke-virtual \{.*}, Landroid/net/NetworkCapabilities;->hasTransport\(I\)Z\n\n    )move-result ([pv]\d+)',
		r'\1const/4 \2, 0x0'
	]
]
regex_for_fix_installer = [
	[
		r'invoke-virtual \{.*\}, Landroid/content/pm/PackageManager;->(getInstallerPackageName|InstallerPackageName)\(Ljava/lang/String;\)Ljava/lang/String;',
		r'invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->installer()Ljava/lang/String;'
	]
]
regex_for_usb_debugging = [
	[
		r'(const-string (.*), "development_settings_enabled"\s*invoke-static \{(.*), (.*), (.*)\}, .*;->getInt\(.*Ljava\/lang\/String;I\)I\s*)(move-result (.*))',
		r'\1#\2\nconst/4 \3, 0x0',
	],
	[
		r'(const-string (.*), "development_settings_enabled"\s*const/4 (.*), 0x0\s*invoke-static \{(.*), (.*), (.*)\}, .*;->getInt\(.*Ljava\/lang\/String;I\)I\s*)(move-result (.*))',
		r'\1#\2\nconst/4 \3, 0x0',
	],
	[
		r'(const-string (.*), "adb_enabled"\s*invoke-static \{(.*), (.*), (.*)\}, .*;->getInt\(.*Ljava\/lang\/String;I\)I\s*)(move-result (.*))',
		r'\1#\2\nconst/4 \3, 0x0',
	],
	[
		r'(const-string (.*), "adb_enabled"\s*const/4 (.*), 0x0\s*invoke-static \{(.*), (.*), (.*)\}, .*;->getInt\(.*Ljava\/lang\/String;I\)I\s*)(move-result (.*)) ',
		r'\1#\2\nconst/4 \3, 0x0',
	]
]
regex_for_pairip = [
	[
		r'(# direct methods\n.method public static )appkiller\(\)V([\s\S]*?.end method)[\w\W]*',
		r'\1constructor <clinit>()V\2',
	],
	[
		r'sget-object.*\s+.*const-string v1,(.*\s+).*.line.*\n+.+.*\n.*invoke-static \{v0\}, Lmt/Objectlogger;->logstring\(Ljava/lang/Object;\)V',
		r'const-string v0,\1'
	],
	[
		r'invoke-static \{\}, .*;->callobjects\(\)V\n',
		r''
	],
	[
		r'(\.method public.*onReceive\(Landroid/content/Context;Landroid/content/Intent;\)V\n    \.registers) .[\s\S]*const-string/jumbo.*\s+.*\s+.*\s+(return-void)',
		r'\1 3\n    \2'
	],
	[
		r'.*invoke.*pairip.*\)Ljava/lang/Object;.*',
		r'invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()Ljava/lang/Object;'
	],
	[
		r'.*invoke.*pairip.*\)V.*',
		r'invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()V'
	],
	[
		r'.*invoke.*pairip.*\)Z.*',
		r'invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()Z'
	]
]
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

trackers = [
	["Agora Analytics", "io.agora.utils.", "https://www.agora.io/en/products/agora-analytics/"],
	["Amazon Advertisement", "com.amazon.device.ads", "https://advertising.amazon.com/API/docs/en-us/get-started/overview"],
	["AppLovin", "com.applovin", "https://www.applovin.com/"] ,
	["AppsFlyer", "com.appsflyer.", "https://www.appsflyer.com/"],
	["CleverTap", "com.clevertap.", "https://clevertap.com/"],
	["Criteo", "com.criteo.", "https://www.criteo.com/"],
	["Facebook Ads","com.facebook.ads","https://developers.facebook.com/docs/android"],
	["Facebook Analytics","com.facebook.appevents","https://developers.facebook.com/docs/android"],
	["Facebook Share","com.facebook.share","https://developers.facebook.com/docs/android"],
	["Firebase Analytics", "com.google.android.gms.measurement.", "https://firebase.google.com/docs/analytics"],
	["Firebase Analytics", "com.google.firebase.analytics.", "https://firebase.google.com/docs/analytics"],
	["Freshchat", "com.freshchat", "https://www.freshworks.com/live-chat-software"],
	["Google AdMob", "com.google.ads.", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.AdActivity", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.AdRequest", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.AdView", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.mediation", "https://admob.google.com/home/"],
	["Google Ads","com.google.android.gms.ads.mediation","https://developers.google.con/admob/android"],
	["Google CrashLytics","com.google.firebase.crashlytics","http://crashlytics.com"],
	["Google Firebase Analytics","com.google.android.gms.measurement","https://firebase.google.com/"],
	["Google ML Kit", "com.google.mlkit", "https://developers.google.com/ml-kit"],
	["Google Play Billing Library / Service", "com.android.billingclient", "https://developer.android.com/google/play/billing/integrate"],
	["IAB Open Measurement", "com.iab.omid.library", "https://iabtechlab.com/standards/open-measurement-sdk/"],
	["InMobi", "com.inmobi", "https://www.inmobi.com/"],
	["Pollfish","com.pollfish","https://www.pollfish.com"],
	["Unity3d Ads", "com.unity3d.ads", "https://unity.com/products/unity-ads"],
	["Unity3d Ads", "com.unity3d.services", "https://unity.com/products/unity-ads"],
	["ironSource", "com.ironsource.", "https://www.is.com/"],
	['Adjust', 'com.adjust.sdk.', 'https://github.com/adjust/ios_sdk_dynamic_links_docs'],
	['Adobe Experience Cloud', 'com.adobe.marketing.mobile', 'https://aep-sdks.gitbook.io/docs/'],
	['Alibaba UserTrack Device IDentity (UTDID)', 'com.ta.utdid2', 'https://developer.alibaba.com/docs/dev/deviceid/introduction'],
	['Alipay SDK', 'com.alipay.sdk.', 'https://docs.open.alipay.com/api_1/alipay.trade.app.pay'],
	['Amazon Advertisement', 'com.amazon.device.ads', 'https://developer.amazon.com/docs/ad-api/overview.html'],
	['Amplitude Android SDK', 'com.amplitude.', 'https://developers.amplitude.com/docs/android-sdk-overview'],
	['AppLovin', 'com.applovin', 'https://dash.applovin.com/documentation/mediation/android/integration'],
	['AppMetrica', 'com.yandex.metrica.', 'https://yandex.com/dev/metrica/doc/mobile-sdk/quickstart.html'],
	['Appodeal Stack', 'com.explorestack.', 'https://www.appodeal.com/docs/'],
	['AppsFlyer', 'com.appsflyer.', 'https://docs.appsflyer.com/docs/android-sdk-integration'],
	['BidMachine', 'io.bidmachine.', 'https://bidmachine.com/docs/'],
	['Bolts', 'com.parse.bolts', 'https://github.com/BoltsFramework/Bolts-Android'],
	['Branch', 'io.branch.', 'https://docs.branch.io/apps/android/'],
	['Bugsnag', 'com.bugsnag.', 'https://docs.bugsnag.com/platforms/android/'],
	['ChartBoost', 'com.chartboost.sdk.', 'https://answers.chartboost.com/hc/en-us/articles/200780759-Android-SDK-Integration-Guide'],
	['Crashlytics', 'com.google.firebase.crashlytics', 'https://firebase.google.com/docs/crashlytics/get-started?platform=android'],
	['DaoCheng(Thinkyeah)', 'com.thinkyeah.common.', 'https://github.com/ThinkYeah/Android-Common-Library'],
	['Facebook Ads', 'com.facebook.ads', 'https://developers.facebook.com/docs/audiences-sdk/android/'],
	['Facebook Analytics', 'com.facebook.appevents', 'https://developers.facebook.com/docs/analytics/android/'],
	['Facebook Login', 'com.facebook.login', 'https://developers.facebook.com/docs/facebook-login/android'],
	['Facebook Share', 'com.facebook.share', 'https://developers.facebook.com/docs/sharing/android'],
	['Firebase Analytics', 'com.google.android.gms.measurement.', 'https://firebase.google.com/docs/analytics/android/start'],
	['Firebase Analytics', 'com.google.firebase.analytics.', 'https://firebase.google.com/docs/analytics/android/start'],
	['Firebase Analytics', 'com.google.firebase.firebase_analytics', 'https://firebase.google.com/docs/analytics/android/start'],
	['Fyber', 'com.fyber.', 'https://help.fyber.com/hc/en-us/articles/360038960931-Integration-Guide-Android-SDK'],
	['GIPHY Analytics', 'com.giphy.sdk.analytics', 'https://developers.giphy.com/docs/docs/sdk/android-sdk-analytics'],
	['Google AdMob', 'com.google.ads.', 'https://developers.google.com/admob/android/quick-start'],
	['Google Analytics', 'com.google.android.gms.analytics.', 'https://developers.google.com/analytics/devguides/collection/android/v4/'],
	['Google Cloud Audit', 'com.google.cloud.audit', 'https://cloud.google.com/logging/docs/auditlogsn'],
	['Google ML Kit', 'com.google.mlkit', 'https://developers.google.com/ml-kit'],
	['Google Play Billing Library / Service', 'com.android.billingclient', 'https://developer.android.com/google/play/billing'],
	['Google Tag Manager', 'com.google.android.gms.tagmanager', 'https://developers.google/tag-platform/tag-manager/android'],
	['IAB Open Measurement', 'com.iab.omid.library', 'https://github.com/IABTechLab/OMID-for-Android'],
	['IAB Open Measurement', 'com.ironsource.', 'https://developers.is.com/ironsource-mobile-sdk/android/ '],
	['IAB Open Measurement', 'ironSource', 'https://developers.is.com/ironsource-mobile-sdk/android/ '],
	['InMobi', 'com.inmobi', 'https://www.inmobi.com/sdk/'],
	['InMobi', 'com.ironsource.', 'https://developers.is.com/ironsource-mobile-sdk/android/'],
	['InMobi', 'ironsource', 'https://developers.is.com/ironsource-mobile-sdk/android/'],
	['Microsoft Visual Studio App Center Analytics', 'com.microsoft.appcenter.analytics', 'https://learn.microsoft.com/en-us/appcenter/sdk/analytics/overview/'],
	['Microsoft Visual Studio App Center Crashes', 'com.microsoft.appcenter.crashes', 'https://learn.microsoft.com/en-us/appcenter/sdk/analytics/overview/'],
	['Mintegral', 'com.mbridge.msdk.', 'https://www.mintegral.com/docs/sdk/android-sdk/'],
	['OneSignal', 'com.onesignal.', 'https://documentation.onesignal.com/docs/android-sdk-installation'],
	['Pangle', 'com.bytedance.applog.', 'https://developers.pangle.cn/docs/sdk/android/integration-guide/overview'],
	['Pangle', 'com.bytedance.sdk.openadsdk', 'https://developers.pangle.cn/docs/sdk/android/integration-guide/overview'],
	['Parse', 'com.parse.Parse', 'https://parseplatform.org/android/docs/'],
	['PubNative', 'net.pubnative', 'https://docs.pubnative.net/sdk/android/'],
	['RevenueCat', 'com.revenuecat.', 'https://docs.revenuecat.com/docs/overview'],
	['Sentry', 'io.sentry.', 'https://docs.sentry.io/platforms/android/'],
	['Smaato', 'com.smaato.', 'https://www.smaato.com/developers/sdk/'],
	['Tencent Stats', 'com.tencent.wxop.stat', 'https://developers.weixin.qq.com/miniprogram/en/dev/framework/stat.html'],
	['Tencent Wechat SDK', '.wxapi.', 'https://developers.weixin.qq.com/doc/oplatform/en/Inside/WeChat_SDK.html'],
	['Tencent Wechat SDK', 'com.tencent.mm.opensdk', 'https://developers.weixin.qq.com/doc/oplatform/en/Inside/WeChat_SDK.html'],
	['Unity3d Ads', 'com.unity3d.ads', 'https://docs.unity3d.com/Manual/UnityAds.html'],
	['Unity3d Ads', 'com.unity3d.services', 'https://docs.unity3d.com/Manual/UnityAds.html'],
	['VKontakte SDK', 'com.vk.api.sdk.', 'https://vk.com/dev/androidSDK'],
	['Yandex Ad', 'com.yandex.mobile.ads', 'https://yandex.com/dev/mobile-ads/doc/dg/overview.html'],
	['Zendesk', 'zendesk.', 'https://developer.zendesk.com/documentation/android-sdk/']
]

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
	(r"matchall_invoke",r"(invoke-.*\s\{.*\},\s)"),
	(r"matchall_conststring",r"const-string\s(v[0-9]),\s\"(.*?)\"")
)

kamusexit = (
	("Ljava/lang/System;->exit(I)V"),
	("Landroid/app/Activity;->onDestroy()V"),
	("Landroid/app/Activity;->finish()V"),
	("Landroid/app/Service;->stopSelf()V"),
	("Landroid/app/Activity;->finishActivity(I)V"),
	("Landroid/os/Process;->killProcess(I)V"),
	("Landroid/app/Activity;->finishAffinity()V"),
	("Landroid/app/Activity;->finishAndRemoveTask()V")
)

paidkeywords = [
	"ContainsKey", "ad_removed", "adremoved", "already_vip", "alreadyvip",
	"billingprocessor", "contains", "getpremium", "go_premium", "gopremium",
	"is_premium", "is_pro", "is_purchased", "is_subscribed", "is_vip",
	"ispremium", "ispremium_user", "ispremiumuser", "ispro", "ispro_user",
	"isprouser", "ispurchase", "ispurchased", "ispurchased ", "issubscribed",
	"isuserpremium ", "isuservip", "isvip", "ivVipUser", "mispremium ",
	"premium", "pro\"", "purchase", "purchaseType", "purchased",
	"removed_ads", "subscribe", "subscribe_pro", "subscribed", "subscriberpro",
	"unlocked", "vip", "vip_user", "vipuser",
]
if os.path.isfile("keywords.txt"):
	with open("keywords.txt","r") as f:
		paidkeywords = [x.strip() for x in f.read().splitlines() if x.strip() != ""]

neutralize = """.class public Lsec/blackhole/dtlx/Schadenfreude;
.super Ljava/lang/Object;
.source "Schadenfreude.java"

.method public static neutralize()V
    .locals 0
    return-void
.end method

.method public static neutralize()Z
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public static neutralize_true()Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public static neutralize()Ljava/lang/Object;
    .locals 1
    # Create a new Object instance
    new-instance v0, Ljava/lang/Object;
    # Call the constructor of Object
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    # Return the instance
    return-object v0
.end method

.method public static installer()Ljava/lang/String;
    .registers 1

    const-string v0, "com.android.vending"

    return-object v0
.end method
"""

def system(cmd):
	try:
		sysExec = subprocess.run(cmd,shell=True,check=True,stdout=subprocess.PIPE).stdout.decode()
		return sysExec
	except Exception as e:
		print(e)
		return None

def check_update():
	os.popen("git fetch origin master")
	localcommitid = os.popen("git rev-parse HEAD").read().strip()
	remotecommitid = os.popen("git rev-parse origin/master").read().strip()
	if localcommitid != remotecommitid:
		print("\x1b[1;41;93mUpdates are available. Pulling latest changes...\x1b[0m")
		os.system("git pull origin master")

def directrun():
	realpath = __file__
	filename = realpath.split("/")[-1]
	realpath = realpath[0:len(realpath)-len(filename)]
	while realpath.endswith("/"):
		realpath = realpath[0:len(realpath)-1]
	if os.getenv("PWD") == realpath:
		return True
	return False

def whereapkfrom():
	realpath = os.popen(f"realpath \"{sys.argv[-1]}\"").read()
	filename = realpath.split("/")[-1]
	while realpath.endswith("/"):
		realpath = realpath[0:len(realpath)-1]
	realpath = realpath[0:len(realpath)-len(filename)]
	while realpath.endswith("/"):
		realpath = realpath[0:len(realpath)-1]
	return realpath

def main():
	if directrun():
		check_update()
	print(mainbanner)
	global isconsole
	c = 0
	p = sys.argv
	p.remove(p[0])
	if len(p) >= 2:
		funcls = []
		ftarget = p[-1]
		if os.path.exists(ftarget):
			p = p[0:len(p)-1]
		else:
			print(helpbanner)
			return None
		patchfile = ""
		ispatch = False
		for px in p:
			if ispatch:
				patchfile = px
				ispatch = False
				continue
			if px == "--rmads1":
				funcls.append("rmads1")
			elif px == "--rmads2":
				funcls.append("rmads2")
			elif px == "--rmads3":
				funcls.append("rmads3")
			elif px == "--rmads4":
				funcls.append("rmads4")
			elif px == "--rmads5":
				funcls.append("rmads5")
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
			elif px == "--rmtrackers":
				funcls.append("rmtrackers")
			elif px == "--cleanrun":
				funcls.append("cleanrun")
			elif px == "--nokill":
				funcls.append("nokill")
			elif px == "--findstring":
				funcls.append("findstr")
			elif px == "--paidkw":
				funcls.append("paidkw")
			elif px == "--noc":
				funcls.append("nocompile")
			elif px == "--patch":
				funcls.append("patch")
				ispatch = True
			elif px == "--rmpairip":
				funcls.append("rmpairip")
			elif px == "--rmvpndet":
				funcls.append("rmvpndet")
			elif px == "--rmusbdebug":
				funcls.append("rmusbdebug")
			elif px == "--rmssrestrict":
				funcls.append("rmssrestrict")
			elif px == "--rmxposedvpn":
				funcls.append("rmrootxposedvpn")
			elif px == "--sslbypass":
				funcls.append("sslbypass")
			elif px == "--rmexportdata":
				funcls.append("rmexportdata")
			elif px == "--fixinstall":
				funcls.append("fixinstall")
			elif px == "--bppairip":
				funcls.append("bppairip")
			elif px == "--il2cppdumper":
				funcls.append("il2cppdumper")
			elif px == "--obfuscatemethods":
				funcls.append("obfuscatemethods")
			elif px == "--mergeobb":
				funcls.append("mergeobb")
			elif px == "--injectdocsprovider":
				funcls.append("injectdocsprovider")
			elif px == "--changeactivity":
				funcls.append("changeactivity")
			elif px == "--changepkgname":
				funcls.append("changepackagename")
			elif px == "--cloneapk":
				funcls.append("cloneapk")
		if ispatch:
			if not os.path.isfile(patchfile):
				print(f"\x1b[1;41;93m[!] dtlx: '{patchfile}': No such file exists\x1b[0m")
				sys.exit()
			with open(patchfile,"rb") as f:
				if f.read()[0:4] != b"PK\x03\x04":
					print(f"\x1b[1;41;93m[!] dtlx: '{patchfile}': Patch file should be a ZIP contains (patch.txt, etc)\x1b[0m")
					sys.exit()
		patcher(ftarget,funcls,patchfile=patchfile)

if not os.path.isfile(dtlxhistory):
	open(dtlxhistory,"w")
readline.read_history_file(dtlxhistory)
if __name__ == "__main__":
	if len(sys.argv) >= 2:
		main()
	else:
		print(helpbanner)
