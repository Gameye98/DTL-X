#!/usr/bin/python3
import os, sys, re
import random
import hashlib
import subprocess
import readline

endl = "\012"

def randomid():
	randomstr = ""
	while len(randomstr) < 6:
		randomstr += str(random.choice(list(range(0,10))))
	return randomstr

class patcher:
	def __init__(self, fin, args):
		self.endl = "\012"
		self.isneutralize = False
		self.ismodified = False
		self.isclean = False
		self.fin = fin
		self.fnm = fin.split("/")[-1] if "/" in fin else fin
		if not os.path.isfile(self.fin):
			raise FileNotFoundError(f"{self.fin}: No such file or directory")
		self.fout = self.fnm
		isselfout = False
		if self.fout.endswith(".apk"):
			self.fout = self.fout[0:len(self.fout)-4]
		else:
			self.fout = self.fout+".out"
			isselfout = True
		if isselfout:
			while os.path.isdir(self.fout):
				self.fout = self.fout+".out"
		self.raw = self.fout
		# Decompile APK file
		print("\x1b[92m+++++ Decompile APK into Project\x1b[0m")
		os.system(f"apktool d -f {self.fin}")
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
			elif args_iter=="rmads5":self.removeAds5()
			elif args_iter=="rmnop":self.removeNop()
			elif args_iter=="rmnown":self.removeUnknown()
			elif args_iter=="customfont":self.customFont()
			elif args_iter=="rmscrnrestrict":self.removeSetsecure()
			elif args_iter=="rmcopy":self.removeCopyProtection()
			elif args_iter=="rmprop":self.removeProperties()
			elif args_iter=="rmtrackers":self.removeTrackers()
			elif args_iter=="cleanrun":self.isclean=True
			elif args_iter=="nokill":self.nokill()
			elif args_iter=="findstr":self.findstr()
			elif args_iter=="paidkw":self.paidkw()
		# Compile Project
		print("\x1b[92m+++++ Compile Project into APK\x1b[0m")
		os.system(f"apktool b -f --use-aapt2 -a assets/aapt2 -d {self.fout}")
		print("\x1b[1;92m[+] Signing APK file... \x1b[0m",end="")
		os.system(f"apksigner sign --ks assets/user.keystore --ks-key-alias user --ks-pass pass:12345678 {self.fout}/dist/{self.fnm}")
		print("\x1b[1;92mOK\x1b[0m")
		print("\x1b[1;92m[+] Verifying APK file.... \x1b[0m",end="")
		os.system(f"apksigner verify {self.fout}/dist/{self.fnm}")
		print("\x1b[1;92mOK\x1b[0m")
		self.signed = self.fnm
		if self.signed.endswith(".apk"):
			self.signed = self.signed[0:len(self.signed)-4]+"_sign.apk"
		else:
			self.signed = self.signed+"_sign.apk"
		os.rename(self.fout+"/dist/"+self.fnm, self.signed)
		# Delete Project if isclean = True
		if self.isclean: os.system(f"rm -rf {self.fout}")
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
					self.success(f"[+] Found (\"ca-app-pub): {fx}... ")
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
	def removeSetsecure(self):
		print("Still working on")
	def removeTrackers(self):
		for tracksx in trackers:
			self.warning(tracksx[0]+": "+tracksx[2])
			self.removeClass(tracksx[1])
	def removeClass(self, class_name):
		# Delete class com.crashlytics.android
		for smalixdir in self.smalidir:
			if os.path.isdir(smalixdir+"/"+class_name.replace(".","/")):
				self.warning(smalixdir+"/"+class_name.replace(".","/"))
				os.system(f"rm -rf {smalixdir}/"+class_name.replace(".","/"))
		for smalixdir in self.smalidir:
			self.f_ls = subprocess.run(f"find {smalixdir}/",shell=True,check=True,stdout=subprocess.PIPE).stdout.decode().split(self.endl)
			self.f_ls = list(filter(lambda x: not x.startswith(".") and x.strip() != "", self.f_ls))
			self.f_ls = list(filter(lambda x: x.endswith(""), self.f_ls))
			self.f_ls = list(filter(lambda x: os.path.isfile(x), self.f_ls))
			# Clean smali code that execute operations pertain to $class_name
			for fx in self.f_ls:
				self.ffx = open(fx,"r").read()
				self.readperline = self.ffx.strip().split(endl)
				while "" in self.readperline:
					self.readperline.remove("")
				self.modifiedsourcefile = ""
				isgetobj = False
				for rpl_iterx in self.readperline:
					rplix = rpl_iterx.strip()
					if class_name.replace(".","/") in rpl_iterx or class_name in rpl_iterx:
						if rplix.startswith("invoke"):
							if rpl_iterx.strip().endswith(")V"):
								print("*"*int(system("tput cols")))
								self.success(f"[+] Patch (invoke~()V): {fx}")
								self.warning(rpl_iterx)
								rpl_iterx = rpl_iterx.replace(rplix,"invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()V")
								self.success(rpl_iterx)
							elif rpl_iterx.strip().endswith(")Z"):
								print("*"*int(system("tput cols")))
								self.success(f"[+] Patch (invoke~()Z): {fx}")
								self.warning(rpl_iterx)
								rpl_iterx = rpl_iterx.replace(rplix,"invoke-static {}, Lsec/blackhole/dtlx/Schadenfreude;->neutralize()Z")
								self.success(rpl_iterx)
						elif rplix.startswith("move-result") and isgetobj:
							print(f"\x1b[1;92m[+] Patch (new-instance): {fx}... \x1b[0m")
							self.warning(rpl_iterx)
							rpl_iterx = rpl_iterx.replace(rplix,"")
							isgetobj = False
						elif rplix.startswith("new-instance"):
							print(f"\x1b[1;92m[+] Patch (new-instance): {fx}... \x1b[0m")
							self.warning(rpl_iterx)
							rpl_iterx = rpl_iterx.replace(rplix,"")
							isgetobj = True
						elif rplix.startswith("iget"):
							print(f"\x1b[1;92m[+] Patch (iget): {fx}... \x1b[0m")
							self.warning(rpl_iterx)
							rpl_iterx = rpl_iterx.replace(rplix,"")
						elif rplix.startswith("iput"):
							print(f"\x1b[1;92m[+] Patch (iput): {fx}... \x1b[0m")
							self.warning(rpl_iterx)
							rpl_iterx = rpl_iterx.replace(rplix,"")
						self.modifiedsourcefile += rpl_iterx+endl
					elif rplix.startswith("const-string") and "\"crashlytics" in rplix.lower():
						print(f"\x1b[1;92m[+] Patch (const-string): {fx}... \x1b[0m")
						self.warning(rpl_iterx)
						constvar = rplix.split(",")[0]
						rpl_iterx = rpl_iterx.replace(rplix,f"{constvar}, \"null\"")
						self.modifiedsourcefile += rpl_iterx+endl
					else:
						self.modifiedsourcefile += rpl_iterx+endl
				open(fx,"w").write(self.modifiedsourcefile)
				self.ismodified = True
		if self.ismodified: self.writeNeutralize()
		# Remove leftover from AndroidManifest.xml
		self.cleanManifest(class_name)
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
		self.searchresults = []
		for f in self.smalidir:
			f_ls = os.popen(f"find {f}/").read().splitlines()
			while "" in f_ls: f_ls.remove("")
			f_ls = list(map(lambda x: x.strip(), f_ls))
			f_ls = list(filter(lambda x: os.path.isfile(x), f_ls))
			for fx in f_ls:
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
									smaliobj.updatw({"path": fx})
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
		outfile = f"{self.fnm}_paidkeywords_{randomid()}.txt"
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
		self.searchkwresults = []
		for f in self.smalidir:
			f_ls = os.popen(f"find {f}/").read().splitlines()
			while "" in f_ls: f_ls.remove("")
			f_ls = list(map(lambda x: x.strip(), f_ls))
			f_ls = list(filter(lambda x: os.path.isfile(x), f_ls))
			for fx in f_ls:
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
							for keyword in paidkeywords:
								if keyword in line:
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

trackers = [
	["Google CrashLytics","com.google.firebase.crashlytics","http://crashlytics.com"],
	["Google Firebase Analytics","com.google.android.gms.measurement","https://firebase.google.com/"],
	["Google Ads","com.google.android.gms.ads.mediation","https://developers.google.con/admob/android"],
	["Pollfish","com.pollfish","https://www.pollfish.com"],
	["Facebook Analytics","com.facebook.appevents","https://developers.facebook.com/docs/android"],
	["Facebook Share","com.facebook.share","https://developers.facebook.com/docs/android"],
	["Facebook Ads","com.facebook.ads","https://developers.facebook.com/docs/android"],
	["Amazon Advertisement", "com.amazon.device.ads", "https://advertising.amazon.com/API/docs/en-us/get-started/overview"],
	["AppLovin", "com.applovin", "https://www.applovin.com/"] ,
	["AppsFlyer", "com.appsflyer.", "https://www.appsflyer.com/"],
	["CleverTap", "com.clevertap.", "https://clevertap.com/"],
	["Criteo", "com.criteo.", "https://www.criteo.com/"],
	["Firebase Analytics", "com.google.firebase.analytics.", "https://firebase.google.com/docs/analytics"],
	["Firebase Analytics", "com.google.android.gms.measurement.", "https://firebase.google.com/docs/analytics"],
	["Google AdMob", "com.google.ads.", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.AdView", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.AdActivity", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.AdRequest", "https://admob.google.com/home/"],
	["Google AdMob", "com.google.android.gms.ads.mediation", "https://admob.google.com/home/"],
	["IAB Open Measurement", "com.iab.omid.library", "https://iabtechlab.com/standards/open-measurement-sdk/"],
	["InMobi", "com.inmobi", "https://www.inmobi.com/"],
	["ironSource", "com.ironsource.", "https://www.is.com/"],
	["Unity3d Ads", "com.unity3d.services", "https://unity.com/products/unity-ads"],
	["Unity3d Ads", "com.unity3d.ads", "https://unity.com/products/unity-ads"],
	["²Agora Analytics", "io.agora.utils.", "https://www.agora.io/en/products/agora-analytics/"],
	["²Google ML Kit", "com.google.mlkit", "https://developers.google.com/ml-kit"],
	["²Google Play Billing Library / Service", "com.android.billingclient", "https://developer.android.com/google/play/billing/integrate"],
	["Freshchat", "com.freshchat", "https://www.freshworks.com/live-chat-software"]
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

paidkeywords = {
	"ContainsKey", "ad_removed", "adremoved", "already_vip", "alreadyvip",
	"billingprocessor", "contains", "getpremium", "go_premium", "gopremium",
	"is_premium", "is_pro", "is_purchased", "is_subscribed", "is_vip",
	"ispremium", "ispremium_user", "ispremiumuser", "ispro", "ispro_user",
	"isprouser", "ispurchase", "ispurchased", "ispurchased ", "issubscribed",
	"isuserpremium ", "isuservip", "isvip", "ivVipUser", "mispremium ",
	"premium", "pro\"", "purchase", "purchaseType", "purchased",
	"removed_ads", "subscribe", "subscribe_pro", "subscribed", "subscriberpro",
	"unlocked", "vip", "vip_user", "vipuser",
}

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
		patcher(ftarget,funcls)

if __name__ == "__main__":
	if len(sys.argv) >= 2:
		main()
	else:
		print(helpbanner)
