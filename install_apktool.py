#!/usr/bin/python
import os, requests
import re, random
import progressbar

civis = lambda: os.system("tput civis")
cnorm = lambda: os.system("tput cnorm")
size_units = ["B","kB","MB","GB","TB","PB"]

class fileIsDownloaded(Exception):
	pass

def getfilesize(bytesize):
	index = 0
	while bytesize >= 1024:
		bytesize /= 1024
		index += 1
	try:
		return f"{int(bytesize)}{size_units[index]}"
	except IndexError:
		return "File too large"

def downloadFile(url_addr,filename):
	input_size = 0
	block_size = 1024
	local_size = 0
	session = requests.Session()
	r = session.get(url_addr, stream=True)
	condis = r.headers.get("content-disposition")
	if condis != None:
		filename = re.findall(r'filename="(.*?)"', r.headers.get("content-disposition"))[0]
	if os.path.isfile(filename):
		local_size = os.path.getsize(filename)
	total_size = int(r.headers.get("content-length", 0))
	if total_size == 0:
		with open(filename, "wb") as f:
			civis()
			for data in r.iter_content(chunk_size=block_size):
				if data:
					input_size += len(data)
					print(f"{filename}: {getfilesize(input_size)}\r", end="")
					f.write(data)
		f.close()
		session.close()
		pbar.finish()
		cnorm()
	else:
		if local_size == 0:
			print(f"{filename}: {getfilesize(total_size)}")
			pbar = progressbar.ProgressBar(total_size).start()
			with open(filename, "wb") as f:
				civis()
				for data in r.iter_content(chunk_size=block_size):
					if data:
						input_size += len(data)
						pbar.update(input_size)
						f.write(data)
			f.close()
			session.close()
			pbar.finish()
			cnorm()
		elif local_size == total_size:
			raise fileIsDownloaded
		else:
			input_size = local_size
			r = session.get(url_addr, headers={"Range":f"bytes={local_size}-"}, stream=True)
			total_size = int(r.headers.get("content-length", 0))
			print(f"{filename}: {getfilesize(total_size+local_size)}")
			pbar = progressbar.ProgressBar(local_size+total_size).start()
			with open(filename, "ab") as f:
				civis()
				for data in r.iter_content(chunk_size=block_size):
					if data:
						input_size += len(data)
						pbar.update(input_size)
						f.write(data)
			f.close()
			session.close()
			pbar.finish()
			cnorm()

def randomid():
	randomstr = ""
	while len(randomstr) < 6:
		randomstr += str(random.choice(list(range(0,10))))
	return randomstr

exportcmd = "export PATH=$PATH:$HOME/bin"
exportcmd2 = "export PATH=$PATH:$HOME/bin"
def main():
    apktoolurl = "https://raw.githubusercontent.com/Gameye98/DTL-X/master/apktool-v2.9.3.jar"
    bindir = os.getenv("HOME")+"/bin"
    print("\x1b[1;92m[+] check and mkdir $HOME/bin... \x1b[0m", end="")
    if os.path.exists(bindir):
        if os.path.isfile(bindir):
            os.rename(bindir, bindir+"-"+randomid())
            os.mkdir(bindir)
    else:
        os.mkdir(bindir)
    print("\x1b[1;93mOK\x1b[0m")
    apktoolfile = bindir+"/apktool-dtlx.jar"
    print(f"\x1b[1;92m[+] check and download {apktoolfile}... \x1b[0m", end="")
    if os.path.exists(apktoolfile):
        if os.path.isdir(apktoolfile):
            os.rename(apktoolfile, apktoolfile+"-"+randomid())
            downloadFile(apktoolurl,apktoolfile)
    else:
        downloadFile(apktoolurl,apktoolfile)
    print("\x1b[1;93mOK\x1b[0m")
    bashrc = os.getenv("HOME")+"/.bashrc"
    iswritten = False
    print(f"\x1b[1;92m[+] check and modify {bashrc}... \x1b[0m", end="")
    if os.path.isfile(bashrc):
        with open(bashrc,"r") as f:
            lines = [x.strip() for x in f.read().splitlines()]
            for line in lines:
                if any([x in line for x in [exportcmd, exportcmd2]]):
                    iswritten = True
                    break
    if not iswritten:
        with open(bashrc,"a") as f:
            f.write("\n"+exportcmd+"\n")
    print("\x1b[1;93mOK\x1b[0m")
    print(f"\x1b[1;92m[+] add executable 'apktool'... \x1b[0m", end="")
    with open(bindir+"/apktool","w") as f:
        f.write("#!/usr/bin/bash\njava -jar $HOME/bin/apktool-dtlx.jar \"$@\"\n")
        os.system("chmod 755 "+bindir+"/apktool")
    print("\x1b[1;93mOK\x1b[0m")
    print("\x1b[1;41;93m[!] Run command below:\x1b[0m")
    print("\x1b[1;45m$ cd $HOME && source .bashrc\x1b[0m")

if __name__ == "__main__":
    main()
