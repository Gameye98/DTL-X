# Author: Gameye98/DedSecTL
# Founder: Schadenfreude & BlackHole Security
# Date: Sat Jan  7 05:37:28 2023
# Schadenfreude      - https://t.me/schdenfreude
# BlackHole Security - https://t.me/PRESS_OFFICIAL_V3_MAX_PRO
###### Contact Me
# GitHub: https://github.com/Gameye98
# Telegram: https://t.me/deletuserbot
import r2pipe, os
import readline, re
from loguru import logger

@logger.catch
def main():
	binary = input("[*] Binary: ")
	f = open(binary+".txt","w")
	readline.write_history_file(".findval_history")
	try:
		r = r2pipe.open(binary)
		if not os.path.isfile(binary):
			raise Exception("No such file or directory")
		while True:
			offset = input("[*] Offset: ")
			readline.write_history_file(".findval_history")
			address = input("[*] Address (split:',';can input from file): ")
			readline.write_history_file(".findval_history")
			if os.path.isfile(address):
				with open(address,"r") as ff:
					address = re.findall(r'RVA: (.*?) Offset', ff.read())
			else:
				address = [x.strip() for x in address.split(",")] if "," in address else [address]
			for addr in address:
				print(f"\x1b[1;41;93m[@] address: {addr}\x1b[0m")
				r.cmd(f"s {addr}")
				ldr = r.cmd(f"aF;pdr | grep {offset} | grep ldr")
				mov = r.cmd(f"aF;pdr | grep {offset} | grep mov")
				f.write(f"[@] address: {addr}\n")
				if not ldr == "":
					print(f"\n\n\x1b[92m{ldr}\x1b[0m")
					f.write(f"\n\n{ldr}\n")
				if not mov == "":
					print(f"\n\n\x1b[93m{mov}\x1b[0m")
					f.write(f"\n\n{mov}\n")
	except KeyboardInterrupt:
		f.close()

if not os.path.isfile(".findval_history"):
	open(".findval_history","w")
readline.read_history_file(".findval_history")
if __name__ == "__main__":
	try:
		main()
	except Exception as e:
		print(e)
