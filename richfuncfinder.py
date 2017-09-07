#richFuncFinder.py v0.5
#find known MS VS Lib signatures in a binary
#by Timo 'T31M' Geissler

import pefile #by erocarrera
import rich #by kirschju.re

import sys, os, struct, time, json, pickle
from collections import defaultdict



class RichFuncFinder:

	def __init__(self, fname, rich, sigFolder, threshold=7):
		self.threshold = int(threshold) #define minimum length of signature byte sequence to be matched
		self.bucketSize = 3 #"depth of "hash table"" = prefix being matched HARDCODED FOR NOW

		self.found_relocs = {'parsed': [], 'unknown': []} #hold all found relocations
		self.found_functions = [] #hold all currently found function signatures
		self.already_found = [] #keep track to avoid duplicates in reloc segment

		self.fname = fname
		self.rich_data = rich
		self.sigFolder = sigFolder
		self.all_signatures = {} #hold all signatures in our current run
		self.hashTable = self.loadSignatures()


	#taken from rich.py
	def __u32(self, x):
		return struct.unpack("<I", x)[0]

	#load signatures from storage
	def loadSignatures(self):

		hashTable = defaultdict(list) #signature store
		loaded = 0 # how many signatures were loaded
		discarded = 0 # how many signatures are below threshold

		start = time.perf_counter()

		#extract rich header data
		#rich_data = rich.parse(self.fname)

		#load db according to found rich header values
		for cmpid in self.rich_data['cmpids']:
			if(os.path.isfile(self.sigFolder + str(cmpid['compid'])+ ".pickle")):
				with open(self.sigFolder + str(cmpid['compid'])+ ".pickle", 'rb') as infile:
					curr_sig_file = pickle.load(infile)

					#load signatures
					for sig in curr_sig_file:
						self.all_signatures[sig['name']] = sig #store all sigs
						
						if len(sig['raw']) >= self.threshold: #store sigs over threshold
							hashTable[sig['raw'][:self.bucketSize]].append(sig)
							loaded += 1
						else:
							discarded += 1

				print("Lib for 0x%x found (%d Signatures added)" % (cmpid['compid'], len(curr_sig_file)))
			else:
				print("No Lib for 0x%x found at %s" % (cmpid['compid'], self.sigFolder))

		stop = time.perf_counter()
		print("")
		print("Loaded %d entries in %d buckets. Discarded : %d. Took: %fs" % (loaded-discarded, len(hashTable), discarded, (stop-start)))
		print("")

		return hashTable

	#If we find a matching signature in our binary, this can be used to extract all relocations stored for this signature in our db
	def xtractRelocs(self, sig, dat, virtAddr, imagebase, memranges):

		relocs = sig['relocs']
		syms = sig['syms']
		num_found = 0

		#Parse all relocations in Signature
		for reloc in relocs:
			reloc_addr = self.__u32(dat[reloc['addr']:reloc['addr']+4]) #extract relocation address ("Call Target")
			name = sig['syms'][reloc['symidx']]['name'] #Name of "Call Target" / Relocation

			if reloc['type'] == 20: #relative relocation to current position
				call_target = virtAddr + reloc['addr'] + 4 + reloc_addr
				if call_target >= 1<<31: 
					call_target -= 1<<32 #take care of 'negative jumps / offsets'

				if not any([call_target >= r[0] and call_target < r[1] for r in memranges]): #is call target in memory range? = no constant
					continue

				num_found += 1

				if call_target in self.already_found: #is the relocation already known ?
					continue
				else:
					self.already_found.append(call_target)

				if name in self.all_signatures:	#is our relocated function in the signature table == more information available ?
					self.found_relocs['parsed'].append({'name': name.decode("utf-8"), 'size': len(self.all_signatures[name]['raw']), 
						'virtAddr': call_target, 'compid': self.all_signatures[name]['compid']})
				else:
					self.found_relocs['unknown'].append({'name': name.decode("utf-8"), 'virtAddr': reloc_addr, 
					'type': reloc['type'], 'call_target': call_target})

			elif reloc['type'] == 6: #direct relocations

				if not any([reloc_addr >= r[0] and reloc_addr < r[1] for r in memranges]): #is call target in memory range? = no constant
					continue

				num_found += 1

				if reloc_addr in self.already_found: #is the relocation already known ?
					continue
				else:
					self.already_found.append(reloc_addr)



				if name in self.all_signatures: #is our relocated function in the signature table == more information available ?
					self.found_relocs['parsed'].append({'name': name.decode("utf-8"), 'size': len(self.all_signatures[name]['raw']), 
						'virtAddr': reloc_addr, 'compid': self.all_signatures[name]['compid']})
				else:
					self.found_relocs['unknown'].append({'name': name.decode("utf-8"), 'virtAddr': reloc_addr, 
					'type': reloc['type'], 'call_target': reloc_addr})


			else:
				print("Unknown Relocation Detected: ", reloc['type'])

		return num_found == len(sig['relocs'])

	def parse(self):

		#open binary
		with open(self.fname, "rb") as f:
			dat = f.read()

		#calculate virtual Memory layout size / offsets
		pe = pefile.PE(self.fname)
		codebase = 0
		imagebase = pe.OPTIONAL_HEADER.ImageBase
		for s in pe.sections:
			## TODO actually check for --x attribute
			if s.Name.strip(b"\x00").decode() == ".text":
				dat = dat[s.PointerToRawData:][:s.SizeOfRawData]
				codebase = s.VirtualAddress
				break
		else:
			print("Could not find code section in binary!")
			return {'error': "no code section detected"}

		## TODO: Should we filter out .rsrc and .reloc?
		memranges = [tuple(map(lambda x: x + pe.OPTIONAL_HEADER.ImageBase,
			(s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize))) for s in pe.sections]
		memranges = sorted(memranges, key = lambda mem: mem[0])
		memranges.append((pe.OPTIONAL_HEADER.ImageBase, memranges[0][0]))
		memranges = sorted(memranges, key = lambda mem: mem[0])

		print("Codebase (.text): 0x%x, Imagebase: 0x%x, Code Section Size: %dbytes\n"  % (codebase, imagebase, len(dat)))

		if len(dat) > 1024*512: #512kb
			print("Warning Code Section >512kb will take too much time, aborting")
			return {'error': "code section too large"}

		start = time.perf_counter()

		pos = 0

		#Main loop, load bucketSize bytes from binary, check if exist in our hashtable, continue if found with detailed signature matching
		while (pos < (len(dat) - self.bucketSize)):

			#workaround for signatures starting with only 1 or 2 bytes before relocation e.g. 0x424242 + 0x424200 + 0x420000

			currPattern = dat[pos:pos+self.bucketSize]
			toCheck = [pattern for pattern in [currPattern, bytes([currPattern[0], currPattern[1], 0x0]), bytes([currPattern[0], 0x0, 0x0])] if pattern in self.hashTable]

			for pattern in toCheck:
				for sig in self.hashTable[pattern]:
					found = 0
					for p in sig['raw']:
						if (p != dat[pos + found] and p != 0):
							break
						else:
							found += 1

						if (found == len(sig['raw'])):
							virtAddr = pos + codebase + imagebase
							#print("Match: %s Size: 0x%x Offset: 0x%x  Compid: 0x%x" % (sig['name'], len(sig['raw']), virtAddr, sig['compid']))
							if (len(sig['relocs']) > 0):
								if self.xtractRelocs(sig, dat[pos:pos+found], virtAddr, imagebase, memranges) == False:
									continue

							self.found_functions.append({'name': sig['name'].decode("utf-8") , 'size': len(sig['raw']), 'virtAddr': virtAddr, 'compid': sig['compid']})
							pos += found - 1 
							break
			pos += 1

		stop = time.perf_counter()
		print("\nSignature Search for %s Took %fs (%fkb/s)\n" % (self.fname, stop-start, (len(dat)/(stop-start)) / 1024))

		return ({'detected': self.found_functions, 'relocs': self.found_relocs})