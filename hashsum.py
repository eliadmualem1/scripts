# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# Authors:
# Eliad Mualem <eliad.mualem@otorio.com>
#
# Description:
# This code is a volshell addon for an interactive memory investigation
# 

import re
from hashlib import md5
from struct import unpack
from volatility.plugins.malware.apihooks import ModuleGroup, ApiHooks
from volatility.plugins.malware.malfind import Disassemble as disassemble
import volatility.utils as utils
import volatility.commands as commands
import volatility.win32.tasks as tasks
import volatility.plugins.vadinfo as vadinfo
try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False

#--------------------------------------------------------------------------------
# Core Classes
#--------------------------------------------------------------------------------
global_bits = None

class BinaryData():
    """ 
    This class holds the binary data with all related meta data
    """
    def __init__(self, bin_data, start, bits='32bit'):
        self._bin_data = bin_data
        self._start = start
        self._bits = global_bits
        self._max_length = 0x32
        self.hash = self.hash1()
        self.processes = {}
        self.source_modules = {}
        self.functions = {}
        self.dest_moudles = {}
        self.count = 1
    def hash1(self):
        hash_data = ''
        for o, i, h in self.dis():
            for cmd in i.split(' '):
                if '0x' not in cmd:
                    hash_data += cmd
        return md5(hash_data).hexdigest()
    def dis(self):
        """ 
        disassemble the binary data 
        """
        for o, i, h in disassemble(self._bin_data[:self._max_length], self._start, bits=self._bits):
            yield o, i, h
    def dis_print(self):
        """ 
        disassemble the binary data and prints it
        """
        for o, i, h in disassemble(self._bin_data[:self._max_length], self._start, bits=self._bits):
            print '{0}{1}{2}{3}{4}'.format(hex(o), ' '*(20 - len(hex(o))) , h, ' '*(20 - len(h)), i)

class CodeAnalyzer(BinaryData):
    def dissasemble(self, proc):
        mg = ModuleGroup(proc.get_load_modules())
        space = proc.get_process_address_space()
        for o, i, h in self.dis():
            module_name = ''
            if i.startswith('J'):
                if 'RIP+' in i:
                    offset = re.findall('(0x.+)]', i)[0]
                    address = int(len(h) / 2 + int(o, 16) + int(offset, 16))
                    data = space.read(address, 4)
                    location = unpack('I', data)[0]
                elif '[' in i:
                    offset = re.findall('(0x.+)]', i)[0]
                    address = int(offset, 16)
                    data = space.read(address, 4)
                    location = unpack('I', data)[0]
                else:
                    offset = re.findall('(0x.+)', i)[0]
                    location = int(offset, 16)
                module = mg.find_module(location)
                if module:
                    module_name = '({0})'.format(str(module.FullDllName))
            print '{0}{1}{2}{3}{4} {5}'.format(hex(o), ' '*(20 - len(hex(o))) , h, ' '*(20 - len(h)), i, module_name) 
    def add_data(self, process, address, pid):
        if process:
            if process in self.processes:
                self.processes[process].add((pid, address))
            else:
                self.processes[process] = set([(pid, address)])
    
    def add_data_old(self, process=None, source_module=None, function=None, dest_module=None):
        if process:
            if process in self.processes:
                self.processes[process] += 1
            else:
                self.processes[process] = 1
        if source_module:
            if source_module in self.source_modules:
                self.source_modules[source_module] += 1
            else:
                self.source_modules[source_module] = 1
        if function:
            if function in self.functions:
                self.functions[function] += 1
            else:
                self.functions[function] = 1
        if dest_module:
            if dest_module in self.dest_modules:
                self.dest_modules[dest_module] += 1
            else:
                self.dest_modules[dest_module] = 1

class VadTreeTraversal():
    _MAX = 0x18
    def __init__(self, proc):
        self._proc = proc
        self._vads = self._proc.get_vads()
    def run(self):
        for vad, addr in self._vads:
            if 'EXECUTE' not in vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), ""):
                continue
            bin_data = addr.zread(vad.Start, self._MAX)
            yield CodeAnalyzer(bin_data, vad.Start)

class NewApiHooks(ApiHooks):
    def run(self):
        for proc, dll, hook in self.calculate():
            last_hop = hook.disassembled_hops[-1]
            start = int(last_hop[0])
            bin_data = last_hop[1]
            if proc:
                yield CodeAnalyzer(bin_data, start), str(proc.ImageFileName), int(proc.UniqueProcessId)
            else:
                yield CodeAnalyzer(bin_data, start), str(dll.FullDllName), None

class HashSum(commands.Command):
    def __init__(self, config):
        global global_bits
        self.vtt_hashes = {}
        self.apihooks_hashes = {}
        self._config = config
        self._config.update('UNSAFE', False)
        self._config.update('SKIP_PROCESS', False)
        self._config.update('QUICK', False)
        self._config.update('NO_WHITELIST', True)
        self._config.update('SKIP_KERNEL', False)
        self._config.update('NAME', None)
        addrspace = utils.load_as(self._config)
        global_bits = addrspace.profile.metadata.get("memory_model", "32bit")
    def run(self, vadtree=True, apihooks=False):
        if vadtree:
            addr_space = utils.load_as(self._config)
            for proc in tasks.pslist(addr_space):
                vtt = VadTreeTraversal(proc)
                for bd in vtt.run():
                    if bd.hash in self.vtt_hashes:
                        self.vtt_hashes[bd.hash].count += 1
                    else:
                        self.vtt_hashes[bd.hash] = bd
                    self.vtt_hashes[bd.hash].add_data(process=str(proc.ImageFileName), address=bd._start, pid=int(proc.UniqueProcessId))
        if apihooks:
            apih = NewApiHooks(self._config)
            for bd, proc, pid in apih.run():
                if bd.hash in self.apihooks_hashes:
                    self.apihooks_hashes[bd.hash].count += 1
                else:
                    self.apihooks_hashes[bd.hash] = bd
                self.apihooks_hashes[bd.hash].add_data(process=proc, address=bd._start, pid=pid)
    def display(self):
        for h in self.vtt_hashes:
            print 'VadTree', h, self.vtt_hashes[h].count, '\n'
            for k in  self.vtt_hashes[h].processes:
                print k, len(self.vtt_hashes[h].processes[k])
            print
            self.vtt_hashes[h].dis_print()
            print '-'*20
        for h in self.apihooks_hashes:
            print 'ApiHooks', h, self.apihooks_hashes[h].count, '\n'
            for k in  self.apihooks_hashes[h].processes:
                print k, len(self.apihooks_hashes[h].processes[k])
            print
            self.apihooks_hashes[h].dis_print()
            print '-'*20
    def calculate(self):
        self.run()
        for h in self.vtt_hashes:
            yield 'VadTree', h, self.vtt_hashes[h]
        for h in self.apihooks_hashes:
            yield 'ApiHooks', h, self.apihooks_hashes[h]
    def render_text(self, outfd, data):
        for _type, h, bin_data_obj in data:
            outfd.write('{} {} {}\n'.format(_type, h, bin_data_obj.count))
            for k in bin_data_obj.processes:
                outfd.write('{} {} {}\n'.format(k, len(bin_data_obj.processes[k]), list(bin_data_obj.processes[k])[:3]))
            outfd.write('\n')
            for o, i, h in bin_data_obj.dis():
                outfd.write('{0}{1}{2}{3}{4}\n'.format(hex(o), ' '*(20 - len(hex(o))) , h, ' '*(20 - len(h)), i))
            outfd.write('{}\n'.format('-'*20))