import subprocess
import shlex
import time
import threading
from threading import Timer
import config
import pickle
import os
import operators
import random
from operator import itemgetter
import shutil
import inspect
import glob
import sys
from collections import Counter
from datetime import datetime
import binascii as bina
import copy
import re
import hashlib
import gautils as gau
# import gautils_new as gau_new
import mmap
import BitVector as BV 
import argparse
import cmpOperation as cmpO
from os import path
import imp
import patternSystem

# config.MOSTCOMFLAG=False # this is set once we compute taint for initial inputs.
libfd = open("image.offset", "r+b")
libfd_mm = mmap.mmap(libfd.fileno(), 0)
patternDefinition = list()

def get_min_file(src):
    files = os.listdir(src)
    first = False
    minsize = 0
    for fl in files:
        tfl = os.path.join(src, fl)
        tsize = os.path.getsize(tfl)
        if first == False:
            minsize = tsize
            first = True
        else:
            if tsize < minsize:
                minsize = tsize
    return minsize


def check_env():
    ''' this function checks relevant environment variable that must be set before we stat our fuzzer..'''
    
    gau.log_print( "[*] Checking environment variables" )

    if os.getenv('PIN_ROOT') == None:
        gau.die("[-] PIN_ROOT env is not set. Run export PIN_ROOT=path_to_pin_exe")
    fd1 = open("/proc/sys/kernel/randomize_va_space", 'r')
    b = fd1.read(1)
    fd1.close()
    if int(b) != 0:
        gau.die(
            "[-] ASLR is not disabled. Run: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
    fd = open("/proc/sys/kernel/yama/ptrace_scope", 'r')
    b = fd.read(1)
    fd.close()
    if int(b) != 0:
        gau.die(
            "[-] Pintool may not work. Run: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope")
    if os.path.ismount(config.BASETMP) == False:
        tmp = raw_input(
            "[-] It seems that config.BASETMP is not mounted as tmpfs filesystem. Making it a tmpfs may give you gain on execution speed. Press [Y/y] to mount it OR press [N/n] to continue.")
        if tmp.upper() == "Y":
            print "[-] run: sudo mount -t tmpfs -o size=1024M tmpfs %s" % config.BASETMP
            raise SystemExit(1)
        # gau.die("config.BASETMP is not mounted as tmpfs filesystem. Run: sudo mkdir /mnt/vuzzer , followed by sudo mount -t tmpfs -o size=1024M tmpfs /mnt/vuzzer")


def run(cmd):
    # print "[*] Just about to run ", cmd
    proc = subprocess.Popen(
        " ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    
    stdout, stderr = proc.communicate()

    #print "stdout : %s" % (stdout)
    #print "stderr : %s" % (stderr)

    # print "[*] Run complete..\n"
    # print "## RC %d"%proc.returncode
    # Note: the return is subtracted from 128 to make it compatible with the python Popen return code. Earlier, we were not using the SHELL with Popen.
    return 128-proc.returncode


def sha1OfFile(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()


def bbdict(fn):
    with open(config.BBOUT, "r") as bbFD:
        bb = {}
        for ln in bbFD:
            tLine = ln.split()
            bbadr = int(tLine[0], 0)
            bbfr = int(tLine[1], 0)
            bb[bbadr] = bbfr
        return bb


def form_bitvector(bbdict):
    ''' This function forms bit vector for each trace and append them to config.TEMPTRACE list. '''
    newbb = 0
    temp = set()
    for bbadr in bbdict:

        temp.add(bbadr)
        if bbadr not in config.BBSEENVECTOR:
            # added for bit vector formation
            newbb += 1
            config.BBSEENVECTOR.append(bbadr)
    tbv = BV.BitVector(size=(len(config.BBSEENVECTOR)))
    if newbb == 0:
        for el in temp:
            tbv[config.BBSEENVECTOR.index(el)] = 1
        config.TEMPTRACE.append(tbv.deep_copy())
    else:
        for bvs in config.TEMPTRACE:
            bvs.pad_from_right(newbb)
        for el in temp:
            tbv[config.BBSEENVECTOR.index(el)] = 1
        config.TEMPTRACE.append(tbv.deep_copy())
    del tbv


def form_bitvector2(bbdict, name, source, dest):
    ''' This function forms bit vector for a given bbdict trace for an input name, using the vector info from souce, updates the source and finally append  to dest dict'''
    newbb = 0
    temp = set()
    for bbadr in bbdict:

        temp.add(bbadr)
        if bbadr not in source:
            # added for bit vector formation
            newbb += 1
            source.append(bbadr)
    tbv = BV.BitVector(size=(len(source)))
    if newbb == 0:
        for el in temp:
            tbv[source.index(el)] = 1
        dest[name] = tbv.deep_copy()
    else:
        for bvs in dest.itervalues():
            bvs.pad_from_right(newbb)
        for el in temp:
            tbv[source.index(el)] = 1
        dest[name] = tbv.deep_copy()
    del tbv


def calculate_error_bb():
    ''' this function calculates probably error handling bbs. the heuristic is:
    if a bb is appearing N% of the traces and it is not in the traces of valid inputs, it indicates a error handling bb.'''
    erfd = open("errorbb.txt", 'w')
    perc = (config.BBPERCENT/100)*config.POPSIZE
    sn = len(config.BBSEENVECTOR)
    tbv = BV.BitVector(size=sn)
    tbv[-1] = 1
    for i in range(sn):
        tbv = tbv >> 1
        for tr in config.TEMPTRACE:
            count = 0
            tt = tr & tbv
            if tt.count_bits() == 1:
                count += 1
        if count > perc and config.BBSEENVECTOR[i] not in config.GOODBB:
            config.TEMPERRORBB.add(config.BBSEENVECTOR[i])
    for bbs in config.TEMPERRORBB:
        erfd.write("0x%x\n" % (bbs,))
    erfd.close()
    del tt
    del tbv


def execute(tfl):
    bbs = {}
    args = config.SUT % tfl
    runcmd = config.BBCMD+args.split(' ')
    try:
        os.unlink(config.BBOUT)
    except:
        pass

    #print "[*] args : ", args
    #print "[*] tfl : ", tfl
    #print "[*] config.SUT : ", config.SUT

    #print "[*] execute : %s" % (" ".join(runcmd))

    retc = run(runcmd)

    #print "[*] Done with exit code %d" % (retc)

    # check if loading address was changed
    # liboffsetprev=int(config.LIBOFFSETS[1],0)
    if config.LIBNUM == 2:

        if config.BIT64 == False:
            liboffsetcur = int(libfd_mm[:10], 0)
        else:
            liboffsetcur = int(libfd_mm[:18], 0)

        libfd_mm.seek(0)
        
        if liboffsetcur != int(config.LIBOFFSETS[1], 0):
            # print "Load address changed!"
            gau.die("[-] Load address of %s changed to 0x%x and you gave 0x%x : change it in launch options" % (config.LIBTOMONITOR, liboffsetcur, int(config.LIBOFFSETS[1], 0)))

    if config.CLEARSPECIALOUTPUT:
        gau.delete_special_out_file(config.SPECIALOUTPUT)

    # open BB trace file to get BBs
    bbs = bbdict(config.BBOUT)
    if config.CLEANOUT == True:
        gau.delete_out_file(tfl)

    return (bbs, retc)


def get_hexStr(inp):
    ''' This functions receives a hex string (0xdddddd type) and returns a string of the form \xdd\xdd..... Also, we need to take care of endianness. it it is little endian, this string needs to be reversed'''
    if len(inp[2:]) % 2 != 0:
        r = bina.unhexlify('0'+inp[2:])
    else:
        r = bina.unhexlify(inp[2:])
    if config.ARCHLIL == True:
        return r[::-1]
    else:
        return r
    # return bina.unhexlify('0'+inp[2:])
    # return bina.unhexlify(inp[2:])


def isNonPrintable(hexstr):
    nonprint = ['\x0a', '\x0d']
    if hexstr in nonprint:
        return True
    else:
        return False


def execute2(tfl, fl, is_initial=0):
    args = config.SUT % tfl
    args = '\"' + args + '\"'  # For cmd shell
    pargs = config.PINTNTCMD[:]

    if is_initial == 1:
        runcmd = [pargs[0], args, fl, "0"] 
    else:
        runcmd = [pargs[0], args, fl, str(config.TIMEOUT)]

    # pargs[pargs.index("inputf")]=fl
    # runcmd=pargs + args.split.split(' ')

    #print "[*] args : ", args
    #print "[*] tfl : ", tfl
    #print "[*] config.SUT : ", config.SUT

    #print "[*] execute : %s" % (" ".join(runcmd))


    retc = run(runcmd)

    if config.CLEARSPECIALOUTPUT:
        gau.delete_special_out_file(config.SPECIALOUTPUT)

    #print "[+] Done with exit code %d" % (retc)

    if config.CLEANOUT == True:
        gau.delete_out_file(tfl)

    return retc


def extract_offsetStr(offStr, hexs, fsize):
    '''Given a string of offsets, separated by comma and other offset num, this function return a tuple of offset and hex_string.'''
    offsets = offStr.split(',')
    offsets = [int(o) for o in offsets]
    if len(offsets) < 5:  # ==1:#<5:
        # as this only to detect magicbytes, i assume that magicbytes are contiguous in file and thus i only consider the 1st offset.
        ofs = offsets[0]
        if ofs > fsize-config.MINOFFSET:
            ofs = ofs-fsize
        hexstr = get_hexStr(hexs)
        # raw_input("hexStr: %s"%(hexstr,))
        # raw_input("hexstr is %s"%(bina.b2a_hex(hexstr),))
        return (ofs, hexstr)
    else:
        return (-1000, offsets[:])


def get_non_empty(mat, num):

    ind = num
    # mi = 1000000
    while ind < num+9:

        try:
            mat.group(ind)
        except:
            return -1

        # I have changed this
        if mat.group(ind) != '':
            return mat.group(ind)
        ind += 1
    # if mi == 1000000:
    return -1
    # return str(mi)


def read_lea():
    '''
    we also read lea.out file to know offsets that were used in LEA instructions. There offsets are good candidates to fuzz with extreme values, like \xffffffff, \x80000000.'''
    leaFD = open("lea.out", "r")
    # set to keep all the offsets that are used in LEA instructions.
    offsets = set()
    pat = re.compile(
        r"(\d+) (\w+) \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\}", re.I)

    for ln in leaFD:
        mat = pat.match(ln)
        try:  # this is a check to see if lea entry is complete.
            if config.BIT64 == False:
                rr = mat.group(6)
            else:
                rr = mat.group(10)
        except:
            continue
        tempoff = get_non_empty(mat, 3)  # mat.group(9)
        if tempoff == -1:
            continue
        toff = tempoff.split(',')
        toff = [int(o) for o in toff]
        if len(toff) < 5:
            offsets.add(toff[0])
    return offsets.copy()

def read_taint(fpath):
    ''' This function read cmp.out file and parses it to extract offsets and coresponding values and returns a tuple(alltaint, dict).
    dictionary: with key as offset and values as a set of hex values checked for that offset in the cmp instruction. Currently, we want to extract values s.t. one of the operands of CMP instruction is imm value for this set of values.
    ADDITION: we also read lea.out file to know offsets that were used in LEA instructions. There offsets are good candidates to fuzz with extreme values, like \xffffffff, \x80000000.
    '''

    #print "--------------------------------------------"

    gau.log_print( "[*] Parsing taint analysis of %s" % ( os.path.basename(fpath) ) )

    exploitableTaintedOffset = dict()

    allTaintedOffsets = dict()

    fsize = os.path.getsize(fpath)

    offlimit = 0

    # check if taint was generated, else exit
    if (os.path.getsize("cmp.out") == 0):
        gau.die("[-] Empty cmp.out file! Perhaps taint analysis did not run")

    cmpFD = open("cmp.out", "r")

    # each line of the cmp.out has the following format:
    # 32 reg imm 0xb640fb9d {155} {155} {155} {155} {} {} {} {} 0xc0 0xff
    # g1 g2 g3     g4        g5    g6    g7    g8  g9 g10 g11 g12 g13 g14
    # we need a regexp to parse this string.
    if config.BIT64 == False:
        pat = re.compile(
            r"(\d+) ([a-z]+) ([a-z]+) (\w+) \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} (\w+) (\w+)", re.I)
    else:
        pat = re.compile(
            r"(\d+) ([a-z]+) ([a-z]+) (\w+) \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} (\w+) (\w+)", re.I)

    cmpO.id = 0

    goodToProcessList = list()
    allTaintedOffsetsList = list()

    if config.FILTERDUPLICATED:
        rawCmpLines = set()
    else:
        rawCmpLines = list()

    cmpoutLineCount = 0

    # remove duplicates
    for line in cmpFD:
        cmpoutLineCount += 1

        if config.FILTERDUPLICATED:

            if line not in rawCmpLines:
                rawCmpLines.add(line)
        else:
            rawCmpLines.append(line)

    cmpFD.close()

    #print "original cmp.out size : " + str(cmpoutLineCount)
    #print "cmp.out after size : " + str(len(rawCmpLines))

    allCmps = list()

    for ln in rawCmpLines:

        if offlimit > config.MAXFILELINE:
            break

        offlimit += 1

        mat = pat.match(ln)

        try:  # this is a check to see if CMP entry is complete.
            if config.BIT64 == False:
                rr = mat.group(14)
            else:
                rr = mat.group(22)
        except:
            continue

        cmp = cmpO.cmpOperation(mat)

        # TODO : if cmp.offset == -1

        # the cmp is not valid or will not be handle
        if len(cmp.offsetsInInput) == 0:
            continue

        # save each valid cmp
        allCmps.append(cmp)

    # detect any pattern in cmp.out
    if config.USEPATTERNDETECTION == True:

        gau.log_print("[*] Running pattern detection for %s" % ( os.path.basename(fpath) ))

        # search and apply patterns
        allCmps = detectPatterns(allCmps, fpath)

    for cmp in allCmps:
        
        # if the cmp is valid and good to be used with taint based changes
        if cmp.isGoodToTaintChanges == True:
            goodToProcessList.append(cmp)

        # if it's just a normal cmp
        else:
            allTaintedOffsetsList.append(cmp)

    gau.debug_print("[*] allTaintedOffsetsList size : %d" % (len(allTaintedOffsetsList)))
    gau.debug_print("[*] goodToProcessList     size : %d" % (len(goodToProcessList)))

    return (allTaintedOffsetsList, goodToProcessList)

def initPatterns():

    # TODO : check error

    for file in os.listdir("patterns/definitions"):
        if file.endswith(".py"):

            pathStr = os.path.join("patterns/definitions", file)

            if path.exists(pathStr):
                patternDefinition.append(imp.load_source('PatternDefinition', pathStr).PatternDefinition())

    patternCount = 0

    # create each pattern objects
    for file in patternDefinition:
        for sign in file.FILES:

            pathStr = os.path.join("patterns/signatures", sign)

            # create each pattern objects
            if path.exists(pathStr):
                file.patternList.append(patternSystem.Pattern(pathStr))
                patternCount += 1

    gau.log_print("[*] %d patternDefinition detected (%d total)" % (len(patternDefinition), patternCount))

def detectPatterns(cmpList, fpath):

    # test each patterns for each index ?
    # or test each index of each patterns ????
    # currently I choose each index of each patterns because of end offsets

    patternFound = 0

    for patternDef in patternDefinition:

        for pattern in patternDef.patternList:
                
            index = 0

            # loop through each offset of cmp for a pattern
            while index != len(cmpList):

                endOffset = pattern.executeFromCmpObjects(index, cmpList)

                # check if a pattern is found
                if endOffset != -1:

                    gau.debug_print( "\033[0;32m[+] Found %s (%s) from %d to %d" % (pattern.name, patternDef.name, (index),(endOffset)) + " !\033[0m" )
                    
                    # execute the effect of a found pattern
                    cmpList = patternDef.effect(pattern.name, cmpList, index, endOffset, fpath)

                    # jump to the end of the pattern
                    index = endOffset+1

                    patternFound += 1
                else:
                    index += 1

    if patternFound > 0:
        gau.log_print("\033[0;32m[+] %d pattern found\033[0m" % (patternFound))

    return cmpList

def get_taint(dirin, is_initial=0):
    ''' This function is used to get taintflow for each CMP instruction to find which offsets in the input are used at the instructions. It also gets the values used in the CMP.'''

    files = os.listdir(dirin)

    newTaint = []

    for f in files:
        if f not in config.TAINTMAP:
            newTaint.append(f)

    gau.log_print("[*] Starting taintflow calculation for %d files" % (len(newTaint)))

    for fl in files:

        if fl in config.TAINTMAP:
            continue

        pfl = os.path.abspath(os.path.join(dirin, fl))

        if is_initial == 1:
            tnow1 = datetime.now()

        gau.log_print( "[*] Launching taint analysis of %s" % ( os.path.basename(fl) ) )

        rcode = execute2(pfl, fl, is_initial)

        if is_initial == 1:
            tnow2 = datetime.now()
            config.TIMEOUT = max(
                config.TIMEOUT, 2*((tnow2-tnow1).total_seconds()))

        if rcode == 255:
            gau.die("pintool terminated with error 255 on input %s" % (pfl,))
            continue

        config.TAINTMAP[fl] = read_taint(pfl)
        config.LEAMAP[fl] = read_lea()

    gau.log_print("[*] Taintflow parsing done")

    if config.MOSTCOMFLAG == False:

        gau.log_print("[*] Computing MOSTCOMMON calculation")

        tmpTaintMap = config.TAINTMAP.copy()

        for file, values in tmpTaintMap.iteritems():

            for cmp in values[1]:

                offset = cmp.offsetsInInput[0]

                foundInAll = True

                foundMap = list()

                for file2, values2 in tmpTaintMap.iteritems():
                    
                    foundInThisFile = False

                    for cmp2 in values2[1]:
                        
                        if offset in cmp2.offsetsInInput and cmp.taintValue == cmp2.taintValue:
                            foundInThisFile = True

                    foundMap.append(foundInThisFile)

                    if foundInThisFile == False:
                        break

                for file1 in foundMap:
                    if file1 == False:
                        foundInAll = False
                
                if foundInAll == True:
                    config.MOSTCOMMON.append(cmp)

                    # delete it from taint map
                    config.TAINTMAP[file][1].remove(cmp)
                                
            break

    else:
        
        gau.log_print("[*] Computing MORECOMMON calculation")

        tmpTaintMap = config.TAINTMAP.copy()

        for file, values in tmpTaintMap.iteritems():

            for cmp in values[1]:

                offset = cmp.offsetsInInput[0]

                foundInAll = True

                foundMap = list()

                for file2, values2 in tmpTaintMap.iteritems():
                    
                    foundInThisFile = False

                    for cmp2 in values2[1]:
                        
                        if offset in cmp2.offsetsInInput:

                            dif = cmp.taintValue - cmp2.taintValue

                            if dif < 0: dif *= -1

                            if dif < 3:
                                foundInThisFile = True

                    foundMap.append(foundInThisFile)

                    if foundInThisFile == False:
                        break

                for file1 in foundMap:
                    if file1 == False:
                        foundInAll = False
                
                if foundInAll == True:
                    config.MORECOMMON.append(cmp)

                    # delete it from taint map
                    config.TAINTMAP[file][1].remove(cmp)
                                
            break

    #print '------------------------------------------------------------------------------'

    if len(config.MOSTCOMMON) > 0:
        gau.log_print("[*] MOSTCOMMON size is about %d cmps" % (len(config.MOSTCOMMON)))

    #for cmp in config.MOSTCOMMON:
    #    print cmp

    if len(config.MORECOMMON) > 0:
        gau.log_print("[*] MORECOMMON size is about %d cmps" % (len(config.MORECOMMON)))

    #for cmp in config.MORECOMMON:
    #    print cmp

    gau.log_print("[*] Taintflow finished")

    #gau.die("done.")


def dry_run():

    ''' this function executes the initial test set to determine error handling BBs in the SUT. Such BBs are given zero weights during actual fuzzing.'''

    gau.log_print("[*] Starting dry run")
    tempbad = []
    dfiles = os.listdir(config.INITIALD)

    if len(dfiles) < 3:
        gau.die("[-] Not sufficient initial files")

    for fl in dfiles:
        tfl = os.path.join(config.INITIALD, fl)
        try:
            f = open(tfl, 'r')
            f.close()
        except:
            gau.die("[-] Can not open our own input %s !" % (tfl))
        (bbs, retc) = execute(tfl)
        if retc < 0:
            print "Signal: %d" % (retc,)
            gau.die("[-] Looks like we already got a crash !")
        config.GOODBB |= set(bbs.keys())

    gau.log_print("[*] Finished good inputs (%d BB)" % (len(config.GOODBB),))
    # now lets run SUT of probably invalid files. For that we need to create them first.
    gau.log_print("[*] Starting bad inputs")

    lp = 0
    badbb = set()
    while lp < 2:
        try:
            shutil.rmtree(config.INPUTD)
        except OSError:
            pass

        os.mkdir(config.INPUTD)
        gau.create_files_dry(30)
        dfiles = os.listdir(config.INPUTD)
        for fl in dfiles:
            tfl = os.path.join(config.INPUTD, fl)
            (bbs, retc) = execute(tfl)
            if retc < 0:
                gau.log_print( "Signal: %d" % (retc,))
                gau.die("[-] Looks like we already got a crash !")
            tempbad.append(set(bbs.keys()) - config.GOODBB)

        tempcomn = set(tempbad[0])
        for di in tempbad:
            tempcomn.intersection_update(set(di))
        badbb.update(tempcomn)
        lp += 1

    config.ERRORBBALL = badbb.copy()
    gau.log_print("[*] Finished common basic blocks (%d BB)" % (len(badbb)))

    for ebb in config.ERRORBBALL:
        gau.debug_print( "[-] Error on BB : 0x%x" % (ebb,))

    time.sleep(5)
    if config.LIBNUM == 2:
        baseadr = config.LIBOFFSETS[1]
        for ele in tempcomn:
            if ele < baseadr:
                config.ERRORBBAPP.add(ele)
            else:
                config.ERRORBBLIB.add(ele-baseadr)

    del tempbad
    del badbb
    # del tempgood
    return len(config.GOODBB), len(config.ERRORBBALL)


def run_error_bb(pt):

    gau.log_print("[*] Starting run_error_bb")
    files = os.listdir(config.INPUTD)
    for fl in files:
        tfl = os.path.join(config.INPUTD, fl)
        (bbs, retc) = execute(tfl)
        # if retc < 0:
        #    print "[*] crashed while executing %s"%(fl,)
        #    gau.die("Bye...")
        form_bitvector(bbs)
    calculate_error_bb()


def copy_files(src, dest, num):
    files = random.sample(os.listdir(src), num)
    for fl in files:
        tfl = os.path.join(src, fl)
        shutil.copy(tfl, dest)


def conditional_copy_files(src, dest, num):
    # count = 0;
    # tempbuf=set()
    flist = os.listdir(src)
    # we need to handle the case wherein newly added files in SPECIAL are less than the num. in this case, we only copy these newly added files to dest.
    extra = set(flist)-set(config.TAINTMAP)
    if len(extra) == 0:
        return -1
    if len(extra) < num:
        for fl in extra:
            tfl = os.path.join(src, fl)
            shutil.copy(tfl, dest)
        return 0
    else:
        tlist = random.sample(list(extra), num)
        for fl in tlist:
            tfl = os.path.join(src, fl)
            shutil.copy(tfl, dest)
        return 0

    # while count <num:
    #    fl =random.choice(os.listdir(src))
    #    if fl not in config.TAINTMAP and fl not in tempbuf:
    #        tempbuf.add(fl)
    #        count +=1
    #        tfl=os.path.join(src,fl)
    #        shutil.copy(tfl,dest)
    # del tempbuf

import math
import aflcminReduction as afl

def gradient(line, count):
    return '\033[38;5;%dm' % ((16 + (36 * line)) + count)

def banner():

    string = ["__   ___   _ ___________ _ __  ",
              "\ \ / / | | |_  /_  / _ \ '__| : Next generation fuzzer",
              " \ V /| |_| |/ / / /  __/ |    : By Sanjay Rawat, Vivek Jain, Ashish Kumar, Ren Kimura,",
              "  \_/  \__,_/___/___\___|_|      Lucian Cojocar, Cristiano Giuffrida, Herbert Bos, @r0da"]
    clearWhite = '\033[0;00m'

    print "-"*88

    lineId = 0

    for line in string:

        charId = 0

        for c in line:
            color = gradient(lineId, charId)
            sys.stderr.write(clearWhite + c)
            charId += 1
        print

        lineId += 1

    sys.stderr.write(clearWhite)

    print
    print "-"*88

def main():

    banner()

    # first lets create the base directorty to keep all temporary data
    try:
        shutil.rmtree(config.BASETMP)
    except OSError:
        pass
    if os.path.isdir(config.BASETMP) == False:
        os.mkdir(config.BASETMP)
    check_env()
    ## parse the arguments #########
    parser = argparse.ArgumentParser(description='VUzzer options')
    parser.add_argument('-s', '--sut', help='SUT commandline', required=True)
    parser.add_argument(
        '-i', '--inputd', help='seed input directory (relative path)', required=True)
    parser.add_argument(
        '-w', '--weight', help='path of the pickle file(s) for BB wieghts (separated by comma, in case there are two) ', required=True)
    parser.add_argument(
        '-n', '--name', help='Path of the pickle file(s) containing strings from CMP inst (separated by comma if there are two).', required=True)
    parser.add_argument(
        '-l', '--libnum', help='Nunber of binaries to monitor (only application or used libraries)', required=False, default=1)
    parser.add_argument('-o', '--offsets', help='base-address of application and library (if used), separated by comma',
                        required=False, default='0x00000000')
    parser.add_argument(
        '-b', '--libname', help='library name to monitor', required=False, default='#')
    args = parser.parse_args()
    config.SUT = args.sut
    config.INITIALD = os.path.join(config.INITIALD, args.inputd)
    config.LIBNUM = int(args.libnum)
    config.LIBTOMONITOR = args.libname
    config.LIBPICKLE = [w for w in args.weight.split(',')]
    config.NAMESPICKLE = [n for n in args.name.split(',')]
    config.LIBOFFSETS = [o for o in args.offsets.split(',')]
    config.LIBS = args.libname
    # this is just to find the index of the placeholder in BBCMD list to replace it with the libname
    ih = config.BBCMD.index("LIBS=")
    config.BBCMD[ih] = "LIBS=%s" % args.libname

    gau.log_print( "[*] Checking tmps files" )

    if config.CLEARSPECIALOUTPUT:
        gau.delete_special_out_file(config.SPECIALOUTPUT)

    if path.exists("vuzzerRun.log"):
        os.remove("vuzzerRun.log")

    gau.log_print( "[*] Checking directories" )

    if config.USEPATTERNDETECTION == True:
        initPatterns()

    ###################################

    afl.clearDir()

    config.minLength = get_min_file(config.INITIALD)
    try:
        shutil.rmtree(config.KEEPD)
    except OSError:
        pass
    os.mkdir(config.KEEPD)

    try:
        os.mkdir("outd")
    except OSError:
        pass

    try:
        os.mkdir("outd/crashInputs")
    except OSError:
        gau.emptyDir("outd/crashInputs")

    crashHash = []
    try:
        os.mkdir(config.SPECIAL)
    except OSError:
        gau.emptyDir(config.SPECIAL)

    try:
        os.mkdir(config.INTER)
    except OSError:
        gau.emptyDir(config.INTER)

    gau.log_print( "[*] Checking executable base address" )

    #############################################################################
    # let us get the base address of the main executable.
    ifiles = os.listdir(config.INITIALD)
    for fl in ifiles:
        tfl = os.path.join(config.INITIALD, fl)
        try:
            f = open(tfl, 'r')
            f.close()
        except:
            gau.die("[-] Can not open our own input %s !" % (tfl))
        (ibbs, iretc) = execute(tfl)

        if iretc != 128: # 0
            gau.die("[-] Can't run the target program '%s' !" % (os.path.basename(config.SUT.replace(" ","").replace("%s",""))))
        break  # we just want to run the executable once to get its load address

    imgOffFd = open("imageOffset.txt", 'r')
    for ln in imgOffFd:
        if "Main:" in ln:
            lst = ln.split()
            break
    config.LIBOFFSETS[0] = lst[1][:]
    imgOffFd.close()

    if config.LIBTOMONITOR != '' and config.LIBTOMONITOR != '#':
        gau.log_print("[+] Lib %s is at 0x%x" % (config.LIBTOMONITOR, int(config.LIBOFFSETS[1], 0)))

    gau.log_print( "[*] Checking pickles" )

    #############################################################################

    # open names pickle files
    gau.prepareBBOffsets()

    # lets initialize the BBFORPRUNE list from thie cALLBB set.
    if len(config.cALLBB) > 0:
        config.BBFORPRUNE = list(config.cALLBB)
    else:
        gau.log_print("[*] cALLBB is not initialized. something is wrong!!\n")
        system.exit()

    if config.PTMODE:
        pt = simplept.simplept()
    else:
        pt = None

    gau.log_print("[*] Running vuzzer for '%s'" % (os.path.basename(config.SUT.replace(" ","").replace("%s",""))))

    if config.ERRORBBON == True:
        gbb, bbb = dry_run()
    else:
        gbb = 0

    # gau.die("dry run over..")
    import timing
    # selftest()
    noprogress = 0
    currentfit = 0
    lastfit = 0

    config.CRASHIN.clear()
    stat = open("stats.log", 'w')
    stat.write("**** Fuzzing started at: %s ****\n" %
               (datetime.now().isoformat('+'),))
    stat.write("**** Initial BB for seed inputs: %d ****\n" % (gbb,))
    stat.flush()
    os.fsync(stat.fileno())
    stat.write(
        "Genaration\t MINfit\t MAXfit\t AVGfit MINlen\t Maxlen\t AVGlen\t #BB\t AppCov\t AllCov\n")
    stat.flush()
    os.fsync(stat.fileno())
    starttime = time.clock()
    allnodes = set()
    alledges = set()
    try:
        shutil.rmtree(config.INPUTD)
    except OSError:
        pass
    shutil.copytree(config.INITIALD, config.INPUTD)

    # fisrt we get taint of the intial inputs
    get_taint(config.INITIALD, 1)

    # print "MOst common offsets and values:", config.MOSTCOMMON
    # print "Base address: %s"%config.LIBOFFSETS[0]
    # raw_input("Press enter to continue..")
    config.MOSTCOMFLAG = True
    crashhappend = False
    filest = os.listdir(config.INPUTD)
    filenum = len(filest)

    if filenum < config.POPSIZE:
        gau.create_files(config.POPSIZE - filenum)

    gau.log_print( '[*] Population at start is about %d files' % (len(os.listdir(config.INPUTD))))

    efd = open(config.ERRORS, "w")
    gau.prepareBBOffsets()
    writecache = True
    genran = 0
    bbslide = 40  # this is used to call run_error_BB() functions
    keepslide = 3
    keepfilenum = config.BESTP
    config.SEENBB.clear()  # initialize set of BB seen so far, which is 0
    del config.SPECIALENTRY[:]
    todelete = set()  # temp set to keep file names that will be deleted in the special folder
    
    oldPrintSize = 0

    while True:
        # print "[**] Generation %d\n***********"%(genran,)

        del config.TEMPTRACE[:]
        del config.BBSEENVECTOR[:]
        # this is set when a config.SPECIAL gets at least one new input per generation.
        SPECIALCHANGED = False
        config.TMPBBINFO.clear()
        config.TMPBBINFO.update(config.PREVBBINFO)

        fitnes = dict()
        execs = 0
        config.cPERGENBB.clear()
        config.GOTSTUCK = False

        if config.ERRORBBON == True:
            if genran > config.GENNUM/5:
                bbslide = max(bbslide, config.GENNUM/20)
                keepslide = max(keepslide, config.GENNUM/100)
                keepfilenum = keepfilenum/2

            if 0 < genran < config.GENNUM/5 and genran % keepslide == 0:
                copy_files(config.INPUTD, config.KEEPD, keepfilenum)

        # lets find out some of the error handling BBs
            if genran > 40 and genran % bbslide == 0:
                stat.write("\n**** Error BB cal started ****\n")
                stat.flush()
                os.fsync(stat.fileno())
                run_error_bb(pt)
                copy_files(config.KEEPD, config.INPUTD,
                           len(os.listdir(config.KEEPD))*1/10)
            # copy_files(config.INITIALD,config.INPUTD,1)
        files = os.listdir(config.INPUTD)
        per_gen_fnum = 0
        for fl in files:
            per_gen_fnum += 1
            tfl = os.path.join(config.INPUTD, fl)
            iln = os.path.getsize(tfl)
            args = (config.SUT % tfl).split(' ')
            progname = os.path.basename(args[0])
            (bbs, retc) = execute(tfl)
            filecount = len(os.listdir(config.INPUTD))
            inputname = os.path.basename(args[1])

            per_current_stat = (float(per_gen_fnum)/float(filecount)) * 100

            per_show = (int(float(filecount) / 10.0))

            if per_show == 0:
                per_show = 10

            if per_gen_fnum % per_show == 0 or per_gen_fnum == filecount:

                logStr = "[%s] Gen %d : %d%% Executed %d of %d" % (time.strftime("%H:%M:%S"),genran,int(per_current_stat),per_gen_fnum, filecount)
                
                if oldPrintSize > 0:
                    dif = oldPrintSize - len(logStr)
                    if dif > 0: 
                        logStr += " "*dif

                oldPrintSize = len(logStr)

                gau.log_print( logStr )
            else:

                gau.log_print( ' '*oldPrintSize )
                
                sys.stdout.write("\033[F")

                logStr = "[%s] Gen %d : %d%% Executed %d of %d [%s]" % (time.strftime("%H:%M:%S"),genran,int(per_current_stat),per_gen_fnum, filecount,inputname)

                if oldPrintSize > 0:
                    dif = oldPrintSize - len(logStr)
                    if dif > 0: 
                        logStr += " "*dif

                oldPrintSize = len(logStr)

                gau.log_print( logStr )

                sys.stdout.write("\033[F")

            if config.BBWEIGHT == True:
                fitnes[fl] = gau.fitnesCal2(bbs, fl, iln)
            else:
                fitnes[fl] = gau.fitnesNoWeight(bbs, fl, iln)
            # raw_input()
            execs += 1
            # let us prune the inputs(if at all), whose trace is subset of the new input just got executed.
            SPECIALADDED = False
            if config.GOTSPECIAL == True:
                SPECIALCHANGED = True
                SPECIALADDED = True
                todelete.clear()
                form_bitvector2(bbs, fl, config.BBFORPRUNE,
                                config.SPECIALBITVECTORS)
                shutil.copy(tfl, config.SPECIAL)
                config.SPECIALENTRY.append(fl)
                for sfl, bitv in config.SPECIALBITVECTORS.iteritems():
                    if sfl == fl:
                        continue
                    if (config.SPECIALBITVECTORS[fl] & bitv) == bitv:
                        tpath = os.path.join(config.SPECIAL, sfl)
                        os.remove(tpath)
                        todelete.add(sfl)
                        config.SPECIALENTRY.remove(sfl)
                        if sfl in config.TAINTMAP:
                            del config.TAINTMAP[sfl]
                for ele in todelete:
                    del config.SPECIALBITVECTORS[ele]

            if retc < 0 and retc != -2:
                efd.write("%s: %d\n" % (tfl, retc))
                efd.flush()
                os.fsync(efd)
                tmpHash = sha1OfFile(config.CRASHFILE)
                if tmpHash not in crashHash:
                    crashHash.append(tmpHash)
                    tnow = datetime.now().isoformat().replace(":", "-")
                    nf = "%s-%s.%s" % (progname, tnow,
                                       gau.splitFilename(fl)[1])
                    npath = os.path.join("outd/crashInputs", nf)
                    shutil.copyfile(tfl, npath)
                    if SPECIALADDED == False:
                        shutil.copy(tfl, config.SPECIAL)

                    config.CRASHIN.add(fl)
                if config.STOPONCRASH == True:
                    # efd.close()
                    crashhappend = True
                    break
        fitscore = [v for k, v in fitnes.items()]
        maxfit = max(fitscore)
        avefit = sum(fitscore)/len(fitscore)
        mnlen, mxlen, avlen = gau.getFileMinMax(config.INPUTD)

        gau.log_print( "[*] Done with all input in Gen %d" % (genran) )
        gau.log_print( "[*] Calculating code coverage" )

        appcov, allcov = gau.calculateCov()
        tnow = datetime.now().isoformat().replace(":", "-")
        # stat.write("\t%d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %s\n"%(genran,min(fitscore),maxfit,avefit,mnlen,mxlen,avlen,len(config.cPERGENBB),appcov,allcov,tnow))
        stat.write("\t%d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %s\n" % (genran, min(
            fitscore), maxfit, avefit, mnlen, mxlen, avlen, len(config.SEENBB), appcov, allcov, tnow))
        stat.flush()
        os.fsync(stat.fileno())
        gau.log_print( "[*] Wrote to stat.log" )

        seenBB = len(config.SEENBB)

        codeCovStr = "[+] BB Code coverage is %d" % (seenBB)

        if config.LASTTURNCODECOV != 0:

            difLastTurnStr = "(no new BB found)"

            codeCovDif = seenBB - config.LASTTURNCODECOV

            if codeCovDif > 0:
                difLastTurnStr = "\033[0;32m(+%d BB)\033[0m" % (codeCovDif)
            elif codeCovDif < 0:
                difLastTurnStr = "\033[0;31m(-%d BB)\033[0m" % (codeCovDif)

            perBBTotal = (float(seenBB) / float(len(config.ALLBB))) * 100

            difGoodBB = seenBB - len(config.GOODBB)

            difGoodBBStr = "no"

            if difGoodBB > 0:
                difGoodBBStr = "+%d" % (difGoodBB)
            elif difGoodBB < 0:
                difGoodBBStr = "-%d" % (difGoodBB)

            codeCovStr += " %s (%d%% of all BB) (%s BB dif with good path)" % (difLastTurnStr, perBBTotal, difGoodBBStr)
            
        config.LASTTURNCODECOV = seenBB

        gau.log_print( "-"*len(codeCovStr) ) 
        gau.log_print( codeCovStr )
        gau.log_print( "-"*len(codeCovStr) )
        
        if crashhappend == True:
            break
        # lets find out some of the error handling BBs
        # if genran >20 and genran%5==0:
         #   run_error_bb(pt)
        genran += 1
        config.CURRENTGEN += 1
        # this part is to get initial fitness that will be used to determine if fuzzer got stuck.
        lastfit = currentfit
        # currentfit=maxfit
        currentfit = len(config.SEENBB)
        # lastfit-config.FITMARGIN < currentfit < lastfit+config.FITMARGIN:
        if currentfit == lastfit:
            noprogress += 1
        else:
            noprogress = 0
        if noprogress > 20:
            config.GOTSTUCK = True
            stat.write("Heavy mutate happens now..\n")
            noprogress = 0
        if (genran >= config.GENNUM) and (config.STOPOVERGENNUM == True):
            break
        if len(os.listdir(config.SPECIAL)) > 0 and SPECIALCHANGED == True:
            if len(os.listdir(config.SPECIAL)) < config.NEWTAINTFILES:
                get_taint(config.SPECIAL)
            else:
                try:
                    os.mkdir(config.TAINTTMP)
                except OSError:
                    gau.emptyDir(config.TAINTTMP)
                if conditional_copy_files(config.SPECIAL, config.TAINTTMP, config.NEWTAINTFILES) == 0:
                    get_taint(config.TAINTTMP)
            # print "MOst common offsets and values:", config.MOSTCOMMON
            # gg=raw_input("press any key to continue..")

        gau.log_print( "[*] Going for new generation creation" )
        gau.createNextGeneration3(fitnes, genran)
        # raw_input("press any key...")

    efd.close()
    stat.close()
    libfd_mm.close()
    libfd.close()
    endtime = time.clock()

    gau.log_print( "[**] Totol time %f sec" % (endtime-starttime,) )
    gau.log_print( "[**] Fuzzing done. Check %s to see if there were crashes" % (
        config.ERRORS,))


if __name__ == '__main__':

    fuzzthread = threading.Thread(target=main)

    fuzzthread.start()

    if config.FLASK:

        socketio.run(app, host="0.0.0.0", port=5000)
