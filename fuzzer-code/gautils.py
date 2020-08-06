import config
import os
import operators
from operator import itemgetter
import pickle
import math
import random
import shutil
from cmpOperation import taintTypeEnum
import aflcminReduction as afl

def die(msg):
    print msg

    if config.WRITELOG:
        try:
            f = open("vuzzerRun.log", 'a')
            f.write(str)
            f.write("\n")
            f.close()
        except:
            print "[-] Fail to write the log"
            f.close()

    raise SystemExit(1)

def isDirEmpty(dn):
    """Test if a directory is empty."""
    return os.listdir(dn) == []

def emptyDir(dn):
    """Remove all files in a directory."""
    for fn in os.listdir(dn):
        os.remove(os.path.join(dn, fn))

def copyd2d(src, dst):
    ''' copies all the files from src dir to dst directory.'''
    for fl in os.listdir(src):
        pfl = os.path.join(src, fl)
        shutil.copy(pfl, dst)

def readFile(fn):
    f = open(fn, 'rb')
    d = f.read()
    f.close()
    return d

def writeFile(fn, d):
    f = open(fn, 'wb')
    f.write(d)
    f.close()

def kill_proc(proc, timeout):
    timeout["value"] = True
    proc.kill()

def splitFilename(fn):
    """Split filename into base and extension (base+ext = filename)."""
    if '.' in fn:
        base, ext = fn.rsplit('.', 1)
    else:
        ext = ''
        base = fn
    return base, ext

def delete_special_out_file(path):

    if os.path.exists(path):
        try: 
            os.remove(path)
            #print "delete_special_out_file %s" % path
        except:
            log_print("[-] Fail to delete file %s" % path)

def delete_out_file(path):
    '''this function recives a full path to a file and deletes any file with the same file name, but different extension in the same directory. This is called only when fuzzing creates different files while executing inputs.'''
    (h, t) = os.path.split(path)
    bs, ex = splitFilename(t)
    if ex == '':
        die("Canot delete files as ther eis no extension")
    files = os.listdir(h)
    for fl in files:
        b, e = splitFilename(fl)
        if b == bs and e != ex:
            tfl = os.path.join(h, fl)
            #print "remove %s" % tfl
            os.remove(tfl)

def create_files_dry(num):
    ''' This function creates num number of files in the input directory. This is called if we do not have enough initial population.'''
    files = os.listdir(config.INITIALD)
    ga = operators.GAoperator(random.Random(), [set(), set()])
    fl = random.choice(files)
    bn, ext = splitFilename(fl)
    while (num != 0):
        fl = random.choice(files)
        fp = os.path.join(config.INITIALD, fl)
        p1 = readFile(fp)
        #ch1= ga.mutate(p1)
        ch1 = ga.totally_random(p1, fl)
        np1 = os.path.join(config.INPUTD, "ex-%d.%s" % (num, ext))
        writeFile(np1, ch1)
        num -= 1
        # files.extend(os.listdir(config.INPUTD))
    return 0

def log_print(str):
    print str

    if config.WRITELOG:
        try:
            f = open("vuzzerRun.log", 'a')
            f.write(str)
            f.write("\n")
            f.close()
        except:
            print "[-] Fail to write the log"
            f.close()

def debug_print(str):
    if config.DEBUGINFO:
        print str

    if config.WRITELOG:
        try:
            f = open("vuzzerRun.log", 'a')
            f.write(str)
            f.write("\n")
            f.close()
        except:
            print "[-] Fail to write the log"
            f.close()


def pattern_debug(str):

    if config.SHOWDEBUGPATTERN:
        if config.DEBUGINFO:
            print str

        if config.WRITELOG:
            try:
                f = open("vuzzerRun.log", 'a')
                f.write(str)
                f.write("\n")
                f.close()
            except:
                print "[-] Fail to write the log"
                f.close()


def check_mutation_conflict(history, size, offset):
    ''' check if a new mutation will override an old one '''

    for mu in history:

        debug_print("[*] Checking 0x%x to 0x%x with 0x%x to 0x%x" % (offset,offset+size,mu,mu+history[mu]))

        baseOffsetInMutation = offset >= mu and offset <= (mu + history[mu])
        endOffsetInMutation = offset + size >= mu and offset + size <= (mu + history[mu])

        if baseOffsetInMutation or endOffsetInMutation:
            return mu
    return 0

def taint_based_change(ch, file, operator):
    ''' this function takes a ch string and changes it according to the taintmap of pr input.'''
    # if pr not in config.TAINTMAP:
    #   return ch
    extVal = ['\xFF\xFF\xFF\xFF', '\xFE\xFF\xFF\xFF',
              '\xFE\xFF', '\xFF,\xFE', '\x80\x00\x00\x00', '\x7F\xFF']

    # we change str to list because it saves space when replacing chars at multiple index in a string.
    chlist = list(ch)

    cmpMutationHistory = dict()
    leaMutationHistory = dict()

    leaApplied = 0
    cmpApplied = 0

    # change offsets from LEA
    if file in config.LEAMAP:

        if len(config.LEAMAP[file]) > 0:

            tof = sorted(random.sample(list(config.LEAMAP[file]), max(1, len(config.LEAMAP[file])/2)))

            for of in tof:

                if of >= len(chlist):
                    continue

                newValue = random.choice(extVal)

                if check_mutation_conflict(leaMutationHistory, len(newValue), of) != 0:
                    #log_print("LEA : CONFLICT FOUND WITH LEA")
                    break

                leaApplied += 1

                for i in range(0, len(newValue)):

                    currentOffset = int(of + i)

                    if currentOffset >= len(chlist):
                        break

                    chlist[currentOffset] = newValue[i]

                    if currentOffset not in leaMutationHistory:
                        leaMutationHistory.update({of:1})
                    else:
                        leaMutationHistory[of] += 1

    # change offsets from CMP
    if file in config.TAINTMAP:

        for cmp in config.TAINTMAP[file][1]:

            # TODO : handle duplicates

            for offset in cmp.offsetsInInput:

                if offset >= len(chlist) or offset < -len(chlist): # or len(v) ==0:
                    continue
                
                valueByteArray = cmp.valueToByteArray()

                if check_mutation_conflict(leaMutationHistory, cmp.valueSizePrediction(), offset) != 0:
                    #debug_print("CMP : CONFLICT FOUND WITH LEA")
                    break

                if check_mutation_conflict(cmpMutationHistory, cmp.valueSizePrediction(), offset) != 0:
                    #debug_print("CMP : CONFLICT FOUND WITH CMP")
                    break

                cmpApplied += 1

                # using value size is more accurate than register size
                for i in range(0, cmp.valueSizePrediction()):

                    currentOffset = int(offset + i)
                    
                    if currentOffset >= len(chlist):
                        break

                    chlist[currentOffset] = valueByteArray[i]

                    if currentOffset not in cmpMutationHistory:
                        cmpMutationHistory.update({offset: 1})
                    else:
                        cmpMutationHistory[offset] += 1

                """
                # apply this cmp to child inputs
                if config.HEAVYCHILDINPUTCREATION == True and config.APPLYTAINTTOCHILDINPUTS == True:

                    tmpChildMap = operator.childMap.copy()

                    # we don't care about conflicts anymore
                    for childInput in tmpChildMap:

                        path = os.path.join(config.INPUTD, childInput)

                        # get child input buffer
                        childInputBuffer = list(readFile(path))

                        # add the new mutation to the history
                        operator.mutationHistory[childInput].update({cmp.offsetsInInput[0] : [cmp]})

                        # apply the changes and add it to history
                        childInputBuffer = operator.change_bytes_from_cmp(childInputBuffer, childInput, cmp)

                        # check is exist and write the file
                        if not operator.write_child_input_update(childInput,''.join(childInputBuffer)):
                            del operator.mutationHistory[childInput][cmp.offsetsInInput[0]]
                """

    chlist = apply_more_common_changes(chlist)

    chlist = apply_most_common_changes(chlist)
    
    debug_print("[*] LEA Tainted changes applied : %d" % (leaApplied))
    debug_print("[*] CMP Tainted changes applied : %d" % (cmpApplied))

    return ''.join(list(ch))

def apply_more_common_changes(buffer):
    ''' TODO'''

    for cmp in config.MORECOMMON:

        for offset in cmp.offsetsInInput:

            if offset >= len(buffer) or offset < -len(buffer):  # or len(v) ==0:
                continue
            
            valueByteArray = cmp.valueToByteArray()

            #print cmp
            #show = [chr(n) for n in valueByteArray]
            #print show

            # using value size is more accurate than register size
            for i in range(0, cmp.valueSizePrediction()):

                if int(offset + i) >= len(buffer):
                    break

                buffer[offset + i] = chr(valueByteArray[i])

    return buffer

def apply_most_common_changes(buffer):
    ''' TODO'''

    for cmp in config.MOSTCOMMON:

        for offset in cmp.offsetsInInput:

            if offset >= len(buffer) or offset < -len(buffer):  # or len(v) ==0:
                continue
            
            valueByteArray = cmp.valueToByteArray()

            #print cmp
            #show = [chr(n) for n in valueByteArray]
            #print show

            # using value size is more accurate than register size
            for i in range(0, cmp.valueSizePrediction()):

                if int(offset + i) >= len(buffer):
                    break

                buffer[offset + i] = chr(valueByteArray[i])

    return buffer

def create_files(num):
    ''' This function creates num number of files in the input directory. This is called if we do not have enough initial population.
    Addition: once a new file is created by mutation/cossover, we query MOSTCOMMON dict to find offsets that replace values at those offsets in the new files. Int he case of mutation, we also use taintmap of the parent input to get other offsets that are used in CMP and change them. For crossover, as there are two parents invlived, we cannot query just one, so we do a random change on those offsets from any of the parents in resulting children.'''
    
    log_print("[*] Creating initial population")
    
    if config.HEAVYCHILDINPUTCREATION:
        log_print("\033[0;33m[!] Child input creation enabled : it could take a while\033[0m")

    files = os.listdir(config.INITIALD)
    ga = operators.GAoperator(random.Random(), config.ALLSTRINGS)

    # creating childs
    while (num != 0):

        if random.uniform(0.1, 1.0) > (1.0 - config.PROBCROSS) and (num > 1):
            # we are going to use crossover, so we get two parents.
            par = random.sample(files, 2)
            bn, ext = splitFilename(par[0])
            # fp1=os.path.join(config.INPUTD,par[0])
            # fp2=os.path.join(config.INPUTD,par[1])
            fp1 = os.path.join(config.INITIALD, par[0])
            fp2 = os.path.join(config.INITIALD, par[1])
            p1 = readFile(fp1)
            p2 = readFile(fp2)
            ch1, ch2 = ga.crossover(p1, p2)  # ,par[0],par[1])
            # now we make changes according to taintflow info.
            ch1 = taint_based_change(ch1, par[0], ga)
            ch2 = taint_based_change(ch2, par[1], ga)
            np1 = os.path.join(config.INPUTD, "cross-ex-g%d-%d.%s" % (config.CURRENTGEN,num, ext))
            np2 = os.path.join(config.INPUTD, "cross-ex-g%d-%d.%s" % (config.CURRENTGEN,num-1, ext))
            writeFile(np1, ch1)
            writeFile(np2, ch2)
            num -= 2
        else:
            fl = random.choice(files)
            bn, ext = splitFilename(fl)
            # fp=os.path.join(config.INPUTD,fl)
            fp = os.path.join(config.INITIALD, fl)
            p1 = readFile(fp)
            ch1 = ga.mutate(p1, fl)
            ch1 = taint_based_change(ch1, fl, ga)
            np1 = os.path.join(config.INPUTD, "ex-g%d-%d.%s" % (config.CURRENTGEN, num, ext))
            writeFile(np1, ch1)
            num -= 1
    
    log_print("[*] Done with initial population")


    if config.ALFINPUTREDUCTION:

        files = os.listdir(config.INPUTD)

        # collect all new files
        createdFiles = []

        for f in files:
            if not "cross-ex-g" in f and not "ex-g" in f:
                continue
            createdFiles.append(os.path.join(config.INPUTD, f))

        if len(createdFiles) == 0:
            log_print("[-] ALFINPUTREDUCTION : No input created")
        else:
            log_print("[*] Starting input reduction (%d files)" % (len(createdFiles)))
            
            # start reduction
            afl.reduction(createdFiles)

    if config.ALFCHILDINPUTREDUCTION and config.HEAVYCHILDINPUTCREATION:

        # collect all childs
        createdChilds = []

        for child in ga.childMap:
            createdChilds.append(os.path.join(config.INPUTD, child))

        if len(createdChilds) > 0:
        
            log_print("[*] Starting child input reduction (%d files)" % (len(createdChilds)))

            # start reduction
            afl.reduction(createdChilds)
        else:
            log_print("[-] ALFINPUTREDUCTION : No child input created")


    #if config.HEAVYCHILDINPUTCREATION:
    #    log_print("\033[0;33m[!] Child input creation enabled : it could take a while\033[0m")


    return 0

def createNextGeneration3(fit, gn):
    ''' this funtion generates new generation. This is the implemntation of standard ilitism approach. We are also addressing "input bloating" issue  by selecting inputs based on its length. the idea is to select inputs for crossover their lenths is less than the best input's length. Oterwise, such inputs directly go for mutation whereby having a chance to reduce their lengths.'''

    if config.HEAVYCHILDINPUTCREATION:
        log_print("\033[0;33m[!] Child input creation enabled : it could take a while\033[0m")

    files = os.listdir(config.INPUTD)
    ga = operators.GAoperator(random.Random(), config.ALLSTRINGS)
    sfit = sorted(fit.items(), key=itemgetter(1), reverse=True)
    bfp = os.path.join(config.INPUTD, sfit[0][0])
    bestLen = os.path.getsize(bfp)
    fitnames = [k for k, v in sfit]
    # as our selection policy requires that each input that trigerred a new BB must go to the next generation, we need to find a set of BEST BBs and merge it with this set of inputs.
    best = set(fitnames[:config.BESTP])  # .union(set(config.SPECIALENTRY))
    # best.update(config.CRASHIN)
    #print "best",best, len(best)
    if len(best) % 2 != 0:
        for nm in fitnames:
            if nm not in best:
                best.add(nm)
                break

    if config.GOTSTUCK == True:
        heavyMutate(config.INPUTD, ga, best)

    # here we check for file length and see if we can reduce lengths of some.
    #if gn % config.skipGen == 0:
    #    mn, mx, avg = getFileMinMax(config.INPUTD)
    #    filesTrim(config.INPUTD, avg, bestLen, config.minLength, ga, best)
    
    i = 0
    bn, ext = splitFilename(sfit[i][0])
    #limit=config.POPSIZE - config.BESTP
    limit = config.POPSIZE - len(best)
    #print "nextgen length %d - %d\n"%(limit, len(best))
    #raw_input("enter key")

    # this variable is used to count new inputs generated with crashing inputs.
    crashnum = 0
    emptyDir(config.INTER)
    copyd2d(config.SPECIAL, config.INTER)

    if config.ERRORBBON == True:
        copyd2d(config.INITIALD, config.INTER)

    while i < limit:
        cutp = int(random.uniform(0.4, 0.8)*len(fitnames))
        # we are going to use crossover s.t. we want to choose best parents frequently, but giving chance to less fit parents also to breed. the above cut gives us an offset to choose parents from. Note that last 10% never get a chance to breed.
        #print "crossover"
        par = random.sample(fitnames[:cutp], 2)
        fp1 = os.path.join(config.INPUTD, par[0])
        fp2 = os.path.join(config.INPUTD, par[1])
        inpsp = os.listdir(config.INTER)

        sin1 = 'xxyy'
        sin2 = 'yyzz'
        if len(inpsp) > 0:
            if random.randint(0, 9) > config.SELECTNUM:
                sin1 = random.choice(inpsp)
                fp1 = os.path.join(config.INTER, sin1)
            if random.randint(0, 9) > config.SELECTNUM:
                sin2 = random.choice(inpsp)
                fp2 = os.path.join(config.INTER, sin2)
        np1 = os.path.join(config.INPUTD, "new-g%d-%d.%s" % (gn, i, ext))
        np2 = os.path.join(config.INPUTD, "new-g%d-%d.%s" % (gn, i+1, ext))
        p1 = readFile(fp1)
        p2 = readFile(fp2)

        if (len(p1) > bestLen) or (len(p2) > bestLen):
            #print "no crossover"
            #mch1= ga.mutate(p1)
            if sin1 != 'xxyy':
                mch1 = ga.mutate(p1, sin1)
                mch1 = taint_based_change(mch1, sin1, ga)
            else:
                mch1 = ga.mutate(p1, par[0])
                mch1 = taint_based_change(mch1, par[0], ga)
            #mch2= ga.mutate(p2)
            if sin2 != 'yyzz':
                mch2 = ga.mutate(p2, sin2)
                mch2 = taint_based_change(mch2, sin2, ga)
            else:
                mch2 = ga.mutate(p2, par[1])
                mch2 = taint_based_change(mch2, par[1], ga)
            if len(mch1) < 3 or len(mch2) < 3:
                die("zero input created")
            writeFile(np1, mch1)
            writeFile(np2, mch2)
            i += 2
            # continue
        else:
            #print "crossover"
            ch1, ch2 = ga.crossover(p1, p2)
            # now we do mutation on these children, one by one
            if random.uniform(0.1, 1.0) > (1.0 - config.PROBMUT):
                #mch1= ga.mutate(ch1)
                if sin1 != 'xxyy':
                    mch1 = ga.mutate(ch1, sin1)
                    mch1 = taint_based_change(mch1, sin1, ga)
                else:
                    mch1 = ga.mutate(ch1, par[0])
                    mch1 = taint_based_change(mch1, par[0], ga)
                if len(mch1) < 3:
                    die("zero input created")
                writeFile(np1, mch1)
            else:
                if sin1 != 'xxyy':
                    ch1 = taint_based_change(ch1, sin1, ga)
                else:
                    ch1 = taint_based_change(ch1, par[0], ga)
                writeFile(np1, ch1)
            if random.uniform(0.1, 1.0) > (1.0 - config.PROBMUT):
                #mch2= ga.mutate(ch2)
                if sin2 != 'yyzz':
                    mch2 = ga.mutate(ch2, sin2)
                    mch2 = taint_based_change(mch2, sin2, ga)
                else:
                    mch2 = ga.mutate(ch2, par[1])
                    mch2 = taint_based_change(mch2, par[1], ga)

                if len(mch2) < 3:
                    die("zero input created")
                writeFile(np2, mch2)
            else:
                if sin2 != 'yyzz':
                    ch2 = taint_based_change(ch2, sin2, ga)
                else:
                    ch2 = taint_based_change(ch2, par[1], ga)

                writeFile(np2, ch2)
            i += 2

    # now we need to delete last generation inputs from INPUTD dir, preserving BEST inputs.
    #best=[k for k,v in sfit][:config.BESTP]
    #print "gennext loop ",i
    # raw_input("enterkey..")

    for fl in files:
        if fl in best:
            continue
        os.remove(os.path.join(config.INPUTD, fl))

    if config.ALFINPUTREDUCTION:

        files = os.listdir(config.INPUTD)

        # collect all new files
        createdFiles = []

        for f in files:
            if not "cross-ex-g" in f and not "ex-g" in f and not "new-g" in f: 
                continue
            createdFiles.append(os.path.join(config.INPUTD, f))

        if len(createdFiles) == 0:
            log_print("[-] ALFINPUTREDUCTION : No input created")
        else:
            log_print("[*] Starting input reduction (%d files)" % (len(createdFiles)))

            # start reduction
            afl.reduction(createdFiles)

    if config.ALFCHILDINPUTREDUCTION and config.HEAVYCHILDINPUTCREATION:

        # collect all childs
        createdChilds = []

        for child in ga.childMap:
            createdChilds.append(os.path.join(config.INPUTD, child))

        if len(createdChilds) > 0:
        
            log_print("[*] Starting child input reduction (%d files)" % (len(createdChilds)))

            # start reduction
            afl.reduction(createdChilds)
        else:
            log_print("[-] ALFINPUTREDUCTION : No child input created")


    # lets check if everything went well!!!
    # if len(os.listdir(config.INPUTD))!=config.POPSIZE:
    #    die("Something went wrong while creating next gen inputs.. check it!")

    log_print("[*] Done with new generation population")

    return 0

def prepareBBOffsets():
    ''' This functions load pickle files to prepare BB weights and strings found in binary. The strings are read from a pickle file, generated by IDAPython. This file contains a tuple of two sets (A,B). A= set of all strings found at CMP instructions. B= set of individual bytes, generated from strings of A and CMP.'''
    tempFull = set()
    tempByte = set()
    for i in range(config.LIBNUM):
        pFD = open(config.LIBPICKLE[i], "r")
        tBB = pickle.load(pFD)
        for tb in tBB:
            ad = tb+int(config.LIBOFFSETS[i], 0)
            # we do not consider weights greater than BBMAXWEIGHT and we take log2 of weights as final weight.
            if tBB[tb][0] > config.BBMAXWEIGHT:
                config.ALLBB[ad] = int(math.log(config.BBMAXWEIGHT, 2))
            else:
                config.ALLBB[ad] = int(math.log((tBB[tb][0]+1), 2))
            if i == 0:
                config.cAPPBB.add(ad)
            config.cALLBB.add(ad)
        pFD.close()
        tFD = open(config.NAMESPICKLE[i], "r")
        tdata = pickle.load(tFD)
        tempFull.update(tdata[0])  # set of full strings from the binary
        tempByte.update(tdata[1])  # set of individual bytes from the binary
    if config.NOFFBYTES == True:
        tempFull.discard('\xFF\xFF\xFF\xFF')
        tempFull.discard('\xff\xff\xff\xff')
        tempFull.discard('\x00\xFF\xFF\xFF\xFF')
        tempFull.discard('\x00\xff\xff\xff\xff')
    config.ALLSTRINGS.append(tempFull.copy())
    config.ALLSTRINGS.append(tempByte.copy())

def prepareLibBBOffsets(loffset):
    ''' This functions load pickle files to prepare BB weights in the case of loadtime image address change.'''
    config.ALLBB.clear()
    config.cALLBB.clear()
    for i in range(config.LIBNUM):
        pFD = open(config.LIBPICKLE[i], "r")
        tBB = pickle.load(pFD)
        if i == 0:
            for tb in tBB:
                ad = tb+int(config.LIBOFFSETS[i], 0)
                config.ALLBB[ad] = tBB[tb][0]
                # config.cAPPBB.add(ad)
                config.cALLBB.add(ad)
        else:
            for tb in tBB:
                ad = tb+loffset
                config.ALLBB[ad] = tBB[tb][0]
                config.cALLBB.add(ad)
        pFD.close()

def fitnesCal2(bbdict, cinput, ilen):
    '''
    calculates fitness of each input based on its execution trace. The difference from "fitnesCal()" is that it again multiplies fitnes score by the number of BB executed.
    '''

    config.GOTSPECIAL = False
    score = 0.0
    bbNum = 0
    tempset = config.ERRORBBALL.union(config.TEMPERRORBB)
    # calculate negative weight for error BBs
    numEBB = len(set(bbdict) & tempset)
    if numEBB > 0:
        ew = -len(bbdict)*config.ERRORBBPERCENTAGE/numEBB

    # we make sure that newly discovered BBs are not related to error BB.
    tset = set(bbdict)-tempset
    config.cPERGENBB.update(tset)
    if not tset <= config.SEENBB:  # and not tset <=tempset:
        diffb = tset-config.SEENBB
        # let input pruning, lets set the flag is this input has found a new BB
        config.GOTSPECIAL = True
        config.SEENBB.update(diffb)
    for bbadr in bbdict:
        # config.cPERGENBB.add(bbadr)#added for code-coverage
        # if bbadr in tempset:#config.ERRORBBALL:
        #    continue
        #bbNum +=1
        bbfr = bbdict[bbadr]
        if bbfr > config.BBMAXFREQ:
            bbfr = config.BBMAXFREQ
        # 1 is added to avoid having log(1)=0 case
        lgfr = int(math.log(bbfr+1, 2))
        # if bbadr not in config.SEENBB:
        #    config.SEENBB.add(bbadr)
        #    config.SPECIALENTRY.append(cinput)
        if bbadr in tempset:
            #print"[0x%x] Error BB hit (%f ) !"%(bbadr,ew)
            score = score+(lgfr*ew)
        elif bbadr in config.ALLBB:
            #print"[0x%x] BB hit (%d - %f) !"%(bbadr,bbfr,config.ALLBB[bbadr])
            score = score+(lgfr*config.ALLBB[bbadr])
            bbNum += 1
        else:
            #print"[0x%x] BB missed (%d) !"%(bbadr,bbfr)
            score = score+lgfr
            bbNum += 1
    del tempset
    #print "BBNum", bbNum
    # return round((score*bbNum)/(ilen*1.0),2)
    # return (score*bbNum)/totalFreq
    if ilen > config.MAXINPUTLEN:
        return (score*bbNum)/int(math.log(ilen+1, 2))
    else:
        return score*bbNum

def fitnesNoWeight(bbdict, cinput, ilen):
    '''
    calculates fitness of each input based on its execution trace. The difference from "fitnesCal()" is that it again multiplies fitnes score by the number of BB executed.
    '''

    score = 0.0
    bbNum = 0
    tempset = config.ERRORBBALL.union(config.TEMPERRORBB)
    tset = set(bbdict)
    config.cPERGENBB.update(tset)
    if not tset <= config.SEENBB and not tset <= tempset:
        diffb = tset-config.SEENBB
        config.SEENBB.update(diffb)
        todel = set()
        tofix = set()
        for tk, tv in config.TMPBBINFO.iteritems():
            if tv <= diffb:
                todel.add(tk)
            elif len(tv & diffb) > 0:
                tofix.add(tk)
            else:
                pass
        for tb in todel:
            del config.TMPBBINFO[tb]
        for tb in tofix:
            config.TMPBBINFO[tb].difference_update(diffb)
        config.TMPBBINFO[cinput] = diffb.copy()
        # del tempset
        del todel
        del diffb
        del tofix
        # return 10 #some random value as we don;t care much about fitness score of such input as they go to next gen anyway!
    for bbadr in bbdict:
        # config.cPERGENBB.add(bbadr)#added for code-coverage
        if bbadr in tempset:  # config.ERRORBBALL:
            continue
        bbNum += 1
        bbfr = bbdict[bbadr]
        if bbfr > config.BBMAXFREQ:
            bbfr = config.BBMAXFREQ
        # 1 is added to avoid having log(1)=0 case
        lgfr = int(math.log(bbfr+1, 2))

        score = score+lgfr
    del tempset

    if ilen > config.MAXINPUTLEN:
        return (score*bbNum)/int(math.log(ilen+1, 2))
    else:
        return score*bbNum

def getFileMinMax(dirP):
    files = os.listdir(dirP)
    sizes = [os.path.getsize(os.path.join(dirP, s)) for s in files]
    return min(sizes), max(sizes), sum(sizes)/len(sizes)

def filesTrim(dpath, aveLen, bestLen, initLen, ga, bestin):
    '''
    this function is used to trim the lenghts of inputs.
    TODO: we can also ignore best inputs. For that we need to have another parameter that contains names of best inputs.
    '''
    files = os.listdir(dpath)
    if aveLen > 100*initLen:
        for fl in files:
            if fl in bestin:
                continue
            if random.uniform(0.1, 1.0) > 0.3:
                tpath = os.path.join(dpath, fl)
                if os.path.getsize(tpath) > bestLen:
                    fd = open(tpath, 'r+b')
                    p = fd.read()
                    ch = ga.double_eliminate(p, fl)
                    ch = taint_based_change(ch, fl, ga)
                    fd.seek(0)
                    fd.truncate()
                    fd.write(ch)
                    fd.close()
    elif aveLen > 50*initLen:
        for fl in files:
            if fl in bestin:
                continue
            if random.uniform(0.1, 1.0) > 0.3:
                tpath = os.path.join(dpath, fl)
                if os.path.getsize(tpath) > bestLen:
                    fd = open(tpath, 'r+b')
                    p = fd.read()
                    ch = ga.eliminate(p, fl)
                    ch = taint_based_change(ch, fl, ga)
                    fd.seek(0)
                    fd.truncate()
                    fd.write(ch)
                    fd.close()
    elif aveLen > 10*initLen:
        for fl in files:
            if fl in bestin:
                continue
            if random.uniform(0.1, 1.0) > 0.4:
                tpath = os.path.join(dpath, fl)
                if os.path.getsize(tpath) > bestLen:
                    fd = open(tpath, 'r+b')
                    p = fd.read()
                    ch = ga.eliminate_random(p, fl)
                    ch = taint_based_change(ch, fl, ga)
                    fd.seek(0)
                    fd.truncate()
                    fd.write(ch)
                    fd.close()
    else:
        pass

def calculateCov():

    if len(config.cAPPBB) == 0:
        return 0, 0
    if config.LIBNUM == 1:
        return 100-(len(config.cAPPBB.difference(config.SEENBB))*100/len(config.cAPPBB)), 0
    else:
        return 100-(len(config.cAPPBB.difference(config.SEENBB))*100/len(config.cAPPBB)), 100-(len(config.cALLBB.difference(config.SEENBB))*100/len(config.cALLBB))

def heavyMutate(dpath, ga, bestin):
    ''' this function performs heavy mutation on the current generation.'''
    files = os.listdir(dpath)
    log_print( "\033[0;33m[!] Starting heavy mutation\033[0m" )
    for fl in files:
        if fl in bestin:
            continue
        tpath = os.path.join(dpath, fl)
        fd = open(tpath, 'r+b')
        p = fd.read()
        ch = ga.double_full_mutate(p, fl)
        ch = taint_based_change(ch, fl, ga)
        fd.seek(0)
        fd.truncate()
        fd.write(ch)
        fd.close()

def remove_files(fitnes):
    ''' This function removes files which are longer s.t. there are shorter files with same fitness value.'''
