"""
operators.py
    This files implements GA operators viz mutation and crossover for fuzzing data.

This is partly based on mutation implementation by Jesse Burns (jesse@isecpartners.com)
"""
import random
import config
import cmpOperation as cmpO
from cmpOperation import taintTypeEnum
import gautils
import hashlib
import os
import os.path

class GAoperator:
    """ create it with a random and have it manipulate data for you. """

    DENOM = 50  # change at most 0-2 % of the binary with each fuzz
    r = None
    int_slide_position = 0
    slide_step = 1

    ALL_CHARS = [chr(n) for n in xrange(256)]
    HIGH_CHARS = [chr(n) for n in xrange(128, 256)]

    def __init__(self, random_object, extra, demoninator=50):
        ''' the 3rd parameter extra us a list of two sets. 1st set is a set of full strings from binary, whereas 2nd set is a set of individual bytes from those strings.'''
        self.DENOM = demoninator
        self.r = random_object
        self.full = list(extra[0])
        self.obytes = list(extra[1])

        self.currentTaintMap = dict()
        self.mutationHistory = dict()
        self.childMap = dict()

        self.childCount = 0

        if len(self.full) > 0:
            self.allStrings = [self.full, self.full,
                               self.HIGH_CHARS, self.obytes]
        elif len(self.obytes) > 0:
            self.allStrings = [self.obytes, self.obytes, self.HIGH_CHARS]
        else:
            self.allStrings = [self.ALL_CHARS]

        self.currentMutation = -1

    def getOffset(self, file, org):

        org = list(org)

        usedFile = file

        if file not in self.currentTaintMap.keys():

            randomFile = self.r.choice(list(self.currentTaintMap.keys()))
            alloffset = self.currentTaintMap[randomFile][0]

            usedFile = randomFile
        else:
            alloffset = self.currentTaintMap[file][0]

        if len(alloffset) == 0:
            gautils.debug_print("[-] Fail to find offset in map")
            return []

        attemps = 10

        cmp = -1

        # I try to optimize the offset selection by selecting only not used offsets
        while attemps != 0:
            cmp = self.r.choice(alloffset)

            if cmp.offsetsInInput[0] in self.mutationHistory[file]:
                attemps -= 1
                continue
            else:
                break

        gautils.debug_print("[*] Testing offset 0x%x" % (cmp.offsetsInInput[0]))

        conflictList = self.check_mutation_conflict_from_register_size(cmp.offsetsInInput[0], cmp.cmpSize, file)

        conflictWithParent = False

        createdChild = -1

        # create the mutation buffer
        self.currentMutation = self.r.sample(self.r.choice(self.allStrings), cmp.cmpSize)

        # is there is not offset without conflicts available 
        if len(conflictList) > 0:

            gautils.debug_print("[-] There is conflict with the parent")

            createTheChild = random.uniform(0.1, 1.0) > (1.0 - config.CHILDINPUTCREATIONRANDOMNESS)

            # creating a child for each conflict
            if config.HEAVYCHILDINPUTCREATION == True and self.childCount < config.CHILDINPUTMAXSIZE and createTheChild:

                conflictWithParent = True

                # create the input child
                name,inputBuffer = self.create_child_input(file, org, conflictList, cmp)

                # check is exist and write the file
                if not self.write_child_input(name,inputBuffer):
                    del self.mutationHistory[name]
                    createdChild = -1
                else:
                    gautils.debug_print("[+] Child input created %s" % (name))
                    createdChild = name
        else:
            gautils.debug_print("[+] There is no conflict in parent")

        # apply the cmp to the child inputs history
        if len(self.childMap) > 0 and config.HEAVYCHILDINPUTCREATION == True:

            # childMap will change during this
            tmpChildMap = self.childMap.copy()

            for childInput in tmpChildMap:

                if createdChild != -1 and childInput == createdChild:
                    continue

                # get conflicts for each child input
                conflictChildList = self.check_mutation_conflict_from_register_size(cmp.offsetsInInput[0], cmp.cmpSize, childInput)

                path = os.path.join(config.INPUTD, childInput)

                # get child input buffer
                childInputBuffer = list(gautils.readFile(path))

                createTheChild = random.uniform(0.1, 1.0) > (1.0 - config.CHILDINPUTCREATIONRANDOMNESS)

                # conflict found
                # NOTE : we still apply cmp to child inputs if there is no conflicts
                if len(conflictChildList) > 0 and self.childCount < config.CHILDINPUTMAXSIZE and createTheChild:
                    
                    gautils.debug_print("[-] There is conflict with child inputs")

                    # create input name

                    # get the extension
                    # TODO : find a better way to do it
                    bn, ext = gautils.splitFilename(usedFile)
                    name = "heavy-child-g%d-%d.%s" % (config.CURRENTGEN,self.childCount, ext)

                    # create the input child
                    inputBuffer = self.create_new_child_from_old(name, childInput, childInputBuffer, conflictChildList, cmp)

                    # check is exist and write the file
                    if not self.write_child_input(name,''.join(inputBuffer)):
                        del self.mutationHistory[name]
                    else:
                        gautils.debug_print("[+] Child input created %s" % (name))

                # no conflict (maybe while self.childCount == config.CHILDINPUTMAXSIZE)
                elif len(conflictChildList) == 0:

                    gautils.debug_print("[+] There is no conflict in child inputs")
                    gautils.debug_print("[+] Updating child input %s" % (childInput))

                    # add the new mutation to the history
                    self.mutationHistory[childInput].update({cmp.offsetsInInput[0] : [cmp]})

                    # apply the changes and add it to history
                    childInputBuffer = self.change_bytes_from_cmp(childInputBuffer, childInput, cmp)

                    # check is exist and write the file
                    if not self.write_child_input_update(childInput,''.join(childInputBuffer)):
                        del self.mutationHistory[childInput][cmp.offsetsInInput[0]]
                    else:
                        gautils.debug_print("[+] Child input updated %s" % (childInput))
        
        # true only if config.HEAVYCHILDINPUTCREATION == True
        if conflictWithParent == True:
            # the parent will not use the mutation because of the conflict
            return []

        else:
            # TODO : improve
            self.mutationHistory[file].update({cmp.offsetsInInput[0] : [cmp]})

            # we will not use this cmp again
            self.currentTaintMap[usedFile][0].remove(cmp)

        # python tricks to not access to cmp function is it None
        return [cmp]

    def write_child_input_update(self,name,inputBuffer):

        # compute its hash
        inputHash = hashlib.md5(inputBuffer).hexdigest()

        # check if the child input already exist
        if inputHash not in self.childMap.values():

            # override the file
            path = os.path.join(config.INPUTD, name)
            gautils.writeFile(path, inputBuffer)

            # change its hash in history
            self.childMap[name] = inputHash

            return True
        else:
            gautils.debug_print("[-] Child input %s already exist" % (inputHash))

            return False

    def write_child_input(self,name,inputBuffer):

        # compute its hash
        inputHash = hashlib.md5(inputBuffer).hexdigest()

        # check if the child input already exist
        if inputHash not in self.childMap.values():

            # write the file
            path = os.path.join(config.INPUTD, name)
            gautils.writeFile(path, inputBuffer)

            # update child input history
            self.childMap.update({name:inputHash})
            self.childCount += 1

            return True
        else:
            gautils.debug_print("[-] Child input %s already exist" % (inputHash))

            return False

    def create_child_input(self, parentInputFL, parentInput, conflicts, newMutation):
        ''' TODO '''

        mutatedInput = parentInput[:]

        # craft the child input name

        # get the extension
        # TODO : find a better way to do it
        bn, ext = gautils.splitFilename(parentInputFL)
        name = "heavy-child-g%d-%d.%s" % (config.CURRENTGEN,self.childCount, ext)

        self.mutationHistory.update({name:dict()})

        # remove old conflicts mutations
        # NOTE : if there is a index out of array here, there is a problem
        for c in conflicts:
            
            #for cmp in c.offsetsInInput:

            mutationHistoryData = self.mutationHistory[parentInputFL][c.offsetsInInput[0]][1]

            for offset in mutationHistoryData:
                i = 0
                for byte in mutationHistoryData[offset]:
                    mutatedInput[offset+i] = (byte)
                    i += 1

        # register the new mutation in history
        self.mutationHistory[name].update({newMutation.offsetsInInput[0] : [newMutation]})

        # add the history directory
        self.mutationHistory[name][newMutation.offsetsInInput[0]].append(dict())

        mutationHistoryData = self.mutationHistory[name][newMutation.offsetsInInput[0]][1]

        # apply new mutation
        for offset in newMutation.offsetsInInput:

            mutationHistoryData.update({offset:[]})

            mutationHistoryDataCurrent = mutationHistoryData[offset]
            
            for i in range(0, newMutation.cmpSize):

                if int(offset + i) >= len(mutatedInput):
                    break

                if newMutation.taintType == taintTypeEnum.UNKNOWN:

                    # save the old value
                    mutationHistoryDataCurrent.append(mutatedInput[(offset + i)])

                    # applying the conflicted parent mutation
                    mutatedInput[(offset + i)] = self.currentMutation[i]

                elif newMutation.taintType == taintTypeEnum.SINGLE_BYTE:

                    # save the old value
                    mutationHistoryDataCurrent.append(mutatedInput[(offset + i)])

                    # applying the conflicted parent mutation
                    mutatedInput[(offset + i)] = self.currentMutation[0]

                elif newMutation.taintType == taintTypeEnum.ARRAY:

                    # save the old value
                    mutationHistoryDataCurrent.append(mutatedInput[(offset + i)])

                    # applying the conflicted parent mutation
                    # TODO : improve strategy
                    mutatedInput[(offset + i)] = self.currentMutation[i]

        # apply magic bytes and most common bytes
        mutatedInput = gautils.apply_more_common_changes(mutatedInput)
        mutatedInput = gautils.apply_most_common_changes(mutatedInput)

        # build a string with the mutated input
        mutatedInput = ''.join(mutatedInput)

        return name,mutatedInput

    def create_new_child_from_old(self, name, parentInputFL, parentInput, conflicts, newMutation):
        ''' TODO '''

        mutatedInput = parentInput

        if parentInputFL not in self.mutationHistory:
            gautils.die("[-] Create a child (%s) from old one (%s), but old one is not in history : Impossible !" % (name,parentInputFL))

        self.mutationHistory.update({name:dict()})

        # remove old conflicts mutations
        # NOTE : if there is a index out of array here, there is a problem
        for c in conflicts:
            
            mutationHistoryData = self.mutationHistory[parentInputFL][c.offsetsInInput[0]][1]

            for offset in mutationHistoryData:
                i = 0
                for byte in mutationHistoryData[offset]:
                    mutatedInput[offset+i] = (byte)
                    i += 1

        # register the new mutation in history
        self.mutationHistory[name].update({newMutation.offsetsInInput[0] : [newMutation]})

        # add the history directory
        self.mutationHistory[name][newMutation.offsetsInInput[0]].append(dict())

        mutationHistoryData = self.mutationHistory[name][newMutation.offsetsInInput[0]][1]

        # apply new mutation
        for offset in newMutation.offsetsInInput:

            mutationHistoryData.update({offset:[]})

            mutationHistoryDataCurrent = mutationHistoryData[offset]
            
            for i in range(0, newMutation.cmpSize):

                if int(offset + i) >= len(mutatedInput):
                    break

                if newMutation.taintType == taintTypeEnum.UNKNOWN:

                    # save the old value
                    mutationHistoryDataCurrent.append(mutatedInput[(offset + i)])

                    # applying the conflicted child input mutation
                    mutatedInput[(offset + i)] = self.currentMutation[i]

                elif newMutation.taintType == taintTypeEnum.SINGLE_BYTE:

                    # save the old value
                    mutationHistoryDataCurrent.append(mutatedInput[(offset + i)])

                    # applying the conflicted child input mutation
                    mutatedInput[(offset + i)] = self.currentMutation[0]

                elif newMutation.taintType == taintTypeEnum.ARRAY:

                    # save the old value
                    mutationHistoryDataCurrent.append(mutatedInput[(offset + i)])

                    # applying the conflicted child input mutation
                    # TODO : improve strategy
                    mutatedInput[(offset + i)] = self.currentMutation[i]
            
        mutatedInput = gautils.apply_more_common_changes(mutatedInput)
        mutatedInput = gautils.apply_most_common_changes(mutatedInput)

        # build a string with the mutated input
        mutatedInput = ''.join(mutatedInput)

        return mutatedInput

    def check_mutation_conflict_from_register_size(self, offset, size, file):
        ''' check if a new mutation will override an old one with the size of the register '''

        conflictList = []

        for mu in self.mutationHistory[file]:

            gautils.debug_print("[*] Checking 0x%x to 0x%x with 0x%x to 0x%x" % (offset,offset+size,mu,mu+self.mutationHistory[file][mu][0].cmpSize))

            baseOffsetInMutation = offset >= mu and offset <= (mu + self.mutationHistory[file][mu][0].cmpSize)
            endOffsetInMutation = offset + size >= mu and offset + size <= (mu + self.mutationHistory[file][mu][0].cmpSize)

            if baseOffsetInMutation or endOffsetInMutation:
                conflictList.append(self.mutationHistory[file][mu][0])

        return conflictList

    def check_mutation_conflict_from_value_size(self, offset, size, file):
        ''' check if a new mutation will override an old one with the size of the value '''

        conflictList = []

        for mu in self.mutationHistory[file]:

            gautils.debug_print("[*] Checking 0x%x to 0x%x with 0x%x to 0x%x" % (offset,offset+size,mu,mu+self.mutationHistory[file][mu][0].valueSizePrediction()))

            baseOffsetInMutation = offset >= mu and offset <= (mu + self.mutationHistory[file][mu][0].valueSizePrediction())
            endOffsetInMutation = offset + size >= mu and offset + size <= (mu + self.mutationHistory[file][mu][0].valueSizePrediction())

            if baseOffsetInMutation or endOffsetInMutation:
                conflictList.append(self.mutationHistory[file][mu][0])

        return conflictList

    def random_string(self, size, source=None):
        if source is None:
            source = self.allStrings
        result = ''
        while len(result) < size:
            result = result+self.r.choice(self.r.choice(source))
        return result

    def change_bytes_from_cmp(self, original, fl, cmp):

        if len(self.currentTaintMap) == 0:
            return original

        if self.currentMutation == -1:
            gautils.die("[-] Mutation not created : impossible !")
            return original

        buffer = list(original)

        if cmp.cmpSize == -1:
            #print "change_bytes: cmp.cmpSize == -1"
            return original

        bytesChanged = 0

        mutationHistory = self.mutationHistory[fl][cmp.offsetsInInput[0]]

        if cmp.offsetsInInput[0] in self.mutationHistory[fl] and len(mutationHistory) == 1:
            mutationHistory.append(dict())

        mutationHistoryData = mutationHistory[1]

        for offset in cmp.offsetsInInput:

            if offset >= len(buffer):
                continue

            mutationHistoryData.update({offset:[]})

            mutationHistoryDataCurrent = mutationHistoryData[offset]

            for i in range(0,cmp.cmpSize):

                currentOffset = int(offset + i)

                if currentOffset >= len(buffer):
                    break

                if cmp.taintType == taintTypeEnum.UNKNOWN:

                    # save the value
                    mutationHistoryDataCurrent.append(buffer[currentOffset])

                    buffer[currentOffset] = self.currentMutation[i]
                    bytesChanged += 1

                elif cmp.taintType == taintTypeEnum.SINGLE_BYTE:

                    # save the value
                    mutationHistoryDataCurrent.append(buffer[currentOffset])

                    buffer[currentOffset] = self.currentMutation[0]
                    bytesChanged += 1

                elif cmp.taintType == taintTypeEnum.ARRAY:

                    # save the value
                    mutationHistoryDataCurrent.append(buffer[currentOffset])

                    # TODO : improve strategy
                    buffer[currentOffset] = self.currentMutation[i]
                    bytesChanged += 1

            gautils.debug_print("[+] Mutation applied 0x%x to 0x%x" % (offset, offset + bytesChanged))

        return ''.join([e for e in buffer])

    def change_bytes(self, original, fl):

        if len(self.currentTaintMap) == 0:
            return original

        cmp = self.getOffset(fl, original)

        if len(cmp) == 0:
            gautils.debug_print("[-] Fail to find offset (it could be because of conflict)")
            return original

        cmp = cmp[0]

        gautils.debug_print("[*] Mutation will be on 0x%x" % cmp.offsetsInInput[0])

        return self.change_bytes_from_cmp(original, fl, cmp)


    def change_random_full(self, original, fl):
        size = len(original)
        add_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.r.randint(0, size - add_size)

        if cut_pos in config.TAINTMAP[fl][0].keys():
            add_size = config.TAINTMAP[fl][0][cut_pos]
            
        if len(self.full) > 1:
            #result = ''.join([original[:cut_pos], self.r.choice(self.full), original[cut_pos:]])
            result = ''.join([original[:cut_pos], self.random_string(
                add_size, [self.full]), original[cut_pos:]])
    #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
            return result
        elif len(self.obytes) > 2 and size > 3:
            pos = self.r.sample([k for k in xrange(1, size-1)], 2)
            result = ''.join([original[:pos[0]], self.r.choice(
                self.obytes), original[pos[0]:pos[1]], self.r.choice(self.obytes), original[pos[1]:]])
        #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
            return result
        else:
            result = ''.join([original[:cut_pos], self.random_string(
                add_size), original[cut_pos + add_size:]])
    #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
        return result


    def totally_random(self, original, fl):
        size = len(original)
        return self.random_string(self.r.randint(100, 1000))
       # return ''.join([self.r.choice(self.r.choice(self.allStrings+self.full)) for n in xrange(size)])

    def int_slide(self, original, fl):
        size = len(original)
        # , '\xAA\xAA\xAA\xAA', '\x41\x41\x41\x41'])
        value = self.r.choice(
            ['\xFF\xFF\xFF\xFF', '\x80\x00\x00\x00', '\x00\x00\x00\x00'])
        if size < 4:
            return value[:size]
        start = self.int_slide_position % size
        if start > size - 4:
            result = original[:start] + value
        else:
            result = ''.join([original[:start], value, original[start + 4:]])
        self.int_slide_position += self.slide_step
        return result

    def double_fuzz(self, original, fl):
        """ runs two fuzzers (one or more of which could be double_fuzz itself! """
        result = self.r.choice(self.mutators)(self, original, fl)
        return self.r.choice(self.mutators)(self, result, fl)

    def double_full_mutate(self, original, fl):
        ''' This is called to do heavy mutation when no progress is made in previous generations. '''
        result = self.change_random_full(original, fl)
        return self.change_random_full(result, fl)

    def single_crossover(self, original1, original2):
        """ This function computes single-point crossover on two parents and returns two children."""
        point = self.r.uniform(0.1, 0.6)
        cut1 = int(point*len(original1))
        cut2 = int(point*len(original2))
        child1 = original1[:cut1]+original2[cut2:]
        child2 = original2[:cut2]+original1[cut1:]
        return child1, child2

    def double_crossover(self, original1, original2):
        """This function computes 2-point crossover on two parents and returns two children."""
        point1 = self.r.uniform(0.1, 0.3)
        point2 = self.r.uniform(0.6, 0.8)
        len1 = len(original1)
        len2 = len(original2)
        cut11 = int(point1*len1)
        cut12 = int(point2*len1)
        cut21 = int(point1*len2)
        cut22 = int(point2*len2)
        child1 = original1[:cut11]+original2[cut21:cut22]+original1[cut12:]
        child2 = original2[:cut21]+original1[cut11:cut12]+original2[cut22:]
        return child1, child2

    """

    def eliminate_random(self, original,fl):
        size = len(original)
        cut_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        #cut_pos = self.r.randint(0, size - cut_size)
        cut_pos = self.get_cut(size - cut_size,fl)
        result = original[:cut_pos] + original[cut_pos + cut_size:]
        #assert len(original) > len(result), "elimination failed to reduce size %d %d" % (len(original), len(result))
        return result

    def eliminate_random_end(self, original,fl):
        size = len(original)
        cut_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.r.randint(size/2, size - cut_size)
        result = original[:cut_pos] + original[cut_pos + cut_size:]
        #assert len(original) > len(result), "elimination failed to reduce size %d %d" % (len(original), len(result))
        return result

    def double_eliminate(self, original,fl):
        result=self.eliminate_random_end(original,fl)
        return self.eliminate_random(result,fl)
    """

    crossovers = [single_crossover, double_crossover]

    # NOTE: we added few mutators more than one so that such operations can be frequent. added ones are: eliminate_random, change_random_full
    #mutators = [eliminate_random, change_bytes, change_bytes, add_random, add_random, change_random, single_change_random, lower_single_random, raise_single_random,
    #            eliminate_null, eliminate_double_null, totally_random, int_slide, double_fuzz, change_random_full, change_random_full, eliminate_random, add_random, change_random]

    #mutators = [change_bytes, add_random, change_random, single_change_random, lower_single_random, raise_single_random,
    #            totally_random, int_slide, double_fuzz, change_random_full, change_random_full]

    # TODO : add more cases like : change to string ...
    mutators = [change_bytes,change_bytes,change_bytes]

    def mutate(self, original, fl):

        self.currentTaintMap = config.TAINTMAP

        if fl not in self.mutationHistory:
            self.mutationHistory.update({fl:dict()})

        result = original

        for i in range(0, config.MUTATIONPERINPUT):

            result = self.r.choice(self.mutators)(self, result, fl)

            while len(result) < 3:
                result = self.r.choice(self.mutators)(self, original, fl)

        assert len(result) > 2, "elimination failed to reduce size %d" % (len(result))

        return result

    """
    def eliminate(self, original, fl):
        loop = self.r.randint(0, 3)
        result = self.r.choice(
            [self.double_eliminate, self.eliminate_random])(original, fl)
        if 4 < len(result) < 10:
            return result
        else:
            return original
        for i in range(loop):
            temp = result
            result = self.r.choice(
                [self.double_eliminate, self.eliminate_random])(result, fl)
        if len(result) < 10:
            return temp
        return result
    """

    def crossover(self, original1, original2):
        minlen = min(len(original1), len(original2))
        if minlen < 20:
            # we don't do any crossover as parents are two young to have babies ;)
            return original1, original2
        return self.r.choice(self.crossovers)(self, original1, original2)
