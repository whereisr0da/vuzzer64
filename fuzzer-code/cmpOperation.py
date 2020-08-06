import config

class taintTypeEnum(object):
    SINGLE_BYTE = 0
    ARRAY = 1
    UNKNOWN = 2

# should be after taintTypeEnum
import gautils

class cmpOperation:
    """ Object that parse a cmp line to extract each of its information """

    id = 0

    def __init__(self, matchCmpLine):

        if config.BIT64 == False:
            self.op1start = 5
            self.op2start = 9
            self.op1val = 13
            self.op2val = 14
        else:
            self.op1start = 5
            self.op2start = 13
            self.op1val = 21
            self.op2val = 22

        self.cmpSize = self.getCmpType(matchCmpLine.group(1))
        self.cmpSizeBit = matchCmpLine.group(1)
        self.operand1 = matchCmpLine.group(2)
        self.operand2 = matchCmpLine.group(3)
        self.offsetInMemory = matchCmpLine.group(4)

        self.valueOperand1 = int(matchCmpLine.group(self.op1val),16)
        self.valueOperand2 = int(matchCmpLine.group(self.op2val),16)

        # I needed this after a coded the getTaintedStartOffset, so not optimized at all
        self.registerByte1 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start))
        self.registerByte2 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+1))
        self.registerByte3 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+2))
        self.registerByte4 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+3))
        self.registerByte5 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+4))
        self.registerByte6 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+5))
        self.registerByte7 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+6))
        self.registerByte8 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+7))

        if config.BIT64 == True:
            self.registerByte9 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+8))
            self.registerByte10 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+9))
            self.registerByte11 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+10))
            self.registerByte12 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+11))
            self.registerByte13 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+12))
            self.registerByte14 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+13))
            self.registerByte15 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+14))
            self.registerByte16 = cmpOperation.removeRegChar(matchCmpLine.group(self.op1start+15))

        # values defined later
        self.offsetListOpe1 = list()
        self.offsetListOpe2 = list()
        self.isGoodToTaintChanges = False
        self.taintValue = -1
        self.taintType = -1
        self.sizeOfFollowed = -1
        self.offsetsInInput = list()

        self.id = cmpOperation.id

        cmpOperation.id += 1

        self.getInputTaintedOffsets(matchCmpLine)

    @staticmethod
    def removeRegChar(str):
        return str.replace("{","").replace("}","")

    def __str__(self):

        # 32 reg mem 0x000000000044f2a9 {} {} {} {} {} {} {} {} {161,162} {161,162} {161,162} {161,162} {} {} {} {} 0x2d 0x1e0 
        strRaw = "%s %s %s %s {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} %s %s" % (self.cmpSizeBit,self.operand1,self.operand2,self.offsetInMemory,hex(self.valueOperand1),hex(self.valueOperand2))

        return strRaw
        #return str(self.id) + " : " + str(self.offsetsInInput) + " value = " + str(hex(self.taintValue))

    def getTaintedStartOffset(self, mat, num):
        ind = num

        if config.BIT64 == False:
            regSize = 3
        else:
            regSize = 7

        while ind < num + regSize:
            if mat.group(ind) != '':
                return ind
            ind += 1
        return -1

    def getTaintedOffsets(self, mat, start, op):
        offset = 0
        offsetList = list()

        if config.BIT64 == False:
            regSize = 4
        else:
            regSize = 8

        while offset < regSize - (start - op):
            currentOffset = mat.group(start + offset)
            if currentOffset != '':
                offsets = currentOffset.split(',')

                #for off in offsets:
                #    offsetList.append(off)

                # handle influanced offsets is too complex to be understood
                # so I take only the first offset
                offsetList.append(offsets[0])
            offset += 1
        return offsetList

    def defineTaintedCmp(self, offsetList):
        """ TODO """
        dataType = taintTypeEnum.UNKNOWN

        if self.isListSingleOffset(offsetList):
            dataType = taintTypeEnum.SINGLE_BYTE
        elif self.isListFollowedOffsets(offsetList):
            dataType = taintTypeEnum.ARRAY

        return dataType

    def isListSingleOffset(self, offsetList):
        """ Return true if the patern is : {n} {n} {n} {n} ... {n}"""

        baseValue = offsetList[0]

        for off in offsetList:
            if off != baseValue:
                return False
        return True

    def isListFollowedOffsets(self, offsetList):
        """ Return true if the patern is : {n} {n+1} {n+2} {n+3} ... {n+length-1}"""

        oldOne = None

        for off in offsetList:
            if oldOne != None:
                if int(off) != int(oldOne)+1:
                    return False
                oldOne = off
            else:
                oldOne = off
        return True

    def isNonPrintable(self, hexstr):
        return hexstr in [0x0a, 0x0d]

    # TODO : handle min offset config
    def getInputTaintedOffsets(self, matchCmpLine):
        """ Get tainted offset of cmp, and define if it's good to taint-based changed """

        # read tainted offsets
        foundStartOffsetOpe1 = self.getTaintedStartOffset(matchCmpLine, self.op1start) 
        foundStartOffsetOpe2 = self.getTaintedStartOffset(matchCmpLine, self.op2start) 

        if foundStartOffsetOpe1 != -1:
            self.offsetListOpe1 = self.getTaintedOffsets(matchCmpLine,foundStartOffsetOpe1,self.op1start)
        if foundStartOffsetOpe2 != -1:
            self.offsetListOpe2 = self.getTaintedOffsets(matchCmpLine,foundStartOffsetOpe2,self.op2start)

        taintOffsetList = list()

        if self.operand1 == 'imm' and self.operand2 == 'imm':
            gautils.die("[-] Immediate compared to immediate : impossible !")

        # check for valid cmp with immediat value that we can collect and apply to input
        elif self.operand1 == 'imm':
            if config.ALLBYTES == True or (self.valueOperand1 != 0xffffffff and self.valueOperand1 != 0x00):
                # TODO : improve the taint selection
                if len(self.offsetListOpe2) < 5 and self.isNonPrintable(self.valueOperand1) == False:
                    # define which operator we want
                    self.isGoodToTaintChanges = True
                    taintOffsetList = self.offsetListOpe2
                    self.taintValue = self.valueOperand1

        elif self.operand2 == 'imm':
            if config.ALLBYTES == True or (self.valueOperand2 != 0xffffffff and self.valueOperand2 != 0x00):
                # TODO : improve the taint selection
                if len(self.offsetListOpe1) < 5 and self.isNonPrintable(self.valueOperand2) == False:
                    self.isGoodToTaintChanges = True
                    taintOffsetList = self.offsetListOpe1
                    self.taintValue = self.valueOperand2

        elif ((self.operand1 == 'mem' and self.operand2 =='mem') or (self.operand1 == 'reg' and self.operand2 =='reg')):

            selectedValue = -1

            if foundStartOffsetOpe1 != -1 and len(self.offsetListOpe1) > 0:
                selectedValue = self.valueOperand1
                taintOffsetList = self.offsetListOpe1
            elif foundStartOffsetOpe2 != -1 and len(self.offsetListOpe2) > 0:
                selectedValue = self.valueOperand2
                taintOffsetList = self.offsetListOpe2

            if selectedValue != -1 and (config.ALLBYTES == True or (selectedValue != 0xffffffff and selectedValue != 0x00)):
                
                if self.isNonPrintable(selectedValue) == False:
                    self.isGoodToTaintChanges = True
                    self.taintValue = selectedValue

        # we don't handle this case in taint changes
        # so will end in allTaintedOffsets
        if self.isGoodToTaintChanges == False:

            # NOTE : self.taintType will be set twince, but it's not used in not taint changes
            if foundStartOffsetOpe1 != -1:
                self.getTaintedOffsetFromType(self.offsetListOpe1)
            if foundStartOffsetOpe2 != -1:
                self.getTaintedOffsetFromType(self.offsetListOpe2)

        # offset taint with immediate value that will be applied on the input
        # so will en in goodTaintedOffset
        else:
            if len(taintOffsetList) == 0:
                gautils.die("[-] Something goes wrong while parsing '%s'" % self)

            self.getTaintedOffsetFromType(taintOffsetList)

    def getTaintedOffsetFromType(self, offList):
        """ TODO """

        # define taint data type
        if config.TAINTOFFSETINTERPRETATION:
            self.taintType = self.defineTaintedCmp(offList)
        else:
            self.taintType = taintTypeEnum.UNKNOWN

        # all registers are focused on one offset of the input
        if self.taintType == taintTypeEnum.SINGLE_BYTE:
            self.offsetsInInput.append(int(offList[0]))
        elif self.taintType == taintTypeEnum.ARRAY:
            # TODO
            self.sizeOfFollowed = len(offList)
            #print "getInputTaintedOffsets: array detected"
            self.offsetsInInput.append(int(offList[0]))
        else:
            # TODO : unknown case
            for off in set(offList):
                self.offsetsInInput.append(int(off))

    def valueSizePrediction(self):
        if self.taintValue <= 0xFF:
            return 1
        elif self.taintValue <= 0xFFFF:
            return 2
        elif self.taintValue <= 0xFFFFFFFF:
            return 4
        elif self.taintValue <= 0xFFFFFFFFFFFFFFFF:
            return 8
        else:
            return -1

    def valueToByteArray(self):
        size = self.valueSizePrediction()

        if size == 1:
            return [self.taintValue]
        elif size == 2:
            return [self.taintValue & 0xFF, (self.taintValue >> 8) & 0xFF]
        elif size == 4:
            return [self.taintValue & 0xFF, (self.taintValue >> 8) & 0xFF,
                   (self.taintValue >> 16) & 0xFF, (self.taintValue >> 24) & 0xFF]
        elif size == 8:
            return [self.taintValue & 0xFF , (self.taintValue >> 8) & 0xFF,
                   (self.taintValue >> 16) & 0xFF, (self.taintValue >> 24) & 0xFF,
                   (self.taintValue >> 32) & 0xFF, (self.taintValue >> 40) & 0xFF, 
                   (self.taintValue >> 48) & 0xFF, (self.taintValue >> 56) & 0xFF]
        else:
            return -1

    # TODO : improve
    def __eq__(self, other):
        return (self.offsetInMemory) == (other.offsetInMemory) and self.operand1 == other.operand1 and self.operand2 == other.operand2 and self.offsetsInInput == other.offsetsInInput and self.cmpSize == other.cmpSize and (self.valueOperand1) == (other.valueOperand1) and (self.valueOperand2) == (other.valueOperand2)

    def __ne__(self, other):
        return not self.__eq__(other)

    def getCmpType(self, str):
        """ TODO """

        if str == '8':
            return 1
        elif str == '16':
            return 2
        elif str == '32':
            return 4
        elif str == '64':
            return 8
        else:
            return -1
