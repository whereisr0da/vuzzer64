# this class should be the same to all patterns
# NOTE : I'm not good enough in python to choose the right way to implement this thing
# TODO : use interfaces

class PatternDefinition:

    # filled with signatures file names
    FILES = ['32_mem_stringLoopSingleTainted.txt']

    def __init__(self):
        
        self.name = "stringLoop"
        self.patternList = []

    def effect(self, patternFile, cmpList, index, endOffset, fpath):

        # if pattern is 32_mem_stringLoopSingleTainted
        if patternFile == PatternDefinition.FILES[0]:
            cmpList = self._32_mem_stringLoopSingleTainted(cmpList, index, endOffset, True, fpath)

        # TODO : handle others

        return cmpList

    def _32_mem_stringLoopSingleTainted(self, cmpList, index, endOffset, rightOperand, fpath):

        newCmpList = cmpList
        string = ""

        # check if it's a string
        # NOTE : last cmp line is not checked because it is not a string (null terminator)
        for i in range(index, endOffset):
            cmp = cmpList[i]
            if PatternDefinition.isStringPrintable(cmp.valueOperand1) == False:
                print("[-] stringLoop : it's not a string")
                return newCmpList
            string += chr(cmp.valueOperand1)
        
        print("[+] stringLoop : looping string is '%s'" % (string))

        # change all cmp to not be used for taint changes
        for i in range(index, endOffset):
            newCmpList[i].isGoodToTaintChanges = False

        print("[+] stringLoop : removed from taint")

        return newCmpList

    @staticmethod
    def isStringPrintable(str):
        return (str) in [int(n) for n in xrange(33, 126)]

