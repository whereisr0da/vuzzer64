"""

patternSystem.py

This files implements the pattern language parsing and execution

Coded by : @r0da


The documentation explain how to create patterns and how use them.

Pattern example :

32 $B imm $C $D(INC_NEW_LINE) $D $D $D * * * * * * * * * * * * $NOT($VAL) $VAL
WHILE_SAME_LAST_PATTERN_LINE(4)
32 $B imm $C $D               $D $D $D * * * * * * * * * * * * $VAL       $VAL

"""

import inspect
import re
import os
import config
import gautils as g

# TODO : check if there is encoding problems

class Variable:

    @staticmethod
    def INC_LINE(cmpValue, var, firstOfLine):
        """ Indicate that the var value should be incressed at each call of it self in a line """

        try:
            (iCmpValue,iVar) = Variable.compareValuesToInt(cmpValue, var)
        except:
            return False

        valid = iCmpValue == (iVar + 1)

        # for the next loop, we will compare the new value
        if valid == True:
            var.value = str(iCmpValue)

        return valid

    @staticmethod
    def INC_ALL(cmpValue, var, firstOfLine):
        """ Indicate that the var value should be incressed at each call of it self in all pattern """

        # the difference is at variable flush
        return Variable.INC_LINE(cmpValue, var, firstOfLine)

    @staticmethod
    def INC_NEW_LINE(cmpValue, var, firstOfLine):
        """ Indicate that the var value should be incressed after the end of a pattern line """

        # TODO : clear the code

        try:
            (iCmpValue,iVar) = Variable.compareValuesToInt(cmpValue, var)
        except:
            return False

        # if it's the first element of the line, it should be increased
        if firstOfLine:
            var.value = str(iVar + 1)

        # it should be the same
        return iCmpValue == int(var.value)

    @staticmethod
    def LINE(cmpValue, var, firstOfLine):
        """ Indicate that the var value should be reset after the end of a pattern line """

        try:
            (iCmpValue,iVar) = Variable.compareValuesToInt(cmpValue, var)
        except:
            return False

        # the difference is at variable flush
        return iCmpValue == iVar

    @staticmethod
    def compareValuesToInt(cmpValue, var):

        try:
            iCmpValue = int(cmpValue)
        except:
            g.pattern_debug( "Pattern: fail to convert %s to int" % (cmpValue) )
            return None
        else:
            g.pattern_debug( "Pattern: iCmpValue = %s" % (iCmpValue) ) 

        try:
            iVar = int(var.value)
        except:
            g.pattern_debug( "Pattern: fail to convert %s to int" % (var.value) )
            return None
        else:
            g.pattern_debug( "Pattern: iVar = %s" % (iVar) )

        return (iCmpValue,iVar)

    TYPES = {"LINE": LINE,"INC_LINE": INC_LINE, "INC_NEW_LINE": INC_NEW_LINE, "INC_ALL": INC_ALL}

    def __init__(self, str):

        self.value = -1

        argument = ""

        nameStr = str.split("$")[1]

        if len(str.split("$")) > 2:
            nameStr = str.split("$")[1] + "$" + str.split("$")[2]

        # variable with special initialization
        if "(" in nameStr and ")" in nameStr:

            #pattern = re.compile(r"\(([a-z]+)\(", re.I)
            # if pattern.match(nameStr) == True:

            argument = nameStr.split("(")[1].split(")")[0]

            name = nameStr.split("(")[0]

            g.pattern_debug( "Pattern: name = '%s'" % (name) )

            if argument == "" or name == "":
                g.pattern_debug( "Pattern: fail to parse '%s'" % (str) )

            elif argument not in Variable.TYPES:
                
                # if variable should be compared to a variable
                if "$" in argument:
                    self.argument = argument.replace("$","")

                    g.pattern_debug( "Pattern: argument '%s'" % (self.argument) )
                    
                else:
                    g.pattern_debug( "Pattern: argument '%s' dosen't exist" % (str) )

            else:
                g.pattern_debug( "Pattern: arg = '%s'" % (argument) )
                self.argument = Variable.TYPES[argument]

        elif "(" in str or ")" in str:
            g.pattern_debug( "Pattern: fail to parse '%s'" % (str) )

        # no argument
        else:
            name = nameStr

            g.pattern_debug( "Pattern: name = '%s'" % (name) )

        self.name = name

    def __str__(self):
        return str(self.name)

class PatternLine:

    def __init__(self, pattern, match):

        self.elemArray = []

        matchCount = len(match.groups())

        if matchCount != 22:
            g.pattern_debug( "Pattern: a pattern line should be 22 elements" )
            return

        # get all the elements of the line
        for i in range(1, matchCount+1):
            
            # by default it's a static value
            elem = match.group(i)

            g.pattern_debug( "Pattern: parsing elem %s" % (elem) )

            # this is a variable
            if "$" in elem:
                # init the var from the string
                elem = Variable(elem)

                # check that the new variable dosen't exist
                alreadyExistingVar = pattern.IsVariablePresent(elem)

                # if so, add its copy to the element array
                if alreadyExistingVar != -1:
                    elem = alreadyExistingVar

                # otherwise, add the function to the global var set
                else:
                    pattern.globalsVariables.append(elem)

            self.elemArray.append(elem)

        # fix variables comparisons
        for var in pattern.globalsVariables:

            try:
                var.argument
            except:
                continue

            # if arg is a variable
            if isinstance(var.argument, basestring):

                found = pattern.IsVariablePresentFromName(var.argument)

                # add it if variable present
                if found != -1:
                    # asign variable instance
                    var.argument = found
                    g.pattern_debug( "Pattern: variable found %s" % (var.argument) )

                else:
                    g.pattern_debug( "Pattern: error while variable comparison asignment" )
        
        # check that all var are found
        for var in pattern.globalsVariables:
            
            try:
                var.argument
            except:
                continue

            # if there is string remaining
            if isinstance(var.argument, basestring):
                g.pattern_debug( "Pattern: variable not found %s" % (var.argument) )

    def check(self, offset, cmpArray):

        if offset >= len(cmpArray):
            g.pattern_debug( "Pattern: offset outside of the cmpArray" )
            return -1

        currentCmp = cmpArray[offset]

        # should be in same order as elemArray
        # EXAMPLE : 32 mem imm 0x0000000000421c4a {0} {0} {0} {0} {} {} {} {} {} {} {} {} {} {} {} {} 0xff 0xff
        cmpItems = [currentCmp.cmpSizeBit, currentCmp.operand1, currentCmp.operand2, currentCmp.offsetInMemory,
                    currentCmp.registerByte1, currentCmp.registerByte2, currentCmp.registerByte3, currentCmp.registerByte4,
                    currentCmp.registerByte5, currentCmp.registerByte6, currentCmp.registerByte7, currentCmp.registerByte8,
                    currentCmp.registerByte9, currentCmp.registerByte10, currentCmp.registerByte11, currentCmp.registerByte12,
                    currentCmp.registerByte13, currentCmp.registerByte14, currentCmp.registerByte15, currentCmp.registerByte16,
                    currentCmp.valueOperand1, currentCmp.valueOperand2]

        self.passedVariable = set()

        # check each element of the line
        for i, e in enumerate(self.elemArray):

            firstOfLine = False

            if isinstance(e, Variable):
                firstOfLine = e not in self.passedVariable
                self.passedVariable.add(e)

            # check the coparison size
            if self.checkElement(cmpItems[i], e, firstOfLine) == False:
                return -1  # oula

        return offset + 1

    def checkElement(self, cmpValue, patternElement, firstOfLine):

        result = True

        # if the element is a string, it's a static element to compare
        if isinstance(patternElement, str):

            # if we don't care about this value
            if patternElement == "*":
                g.pattern_debug( "Pattern: '%s' is ignored by %s" % (
                    cmpValue, patternElement) )
            # it's a static value
            else:
                # if string comparison is possible
                if isinstance(cmpValue, str):

                    # compare the static value
                    if cmpValue == patternElement:
                        g.pattern_debug( "Pattern: valid '%s' with %s" % (
                            cmpValue, patternElement) )
                    else:
                        g.pattern_debug( "Pattern: invalid '%s' with %s" % (
                            cmpValue, patternElement) )
                        result = False
                else:
                    g.pattern_debug( "Pattern: NOT COMP FOR '%s' and %s" % (
                        cmpValue, patternElement) )

        # this is a variable
        # NOTE : variables should be strings
        elif isinstance(patternElement, Variable):

            g.pattern_debug( "Pattern: testing var %s" % (patternElement.name) )

            # check if the variable has an argument
            try:
                patternElement.argument

            # it's a normal variable
            # so the cmpValue should be the same as the variable
            except AttributeError:
                # it's the first time the variable is seen
                if patternElement.value == -1:
                    g.pattern_debug( "Pattern: variable '%s' init with %s" % (patternElement.name, cmpValue) )
                    # ensure string value
                    patternElement.value = str(cmpValue)
                # the value is already set, so cmpValue should be the same
                elif str(cmpValue) != str(patternElement.value):
                    g.pattern_debug( "Pattern: invalid '%s' with var %s = %s" % (cmpValue, patternElement.name, patternElement.value) )
                    result = False
                else:
                    g.pattern_debug( "Pattern: valid '%s' with var %s = %s" % (cmpValue, patternElement.name, patternElement.value) )

            # variable should have a special behaviour
            else:
                
                # it's the first time the variable is seen
                if patternElement.value == -1:

                    if isinstance(patternElement.argument, Variable):
                        
                        # is the comparison var is defined but the variable as no value
                        if patternElement.argument.value != -1:

                            variableComparison = str(patternElement.argument.value) != str(patternElement.value)

                            # if variable value respect the comparison
                            if variableComparison:
                                
                                g.pattern_debug( "Pattern: variable %s init with '%s'" % (patternElement.name, cmpValue) )

                                # ensure string value
                                patternElement.value = str(cmpValue)

                            # otherwise, the pattern is not respected
                            else:
                                g.pattern_debug( "Pattern: invalid '%s' init with var %s value '%s'" 
                                    % (cmpValue, patternElement.argument.name, patternElement.argument.value) )

                                result = False

                        # TODO : HOTFIX check condition after assignement of all var
                        else:

                            g.pattern_debug( "Pattern: variable %s init with '%s'" % (patternElement.name, cmpValue) )
                            # ensure string value
                            patternElement.value = str(cmpValue)

                    # it's a normal variable initialisation
                    else:

                        g.pattern_debug( "Pattern: variable %s init with '%s'" % (patternElement.name, cmpValue) )
                        # ensure string value
                        patternElement.value = str(cmpValue)

                # if the variable as a comparison var
                elif isinstance(patternElement.argument, Variable):

                    # if we ignore the static var, but we care about the comparison
                    if patternElement.name != "NOT":
                        staticVarStatic = str(cmpValue) == str(patternElement.value)
                    else:
                        staticVarStatic = True

                    variableComparison = str(patternElement.argument.value) != str(cmpValue)

                    # if the variable static value is followed and equal / not equal to a specific var
                    if staticVarStatic and variableComparison:
                        g.pattern_debug( "Pattern: valid '%s' with var %s behaviour and %s value '%s'" 
                            % (cmpValue, patternElement.name, patternElement.argument.name, patternElement.argument.value) )

                    else:
                        g.pattern_debug( "Pattern: invalid '%s' with var %s value '%s' and %s value '%s'" 
                            % (cmpValue, patternElement.name, patternElement.value, patternElement.argument.name, patternElement.argument.value) )
                        result = False

                # the value is already set, so cmpValue should match the special behaviour
                elif patternElement.argument.__func__(cmpValue, patternElement, firstOfLine) == False:
                    g.pattern_debug( "Pattern: invalid '%s' with var %s behaviour" % (cmpValue, patternElement.name) )
                    result = False
                else:
                    g.pattern_debug( "Pattern: valid '%s' with var %s behaviour" % (cmpValue, patternElement.name) )

        return result

class Function:
    def __init__(self, func, arg):
        self.func = func
        self.arg = arg

class Functions:

    # TODO : see if a object is better
    @staticmethod
    def WHILE_SAME_LAST_PATTERN_LINE(pattern, patternLineIndex, offset, cmpArray, arg):
        """ Check that the last pattern line and the next one are the same """
        
        g.pattern_debug( "Pattern: HELLO WHILE_SAME_LAST_PATTERN_LINE" )

        if arg == "" or arg is None:
            g.pattern_debug( "Pattern: WHILE_SAME_LAST_PATTERN_LINE should have args" )
            return -1

        if offset >= len(cmpArray):
            g.pattern_debug( "Pattern: offset outside of the cmpArray" )
            return -1

        copyMin = int(arg)

        if offset + copyMin > len(cmpArray):
            g.pattern_debug( "Pattern: scope outside of the cmpArray" )
            return -1 

        if patternLineIndex >= len(pattern.patternLines):
            g.pattern_debug( "Pattern: patternLineIndex outside of patternLines" )
            return -1

        if patternLineIndex - 1 < 0:
            g.pattern_debug( "Pattern: lastPatternLine outside of patternLines" )
            return -1 

        # get the last pattern line that should be duplicated
        lastPatternLine = pattern.patternLines[patternLineIndex - 1]

        nextOffset = offset

        # check if the min condition is respected in the scope
        for i in range(1,copyMin+1):

            # check the pattern at the offset
            nextOffset = lastPatternLine.check(nextOffset, cmpArray)

            # if the pattern don't match
            if nextOffset == -1:
                return -1
            else:
                g.pattern_debug( "Pattern: patternLine %d validated" % (i) )

                # we flush special variables behaviour
                pattern.flushVariablesDataSpecial()

        # from here the scope is followed

        # looping while we have a duplicated
        while (lastPatternLine.check(nextOffset, cmpArray) != -1):

            g.pattern_debug( "Pattern: out of min valid check" )

            if (nextOffset + 1) >= len(cmpArray):
                break

            nextOffset += 1

        # fix for INC_NEW_LINE
        for v in pattern.globalsVariables:

            # check if there is args
            try:
                v.argument
            # it's a common variable
            except:
                continue
            # the variable has a special behaviour
            else:
                if not isinstance(v.argument, Variable):
                    # check if we changed a variable
                    if v.argument.__func__ == Variable.INC_NEW_LINE and v in lastPatternLine.passedVariable:
                        v.value = str(int(v.value) - 1)

        # return the next cmp that is not a duplicate
        return nextOffset 

class Pattern:

    functionList = {"WHILE_SAME_LAST_PATTERN_LINE": Functions.WHILE_SAME_LAST_PATTERN_LINE}

    # TODO : handle x32
    def __init__(self, file):

        g.pattern_debug( "Pattern: reading the file" )

        self.name = os.path.basename(file)
        self.patternLines = []
        self.globalsVariables = []

        # I'm not good at regex
        patternRegex = re.compile(
            r"(.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) ", re.I)

        f = open(file)

        for l in f.readlines():

            if l == "" or l == "\n" or l == "\r\n":
                continue

            fixedLine = self.beautifyLine(l)

            g.pattern_debug( "Pattern: parsing '%s'" % (fixedLine) )

            match = patternRegex.match(fixedLine)

            # if regex parse failed
            if match == False:
                g.pattern_debug( "Pattern: invalid line '%s'" % (l) )
                break
            else:
                # check if the line is a function or a pattern
                try:
                    test = match.group(22)
                # it's a function or a wrong pattern
                except:
                    # if there is no function in the line
                    if any(function in fixedLine for function in self.functionList) == False:
                        g.pattern_debug( "Pattern: pattern line is not complete or not in function list" )
                        break
                    else:

                        if "(" not in fixedLine and ")" not in fixedLine:
                            g.pattern_debug( "Pattern: '()' missing" )
                            break

                        func = fixedLine.split("(")[0]
                        arg  = fixedLine.split("(")[1].split(")")[0]

                        # check if is valid again after parsing
                        if func not in self.functionList:
                            g.pattern_debug( "Pattern: unknown function '%s'" % (func) )
                            break

                        # it's a valid function
                        else:
                            
                            # if there is an argument
                            if arg != "":
                                # NOTE : args are only numbers from now
                                try:
                                    iArg = int(arg)
                                except:
                                    g.pattern_debug( "Pattern: fail to convert arg %s to int" % (arg) )
                                    break
                                else:
                                    g.pattern_debug( "Pattern: iArg = %s" % (arg) )
                                    arg = iArg

                            # add it to the line array
                            self.patternLines.append(Function(self.functionList[func], arg))

                            g.pattern_debug( "Pattern: function = %s" % (func) )

                # it's a pattern line
                else:
                    # init the pattern line
                    self.patternLines.append(PatternLine(self,match))

            g.pattern_debug( "Pattern: line done" )

        g.pattern_debug( "Pattern: init done" )

    def IsVariablePresent(self, var):
        """ Check if a variable is already defined """

        for e in self.globalsVariables:
            if isinstance(e, Variable):
                if var.name == e.name:
                    return e
        return -1

    def IsVariablePresentFromName(self, name):
        """ Check if a variable name is already defined """

        for e in self.globalsVariables:
            if isinstance(e, Variable):
                if name == e.name:
                    return e
        return -1

    def executeFromCmpObjects(self, offset, cmpArray):

        if offset >= len(cmpArray):
            g.pattern_debug( "Pattern: offset is outside of the array" )
            return -1

        g.pattern_debug( "Pattern: processing the array" )

        nextOffset = offset

        if cmpArray < len(self.patternLines):
            g.pattern_debug( "Pattern: less cmp than pattern lines" )
            return -1

        if len(cmpArray) - offset < len(self.patternLines):
            g.pattern_debug( "Pattern: less cmp than pattern lines because end of array" )
            return -1

        patternLineIndex = 0
        lastPatternExecuted = -1

        # looping throught each pattern line def
        for patternLine in self.patternLines:

            g.pattern_debug( "Pattern: processing patternLine %d" % (patternLineIndex) )

            # if the pattern line is a function
            if isinstance(patternLine, Function):
                
                # check if the function is ok
                if callable(patternLine.func):

                    # execute the function and check if it behaviour is followed
                    # if not check return -1
                    # otherwise return the next cmp offset to check
                    # TODO : improve arg
                    nextOffset = patternLine.func(self, patternLineIndex, nextOffset, cmpArray, patternLine.arg)

                # I had this case one day
                else:
                    g.pattern_debug( "Pattern: func is not callable" )
                    patternLineIndex += 1
                    continue

            # otherwive it's a common pattern
            else:

                # save each pattern line executed
                lastPatternExecuted = patternLineIndex

                # check is the cmp is valid at the offset
                # if not check return -1
                # otherwise return the next cmp offset to check
                nextOffset = patternLine.check(nextOffset, cmpArray)

            patternLineIndex += 1

            # the pattern line or behaviour is not followed
            if nextOffset == -1:

                # flush varible data of the line for the next one
                self.flushVariablesData()

                # the pattern dosen't match
                return -1

            # we continue to loop through pattern lines
            else:

                # so we flush special variables behaviour
                self.flushVariablesDataSpecial()

        # flush varible data of the line for the next one
        self.flushVariablesData()

        # if the last pattern executed is a line
        if lastPatternExecuted != -1 and lastPatternExecuted == (len(self.patternLines) - 1):
            nextOffset -= 1

        # the pattern is present, we return the end of pattern
        return nextOffset

    def flushVariablesData(self):

        for v in self.globalsVariables:
            v.value = -1

    def flushVariablesDataSpecial(self):

        for v in self.globalsVariables:

            # check if there is args
            try:
                v.argument
            # it's a common variable
            except:
                continue
            # the variable has a special behaviour
            else:
                # check that the argument is a function
                if not isinstance(v.argument, Variable):
                    # INC_LINE / LINE should be reset because it's only looking at a line
                    if v.argument.__func__ == Variable.INC_LINE or v.argument.__func__ == Variable.LINE:
                        v.value = -1
                    # NOTE : put specials behaviour here
                    
    def beautifyLine(self, str):
        """ Remove all return line characters and remove duplicated spaces """

        str = str.replace("\r\n", "").replace("\n", "")

        tmpStr = ""
        oldChar = -1

        for c in str:
            if oldChar == -1 or (oldChar != " " and c == " ") or (oldChar == " " and c != " ") or (oldChar != " " and c != " "):
                tmpStr += c
                oldChar = c

        # if not the regex will not see the last element
        if tmpStr[len(tmpStr)-1] != " ":
            tmpStr += " "

        return tmpStr
