# Pattern Detection Wiki

Taint flow analysis is good to find magic bytes, but in some cases, this analysis can flag comparisons that aren’t good to use. For example, in a loop process, if a program loops through a buffer, and compares the increasing offset value to a static number, like to get the end of a string with a null character. Taint analysis will mark all immediate comparison numbers (in this case null) as magic bytes, but they are not. So, the improvement could be to identify patterns of following comparisons, and take decision about them.

## What is a pattern ?

#### The comparison list

Libdft taint analysis output (comparisons made by the program) looks like this :

    32 mem imm 0x000000421c4a {0} {0} {0} {0} {} {} {} {} {} {} {} {} {} {} {} {} 0xff 0xff 
    32 mem imm 0x000000421c53 {1} {1} {1} {1} {} {} {} {} {} {} {} {} {} {} {} {} 0xd8 0xd8 
    32 reg imm 0x000000421d2a {1} {1} {1} {1} {} {} {} {} {} {} {} {} {} {} {} {} 0xd8 0xfe 
    32 mem imm 0x000000421a28 {2} {2} {2} {2} {} {} {} {} {} {} {} {} {} {} {} {} 0xff 0xff 
    32 mem imm 0x000000421a88 {3} {3} {3} {3} {} {} {} {} {} {} {} {} {} {} {} {} 0xfe 0xff 
    32 mem imm 0x000000421a91 {3} {3} {3} {3} {} {} {} {} {} {} {} {} {} {} {} {} 0xfe 0x0 
    32 reg imm 0x000000421d2a {3} {3} {3} {3} {} {} {} {} {} {} {} {} {} {} {} {} 0xfe 0xfe
    . . . . . . .

So, a patern should look like that.

#### An example

A pattern will be defined by a list of lines, each line defines a condition. 

    32 $B imm $C $D(INC_NEW_LINE) $D $D $D * * * * * * * * * * * * $NOT($VAL) $VAL
    WHILE_SAME_LAST_PATTERN_LINE(4)
    32 $B imm $C $D               $D $D $D * * * * * * * * * * * * $VAL       $VAL

#### Its literal representation

A line is a set of elements that define how each element of a cmp.out line should be, static values (string that should not change) can be set like above with “32” and “imm”, and ignored elements can be set with the char “*”.

There are variables defined by a “$” followed by its name, if the variable is not registered (first time seen in the pattern), its value will be set to the value saw at its place in the cmp.out. And otherwise the value at its place should be the same as the variable one to validate the pattern. 

Variables can be initialized with an argument that indicates how the variable should evolve. For example, here, the $D variable uses “INC_NEW_LINE” to verify that the value in cmp.out should be increased at each new line of the pattern that contains $D.

Functions can be used too, to define more abstracts things like in this example “WHILE_SAME_LAST_PATTERN_LINE (4)”. This indicates that the same pattern line defined above in the pattern, should be duplicated for the next lines at least 4 times. 

Conditions can be used, like with the “$NOT($VAL)” that setup a variable that will have a value, that should be not equal to the variable “$VAL”. And with the special variable name “NOT”, this variable will not check the comparison between the value in cmp.out, and the value in variable like others. 

#### Representation goal

So, in this example, I want to define the followed pattern :
-	All comparison on 32 bits registers with immediate values on the second operator
-	That loop through an increasing offset of the input
-	That ends on a successful comparison 

In other words, this pattern is a loop through a buffer of our input that ends only on a special condition, like a loop through a string while the character is not null (null terminator).

#### How the old Vuzzer handle this pattern ?

In this specific case, Vuzzer will handle each value in $VAL as a valid byte for taint-based changes, and will apply them to input, but it’s wrong and will probably lead to an error handling. It is why pattern detection can improve Vuzzer if contributors take the time to define detected patterns during application tests. 

## How to use ?

So first of all, you have to create one, or many patterns (like shown above). Those patterns will be stored in the signatures folder (fuzzer-code/pattern/signatures) as *.txt files.

After setting up patterns, you have to code the way that Vuzzer will handle them. You have to code this in python using the template in (TEMPLATE).

The python file will be in the definitions folder (fuzzer-code/pattern/definitions), and each python definition file will handle one, or many pattern signature files. So you can create one code (example : string detection) that handle many string type signatures / comparisons (example : cmp of 8bit / 16bit / 32bit on memory / registers / ... )

A definition file should look like this :

```python
class PatternDefinition:

    # filled with signatures file names
    FILES = ['PATTERN_DEFINITION_FILE.txt', ...]

    def __init__(self):
        
        # set the name of the pattern
        self.name = "PATTERN_NAME"
        self.patternList = []

    def effect(self, patternFile, cmpList, index, endOffset, fpath):

        # do something ...

        return cmpList
```

It should always be a class with the name "PatternDefinition", it should always have a list of pattern signatures called "FILES" (pattern created above). It must contain a constructor that define two variables, self.name that define the pattern name, and a variable self.patternList that should be empty (disadvantage of not using interfaces).

Finally, the effect function with the prototype above, is the function that is called if one of the pattern is found (pattern signature file in the argument "patternFile").

The effect has full control over comparison list of Libdft output (argument "cmpList"), you can erase / add / change any comparison that you want from this function.

The argument "index" is the first comparison in the "cmpList" that match the pattern, and the argument "endOffset" is the last offset that matched the pattern.

## Example

An example with the pattern signature shown above 


32_mem_stringLoopSingleTainted.txt :

    32 $B imm $C $D(INC_NEW_LINE) $D $D $D * * * * * * * * * * * * $NOT($VAL) $VAL
    WHILE_SAME_LAST_PATTERN_LINE(4)
    32 $B imm $C $D               $D $D $D * * * * * * * * * * * * $VAL       $VAL

stringLoop.py : 

```python
class PatternDefinition:

    FILES = ['32_mem_stringLoopSingleTainted.txt']

    def __init__(self):
        
        self.name = "stringLoop"
        self.patternList = []

    def effect(self, patternFile, cmpList, index, endOffset, fpath):

        # if pattern is 32_mem_stringLoopSingleTainted
        if patternFile == PatternDefinition.FILES[0]:
            cmpList = self._32_mem_stringLoopSingleTainted(cmpList, index, endOffset, True, fpath)

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
```

And if the pattern is found, here is the output :

![http://url/to/img.png](https://i.imgur.com/d9BZCbZ.png)

## How to activate it ?

Simply turn on this variable in the config.py file

```python
USEPATTERNDETECTION = True
```
If you have a problem with your pattern, you can turn on logs to see where is the problem

```python
SHOWDEBUGPATTERN = True
```
## Documentation

### Functions :

#### WHILE_SAME_LAST_PATTERN_LINE : 

    Definition : Checks that the last pattern line and the next one are the same
    Argument   : Minimum number of times the pattern should be duplicated
    Example    : WHILE_SAME_LAST_PATTERN_LINE(4)

### Special variables :

#### $NOT : 

    Definition : Checks that the value at its place is not the same as another variable passed in argument
    Argument   : The variable that should be not equal
    Example    : $NOT($VAR)

### Variable arguments :

#### LINE : 

    Definition : Indicate that the var value should be reset after the end of a pattern line
    Example    : $A(LINE)

#### INC_LINE : 

    Definition : Indicate that the var value should be incressed at each call of it self in a line
    Example    : $A(INC_LINE)

#### INC_NEW_LINE : 

    Definition : Indicate that the var value should be incressed after the end of a pattern line
    Example    : $A(INC_NEW_LINE)

#### INC_ALL : 

    Definition : Indicate that the var value should be incressed at each call of it self in all pattern
    Example    : $A(INC_ALL)
