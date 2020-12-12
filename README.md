# Vuzzer64++

This is the github repo of my improved version of Vuzzer64.

This is the code of my internship subject : Improvements of fuzzing techniques in Vuzzer

I made a post on my blog about my research and all details of my improvements : https://whereisr0da.blogspot.com/2020/08/improvements-of-fuzzing-techniques-in.html

## Context  :

Vuzzer is a program that tries to discover vulnerabilities independently within applications. This project helped the cyber security community, but there is still a lot of features that could be added to make it more powerful. It’s in this context that I was charged to improve the existing software during my internship.

## What is Vuzzer ?

Vuzzer is a new generation fuzzer, that tries to generate more efficient inputs and prioritize application parts to test. It tries to learn about how an input can travel deep path in the application to test the code’s part that can be vulnerable. By mutating the input, Vuzzer is able to avoid error handlings and generate inputs valid enough to cross the common error detection, and test the real input usage in order to find bugs.

## What is Vuzzer64++ ?

Vuzzer64++ is basically my improved version of the original [Vuzzer64](https://github.com/vusec/vuzzer64) shown in my article.

## New features :

So this is the list of all things I added to Vuzzer

## Input mutation improvements

Vuzzer was made to be a Proof of concept, so its mutation process uses all kinds of actions to be applied to the input as a demonstration. For example actions that aim to eliminate random bytes in the input, adding random bytes, shrink the input in two parts and merge them in disorder…

Deleting or adding random segment of the base input is not good in my opinion. First, those actions will break the entire input size, and will probably make old mutation knowledge useless. Secondly is that static taint offset changes like magic bytes will potentially override other important / random data, so input mutation is not accurate. Taint-based changes could just be erased or be applied out of the file scope due to deleting, and if a special byte is somewhere because of a special file structure, this will also be erased. 

So, my idea was to only make random changes overriding over existing data, to keep the file architecture. Vuzzer will no longer add and remove part of the input, if it has to change 4 bytes, it will override 4 bytes of the input until the file has the space for it. 

Also, from now, each mutation will no longer be applied on a random offset in the input. Now each mutation is done on a comparison offset Vuzzer stored earlier. And with this, one of the biggest changes here will be that each time an action is performed, this will care about the size of the comparison. If Vuzzer applies a mutation on a cmp input offset, the mutation will be about the size of the register used during the comparison. So, in theory, mutation will be more effective because, it will respect the same size used by the compared value, the size that the value should have.

## Conflicts handling

Original Vuzzer doesn’t see what it doing with mutations, it just finds offsets where to apply mutation without considering that an older one could be there. And handle this important aspect of the mutation is something that improve Vuzzer results.

By using an algorithm called Child input creation, Vuzzer is able to handle conflicts.

[See here the full description and wiki](WIKI_CHILDINPUTGEN.md)

## Pattern detection system

Taint flow analysis is right to find magic bytes, but in some cases, this analysis can flag comparisons that aren’t good to use. For example, in a loop process, if a program loops through a buffer, and compares the increasing offset value to a static number, like to get the end of a string with a null character. Taint analysis will mark all immediate comparison numbers (in this case null bytes) as magic bytes, but it's wrong. So, to solve this, the improvement could be to identify patterns of following comparisons, and take decision about them.

I made a representation pattern language that can identify comparison patterns and handle them.

[See here the full description and wiki](WIKI_PATTERN.md)

## AFL-CMIN input reduction

AFL is a fuzzer coded in C, which is pretty fast due to its low-level language. It has a plugin called AFL-CMIN that, if you give it a list of inputs, will test the target program with each of them, and will output the best ones in terms of code coverage. The idea was to implement this as an input reducer, Vuzzer produces a lot of file inputs and AFL-CMIN reduces this count to something faster to execute.

[See here the full description and wiki](WIKI_AFLCMIN.md)

## Preview

![https://i.imgur.com/iDA1QeY.gif](https://i.imgur.com/iDA1QeY.gif)

## Requirements 

The requirements for running Vuzzer64 are (copy of Vuzzer64 repo) :

* A C++11 compiler and unix build utilities (e.g. GNU Make).
* Version 3.7 of Intel Pin.
* [EWAGBoolArray 0.4.0](https://github.com/lemire/EWAHBoolArray/releases/tag/0.4.0) : To install it in your system just copy headers file /path/to/EWAHBoolArray-0.4.0/headers in /usr/include folder.
* [BitMagic](http://bmagic.sourceforge.net/) : To install it in your system do "*sudo apt-get install bmagic*"
* BitVector module for python.
* Ghidra RE tool OR IDA disassembler to run static analysis part of VUzzer -OR- Ashley (a MS student from Grenoble) visited VUSec as intern and developed a 'angr' (http://angr.io/) based static analysis module. The code can be found at https://github.com/ash09/angr-static-analysis-for-vuzzer64 (yet to be populated!). However, it should be noted that we have not tested this script much and one can expect some glitches specially on large complex applications! If you have questions on this script, please direct them to Ashley.

We have tested VUzzer by running it on Ubuntu 18.04 LTS, Linux 4.15.0 image.

## Installation

Follow the steps to install VUzzer64 (copy of Vuzzer64 repo) :

    cd vuzzer64
    export PIN_HOME=path_to_pin_directory
    export PIN_ROOT=path_to_pin_directory
    export DFT_HOME=$(pwd)/libdft64
    cd fuzzer-code
    make
    cd ../libdft64
    make
    cd ..

## How to use ?

To use Vuzzer, I highly recommand you to read the original wiki on [Vuzzer repo](https://github.com/vusec/vuzzer64/blob/master/wikiHOWTO.md).

Regarding my features, everything is configured in the config.py file, and the feature should be turned on in that file. Some of my improvements needs you to understand the full descriptions linked above.

## Todo

Here is a short list of remaining actions :

- Implement IDA Lighthouse code coverage exportation, I tried to implement it, but Lighthouse seem to need a special version of Intel Pin, and the version used by the current Vuzzer is 3.7 (not the latest).
- My pattern system could be improved with more variables / functions, multiple arguments / behavior for a variable or operators for example.
- The child input algorithm could be improved by doing a filter of applied mutations, to only apply relevant modifications.
- Some ideas of others actions could be implemented like “change_bytes_to_string” or “change_bytes_to_utf8”.
- Fix the fitness score selection, and improve memory file inputs.
- Fix the child input mutation, to apply mutations on children made by its parent, and not the entire child set.
- Handle x32 in pattern detection.

## Creators and contributors

Credit to all people that work on this project :

Sanjay Rawat, 
Vivek Jain,
Ashish Kumar,
Lucian Cojocar, 
Cristiano Giuffrida, 
Herbert Bos,
Ren Kimura
