"""

aflcminReduction.py

This files implements the AFL-CMIN input reduction

Coded by : @r0da

"""

import os
import config
import gautils as g
import subprocess
import shutil

def checkAflcmin():
    return config.ALFCMINEXECUTABLEPATH != '' and os.path.exists(config.ALFCMINEXECUTABLEPATH)

def reduction(files):

    if not checkAflcmin():
        g.log_print("[-] ALFCMINEXECUTABLEPATH is not set or wrong")
        return False

    inputDir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vutemp", "aflinput")
    ouputDir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vutemp","aflouput")

    if not checkDir(inputDir,ouputDir):
        return False

    # NOTE : copy each file is not a good idea, but if we want to split child inputs
    #        and normal population, need to make differents dir

    for f in files:
        shutil.copy(f, os.path.join(inputDir, os.path.basename(f)))

    cmd = "%s -Q -i %s -o %s -- %s @@" % (config.ALFCMINEXECUTABLEPATH,inputDir,ouputDir,config.SUT % "")

    g.log_print("[*] Launching AFL-CMIN")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    
    stdout, stderr = proc.communicate()
    
    inputNumberAfterReduction = len(os.listdir(ouputDir))

    if inputNumberAfterReduction == 0:
        g.log_print("[-] Reduction failed : AFL-CMIN output is null")

        # checked inputs are useless, so we remove them
        for f in files:
            os.remove(f)

    else:
        erasedPer = 100.0 - float((float(inputNumberAfterReduction)/float(len(files))) * 100.0) 

        g.log_print("[+] AFL-CMIN output is about %d files (%.1f%% erased)" % (inputNumberAfterReduction, erasedPer))
        
        validInputPaths = os.listdir(ouputDir)

        validInputs = []

        for f in validInputPaths:
            validInputs.append(os.path.basename(f))

        # removing old not interesting files
        for f in files:
            if os.path.basename(f) not in validInputs:
                os.remove(f)

        g.emptyDir(ouputDir)

    g.emptyDir(inputDir)

    return True

def clearDir():

    inputDir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vutemp", "aflinput")
    ouputDir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vutemp", "aflouput")

    checkDir(inputDir,ouputDir)

    g.emptyDir(inputDir)
    g.emptyDir(ouputDir)

def checkDir(inputDir, ouputDir):

    if not dirExists(inputDir):

        try:
            os.mkdir(inputDir)
        except OSError:
            g.log_print("[-] Failed to create input directory")
            return False

    if not dirExists(ouputDir):

        try:
            os.mkdir(ouputDir)
        except OSError:
            g.log_print("[-] Failed to create ouput directory")
            return False

    return True

def dirExists(path):
    return os.path.isdir(path) and os.path.exists(path)