import atexit
#from time import clock
from time import time
from datetime import datetime

def secondsToStr(t):
    return "%d:%02d:%02d.%03d" % \
        reduce(lambda ll,b : divmod(ll[0],b) + ll[1:],
            [(t*1000,),1000,60,60])

line = "-"*88
def log(s, elapsed=None):
    print line
    #print secondsToStr(clock()), '-', s
    print datetime.now().strftime("%m:%d:%Y %H:%M:%S"), '-', s
    if elapsed:
        print "Elapsed time :", elapsed
    print line

def endlog():
    #end = clock()
    end = time()
    elapsed = end-start
    log("End Fuzzing", secondsToStr(elapsed))

def now():
    #return secondsToStr(clock())
    return secondsToStr(time())

#start = clock()
start = time()
atexit.register(endlog)
log("Start Fuzzing")

