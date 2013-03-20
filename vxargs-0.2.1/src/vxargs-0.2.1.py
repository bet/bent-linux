#!/usr/bin/env python

# DHARMA Project
# Copyright (C) 2003-2004 Yun Mao, University of Pennsylvania
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


"""
vxargs: Visualized xargs with redirected output

"""
version = "0.2.1"
import os, sys, commands, time, signal
import curses, random
import getopt

update_rate = 1

final_stats = {}
def getListFromFile(f, randomize):
    """I'll ignore the line starting with #

    @param f: file object of the host list file
    @return: a list of hostnames (or IPs)
    """

    hostlist = []
    for line in f:
        if line[0]!='#':
            if line.strip():
                hostlist.append([line.strip(),''])
        elif hostlist and hostlist[-1][1]=='':
            hostlist[-1][1] = line.strip()[1:]
    if randomize:
        random.shuffle(hostlist)
    return hostlist

def get_last_line(fn):
    #equ to tail -n1 fn
    try:
        lines = open(fn,'r').readlines()
        if len(lines)>0:
            return (0, lines[-1].strip())
    except IOError:
        pass
    return (1,'')
class Slot:
    def __init__(self, outdir, num, screen, timeout, name, count):
        self.outdir = outdir
        self.slotnum = num
        self.screen = screen
        self.comment = ""
        self.startTime = time.time()
        self.timeout = timeout
        self.name = name
        self.count = count

    def drawLine(self, comment='', done = False):
        if self.screen is None: return
        if comment == '':
            comment = self.comment
        else:
            self.comment = comment
        stdscr = self.screen
        elapsed = time.time()-self.startTime
        try:
            y,x = stdscr.getmaxyx()
            spaces = ' '*x
            stdscr.addstr(self.slotnum+2, 0, spaces) #title occupies two lines
            if done:
                stdscr.addstr(self.slotnum+2,0, comment[:x])
            else:
                #construct the string
                output = "(%3ds)%3d: %s " % ( round(elapsed), self.count, self.name )
                spaceleft = x - len(output)
                if self.outdir and spaceleft>1:
                     outfn = os.path.join(self.outdir, '%s.out' % self.name)
                     errfn = os.path.join(self.outdir, '%s.err' % self.name)
                     lout = get_last_line(outfn)
                     lerr = get_last_line(errfn)
                     if lerr[0]==0 and lerr[1]:
                         output += lerr[1]
                     elif lout[0]==0 and lout[1]:
                         output += lout[1]
                     else:
                         output += comment
                else:
                    output += comment
                stdscr.addstr(self.slotnum+2, 0, output[:x] )
            stdscr.refresh()
        except curses.error: #some of them will be out of screen, ignore it
            pass
    def update(self, pid):
        self.drawLine()
        if self.timeout >0:
            overtime = time.time()-self.startTime - self.timeout
            if overtime > 3: #expired more than 3 seconds, send -9
                os.kill(pid, signal.SIGKILL)
            elif overtime > 2: #expired more than 2 seconds, send -15
                os.kill(pid, signal.SIGTERM)
            elif overtime > 0:
                os.kill(pid, signal.SIGINT)
    
class Slots:
    pids = {}
    def __init__(self, max, screen, timeout, outdir):
        self.maxChild = max
        self.slots = range(self.maxChild)
        self.screen = screen
        self.t = timeout
        self.outdir = outdir
        
    def getSlot(self, name, count):
        if not self.slots:
            #it's empty, wait until other jobs finish
            slot =  self.waitJobs().slotnum
        else:
            slot = self.slots[0]
            self.slots.remove(slot)
        return Slot(self.outdir, slot, self.screen, self.t, name, count)
    
    def mapPID(self, pid, slot):
        """@param slot: slot object
        """
        self.pids[pid] = slot

    def waitJobs(self):
        while 1:
            try:
                pid, status = os.wait()
                break
            except OSError:
                pass
        slot = self.pids[pid]
        if self.outdir:
            open(os.path.join(self.outdir, '%s.status' % slot.name),'w').write('%d' % (status>>8))
            #open(os.path.join(self.outdir, '%s.kill' % slot.name),'w').write('%d' % (status & 0xFF))
            if status & 0xFF:
                open(os.path.join(self.outdir, 'killed_list'),'a').write('%s\n' % (slot.name))
            if status >>8:
                open(os.path.join(self.outdir, 'abnormal_list'),'a').write('%s\n' % (slot.name))
        del self.pids[pid]
        s = status >> 8
        if final_stats.has_key(s):
            final_stats[s]+= 1
        else:
            final_stats[s]=1
        return slot
    def update(self):
        for k,v in self.pids.items():
            v.update(k)
    def timeout(self):
        self.update()
        signal.alarm(update_rate)
        
    def drawTitle(self, stuff):
        if self.screen:
            y,x = self.screen.getmaxyx()
            spaces = ' '*(x*2)
            self.screen.addstr(0,0,  spaces)
            self.screen.addstr(0,0, stuff[:x*2])
            self.screen.refresh()
        else:
            print stuff

gsl = None
def handler(signum, frame):
    if signum==signal.SIGALRM:
        global gsl
        gsl.timeout()
        
def start(stdscr, max_child, hlist, outdir, randomize, commands, timeout):
    total = len(hlist)

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(update_rate)

    win = stdscr
    #if stdscr: win = curses.newwin(max_child+4, 100, 0, 0)
    #curses.nocbreak()
    sl = Slots(max_child, win, timeout, outdir)
    global gsl
    gsl = sl
    count = 0
    for i in hlist:
        slot = sl.getSlot(i[0], count)
        count +=1
        slot.drawLine(i[1])
        #slot.drawLine('')

        x = [per_arg.replace('{}', i[0]) for per_arg in commands]
        sl.drawTitle("%d/%d:%s" %(count, total,' '.join(x)))
        pid = os.fork()
        if pid==0: #child
            outpath = '/dev/null'
            errpath = '/dev/null'
            if outdir:
                outpath = os.path.join(outdir, '%s.out'%i[0])
                errpath = os.path.join(outdir, '%s.err'%i[0])
            out = os.open(outpath, os.O_CREAT|os.O_WRONLY|os.O_TRUNC)
            os.dup2(out,sys.stdout.fileno())
            err = os.open(errpath, os.O_CREAT|os.O_WRONLY|os.O_TRUNC)
            os.dup2(err, sys.stderr.fileno())
            try:
                os.execvp(x[0],x)
            except OSError,e:
                print >> sys.stderr, "vxargs error before execution:",e
            sys.exit(0)
        else: #in parent process
            sl.mapPID(pid, slot)

    while sl.pids:
        slot = sl.waitJobs()
        slot.drawLine('Done', done = True) #Done

def get_output(outdir, argument_list, out= True, err=False, status=False):
    """

    For post processing the output dir.

    @param out: decide whether to process *.out files
    @param err: decide whether to process *.err files
    @param status: decide whether to process *.status files
    
    @return: (out, err, status): out is a hash table, in which the
    keys are the arguments, and the values are the string of the
    output, if available. err is similar. the values of hash table
    status is the value of exit status in int.
    
    """
    if not out and not err and not status:
        raise RuntimeError("one of out, err and status has to be True")
    
    result = ({},{},{})
    map = ('out','err','status')
    p = []
    if out: p.append(0)
    if err: p.append(1)
    if status: p.append(2)
    for arg in argument_list:
        basefn = os.path.join(outdir, arg)
        for i in p:
            fn = '.'.join( (basefn, map[i]) ) #basefn.ext
            try:
                lines = open(fn).readlines()
                result[i][arg]=''.join(lines)
            except IOError:
                pass
    if not status: return result
    int_status = {}
    for k,v in result[2].items():
        try:
            int_status[k] = int(v.strip())
        except ValueError:
            pass
    return result[0], result[1], int_status

def main():
    options = 'hP:ra:o:yt:p'
    long_opts = ['help','max-procs=','randomize','args=','output=','noprompt','timeout=','plain', 'version']
    try:
        opts,args = getopt.getopt(sys.argv[1:], options,long_opts)
    except getopt.GetoptError:
        print "Unknown options"
        usage()
        sys.exit(1)
    #set default values
    ask_prompt = True
    maxchild = 30
    randomize = False
    hostfile = sys.stdin
    outdir = ''
    timeout = 0
    plain = False
    if os.environ.has_key('VXARGS_OUTDIR'):
        outdir = os.environ['VXARGS_OUTDIR']
    for o,a in opts:
        if o in ['--version']:
            print "vxargs version",version
            print "Copyright (c) 2004 Yun Mao (maoy@cis.upenn.edu)"
            print "Freely distributed under GNU LGPL License"
            sys.exit(1)
        elif o in ['-h','--help']:
            usage()
            sys.exit(1)
        elif o in ['-r','--randomize']:
            randomize = True
        elif o in ['-P','--max-procs']:
            maxchild = int(a)
        elif o in ['-a','--args']:
            try:
                hostfile = open(a,'r')
            except IOError:
                print "Cannot find argument file",a
                sys.exit(3)
        elif o in ['-o','--output']:
            outdir = a
            if a =='/dev/null': outdir = ''
        elif o in ['-y','--noprompt']:
            ask_prompt = False
        elif o in ['-t','--timeout']:
            timeout = int(a)
        elif o in ['-p','--plain']:
            plain = True
        else:
            print 'Unknown options'
            usage()
            sys.exit(1)
    if len(args)<1:
        print "No command given."
        usage()
        sys.exit(1)
    #now test outdir
    if outdir:
        if os.path.exists(outdir):
            if not os.path.isdir(outdir):
                print "%s exists and is not a dir, won't continue" % outdir
                sys.exit(3)
            elif ask_prompt:
                if hostfile == sys.stdin:
                    print "You must specify --noprompt (-y) option if no --args (-a) is given. Doing so will destroy folder %s." % (outdir)
                    sys.exit(3)
                else:
                    result = raw_input("%s exists. Continue will destroy everything in it. Are you sure? (y/n) " % (outdir))
                    if result not in ['y','Y']:
                        sys.exit(3)
            os.system('rm -f %s' % (os.path.join(outdir,'*')))
        else:
            os.system('mkdir -p %s' % outdir)
    
    hlist = getListFromFile(hostfile, randomize)
    if plain: # no fancy output
        return start(None, maxchild, hlist, outdir, randomize, args, timeout)
    else:
        # use fancy curses-based animation
        try:
            curses.wrapper(start, maxchild, hlist, outdir, randomize, args, timeout)
        except curses.error:
            sys.exit(4)
    #post execution, output some stats
    total = 0
    for k,v in final_stats.items():
        print "exit code %d: %d job(s)" % (k,v)
        total += v
    print "total number of jobs:", total
def usage():
    print """\
NAME

  vxargs - build and execute command lines from an argument list file
  with visualization and parallelism, and output redirection.
   
DESCRIPTION

  vxargs reads a list of arguments from a txt file or standard input,
  delimited by newlines, and executes the command one or more times
  with initial arguments in which {} is substituted by the arguments
  read from the file or standard input. The current executing commands
  and progress will be dynamically updated on the screen. Stdout and
  stderr of each command will be redirected to separate files. A list
  of all processes with a non-zero exit status is generated in file
  abnormal_list. A list of all timeout processes is generated in file
  killed_list.
  
SYNOPSIS

  vxargs [OPTIONS] command [initial-arguments]

OPTIONS

  --help
    Print a summary of the options to vxargs and exit.

  --max-procs=max-procs, -P max-procs
    Run up to max-procs processes at a time; the default is 30.

  --randomize, -r [OPTIONAL]
    Randomize the host list before all execution.

  --args=filename, -a filename
    The arguments file. If unspecified, the arguments will be read
    from standard input, and -y option must be specified.
    
  --output=outdir, -o outdir
    output directory for stdout and stderr files
    The default value is specified by the environment variable VXARGS_OUTDIR.
    If it is unspecified, both stdout and stderr will be redirected
    to /dev/null.
    Note that if the directory existed before execution, everything
    inside will be wiped.

  --timeout=timeout, -t timeout
    The maximal time in second for each command to execute. timeout=0
    means infinite.  0 (i.e. infinite) is the default value. When the time is up,
    vxargs will send signal SIGINT to the process. If the process does not
    stop after 2 seconds, vxargs will send SIGTERM signal, and send SIGKILL
    if it still keeps running after 3 seconds.

  --noprompt, -y
    Wipe out the outdir without confirmation.

  --plain, -p
    Don't use curses-based output, but plain output to stdout
    instead. It will be less exciting, but will do the same job
    effectively. It is useful if one wants to start vxargs from cron
    or by another program that doesn't want to see the output.
    By default, vxargs uses the curses-based output.

  --version
    Display current version and copyright information.
    
EXAMPLES:
  Suppose the iplist.txt file has following content:
$ cat iplist.txt
216.165.109.79
#planetx.scs.cs.nyu.edu
158.130.6.254
#planetlab1.cis.upenn.edu
158.130.6.253
#planetlab2.cis.upenn.edu
128.232.103.203
#planetlab3.xeno.cl.cam.ac.uk

Note that lines starting with '#' will be interpreted as comment for
the previous lines, which is optional, for visualization purpose only.

$ vxargs -a iplist.txt -o /tmp/result -P 10 ssh upenn_dharma@{} "hostname;uptime"

...[ UI output]...

$ cat /tmp/result/*
planetlab3.xeno.cl.cam.ac.uk
 03:13:21 up 4 days, 14:36,  0 users,  load average: 0.36, 0.44, 0.44
planetlab2.cis.upenn.edu
 03:13:20  up 26 days, 16:19,  0 users,  load average: 8.11, 7.41, 7.41
planetlab1.cis.upenn.edu
 03:13:19  up 22 days, 20:02,  0 users,  load average: 13.60, 12.55, 12.59
ssh: connect to host 216.165.109.79 port 22: Connection timed out
$

other examples:
cat iplist.txt | vxargs -o /tmp/result rsync -az -e ssh --delete mirror $SLICE@{}:

vxargs -a iplist.txt -o /tmp/result ssh {} killall -9 java

For more information, please visit http://dharma.cis.upenn.edu/planetlab/vxargs/
"""
if __name__=='__main__':
    main()
