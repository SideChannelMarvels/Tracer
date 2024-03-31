TracerPIN
=========

TracerPIN an Intel PIN tool for generating execution traces of a running process.
Support is limited to platforms supported by Intel PIN and TracerPIN has only been tested under
X86 and X86_64.

Installation
------------

TracerPIN requires the [Intel PIN framework](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html) to compile and run as well as a few packages.

For example on a Debian Jessie one would do:

```bash
sudo apt-get install --no-install-recommends wget make g++
sudo apt-get install --no-install-recommends libstdc++-4.9-dev libssl-dev
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install --no-install-recommends gcc-multilib g++-multilib
sudo apt-get install --no-install-recommends libstdc++-4.9-dev:i386 libssl-dev:i386
```

Then for Intel PIN, make sure the user has r/w access to the PIN installation and to ease the next steps define PIN_ROOT:

```bash
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.30-98830-g1d7b601b3-gcc-linux.tar.gz
tar xzf pin-3.30-98830-g1d7b601b3-gcc-linux.tar.gz
mv pin-3.30-98830-g1d7b601b3-gcc-linux /opt
export PIN_ROOT=/opt/pin-3.30-98830-g1d7b601b3-gcc-linux
echo -e "\nexport PIN_ROOT=/opt/pin-3.30-98830-g1d7b601b3-gcc-linux" >> ~/.bashrc
```

Now you're ready to compile TracerPIN and install it.

```bash
make
sudo make install
```

Usage
-----

Calling the tool without argument will provide some help:

```bash
Tracer
```

### Human-readable trace

Here's the basic command line you would use to trace the `ls` program and generate a human readable trace 
file called `ls.log`.

```bash
Tracer -o ls.log -- ls
```

or to accept the default filename, just do

```bash
Tracer ls
```

The text format is relatively easy to read. Each line start with a tag indicating the information 
type:

* `[*]` Arguments
* `[-]` Information on base image and libraries
* `[!]` Information on filtered elements
* `[T]` Thread event
* `[B]` Basic block
* `[C]` Function call
* `[R]` Memory read operation
* `[I]` Instruction execution
* `[W]` Memory write operation

### TraceGraph

To visualize this trace with TraceGraph, you need to generate a sqlite database with the 
`-t sqlite` option.

```bash
Tracer -t sqlite -o ls.db -- ls
```

### Filtering addresses

If you trace a large binary you might notice the trace size increase very fast and you might want 
to only trace specific address ranges or binaries. TracerPIN accepts several command line options
to filter the address range.

Option `-f` is used to limit tracing to a given range.

By default (`-f 1`) it's tracing all but system libraries.
It's possible to force to trace them too: `-f 0` or to trace only the main executable: `-f 2` or to
provide a range of addresses to trace: `-f 0x400000-0x410000`.
Option `-f` is about what to instrument when BBLs are getting parsed but it's also possible to give
indications when to instrument, e.g. when you want to capture only a specific iteration of a loop.
To do so, use option `-F 0x400000:0x410000`. This time the addresses serve as a start and stop indicators,
not as an address range, and it's possible to target a specific iteration with the option `-n`,
while by default all iterations will be recorded.

### Filtering information

You may also want to limit the trace to a subset of information.

By default are logged:

* function calls (without their arguments)
* basic blocs
* instructions
* memory accesses

It's possible to disable any of them and it's possible to enable an experimental tracing of the
function calls with their arguments, or at least what Intel PIN can find about them.
Run the tool without arguments to get help about those options.

Troubleshooting
---------------

We noticed the following problem using PIN on IA32 binaries on Debian Stretch under a Linux kernel > 4.3:

```
A: Source/pin/vm_ia32_l/jit_region_ia32_linux.cpp: XlateSysCall: 33: Sysenter is supported on IA32 only and the expected location is inside Linux Gate

################################################################################
## STACK TRACE
################################################################################
etc
```

Strangely enough, running a Debian Jessie in a Docker with the same kernel > 4.3 works fine.  
So till the root cause of this issue is found, please either make sure to run a kernel <= 4.3 or to run from a Docker image with Debian Jessie.

Credits
-------

Based on code written by
* Arnaud Maillet for his [NSC2013 challenge writeup](http://kutioo.blogspot.be/2013/05/nosuchcon-2013-challenge-write-up-and.html)
* tracesurfer for [SSTIC2010](https://code.google.com/p/tartetatintools/)
* Carlos G. Prado for his [Brucon workshop](http://brundlelab.wordpress.com/2013/09/30/brucon-2013-workshop-slides/)
* source/tools/SimpleExamples/trace.cpp by Intel
