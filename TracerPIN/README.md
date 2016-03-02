TracerPIN
=========

TracerPIN an Intel PIN tool for generating execution traces of a running process.
Support is limited to platforms supported by Intel PIN and TracerPIN has only been tested under
X86 and X86_64.

Installation
------------

TracerPIN requires the Intel PIN framework to compile and run as well as a few packages. For example on a Debian Jessie one would do:

```bash
sudo apt-get install --no-install-recommends wget ca-certificates make g++ libstdc++-4.9-dev libssl-dev libsqlite3-dev
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install --no-install-recommends gcc-multilib g++-multilib libstdc++-4.9-dev:i386 libssl-dev:i386 libsqlite3-dev:i386
```

Then for Intel PIN, make sure the user has r/w access to the PIN installation and to ease the next steps define PIN_ROOT:

```bash
wget http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.13-65163-gcc.4.4.7-linux.tar.gz
tar xzf pin-2.13-65163-gcc.4.4.7-linux.tar.gz
sudo mv pin-2.13-65163-gcc.4.4.7-linux /opt
export PIN_ROOT=/opt/pin-2.13-65163-gcc.4.4.7-linux
echo -e "\nexport PIN_ROOT=/opt/pin-2.13-65163-gcc.4.4.7-linux" >> ~/.bashrc
```

Now you're ready to compile TracerPIN and install it.

```bash
make
sudo cp -a Tracer /usr/local/bin
sudo cp -a obj-* /usr/local/bin
```

If your default gcc is too recent for PIN, you'll get an error such as:

`error: #error The C++ ABI of your compiler does not match the ABI of the pin kit.`

You can tell make to use an older one (provided that you installed it), e.g.:

```bash
make CXX=g++-4.9
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

### Filtering

If you trace a large binary you might notice the trace size increase very fast and you might want 
to only trace specific address ranges or binaries. TracerPIN accepts several command line options
to filter the address range.

TODO


Credits
-------

Based on code written by
* Arnaud Maillet for his NSC2013 challenge writeup (http://kutioo.blogspot.be/2013/05/nosuchcon-2013-challenge-write-up-and.html)
* tracesurfer for SSTIC2010 (https://code.google.com/p/tartetatintools/)
* Carlos G. Prado for his Brucon workshop (http://brundlelab.wordpress.com/2013/09/30/brucon-2013-workshop-slides/)
* source/tools/SimpleExamples/trace.cpp by Intel

