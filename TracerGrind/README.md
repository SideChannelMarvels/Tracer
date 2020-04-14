TracerGrind
===========

TracerGrind is a Valgrind tool (plugin) which can generate execution traces of a running process. 
Support is limited to platforms supported by Valgrind and TracerGrind has only been tested under 
X86, X86_64 and ARM.

Installation
------------

TracerGrind requires the complete Valgrind sources to compile as well as a few packages.

For example on a Debian Jessie one would do:

```bash
sudo apt-get install build-essential automake libcapstone-dev libsqlite3-dev
```

And to add support for i386 on an amd64 platform:

```bash
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install --yes --no-install-recommends gcc-multilib
```

The plugin sources have to be copied 
inside Valgrind tree and a few configuration files have to be modified. Those modifications are 
described in patch files provided for various Valgrind versions
3.10.1,
3.11.0,
3.12.0,
3.13.0,
3.15.0.
Below are the full list of commands required to compile it. You can use a different installation prefix 
than /usr (which would overwrite a distribution installation of Valgrind), the default being 
/usr/local.

```bash
wget 'http://valgrind.org/downloads/valgrind-3.12.0.tar.bz2'
tar xf valgrind-3.12.0.tar.bz2
cp -r tracergrind valgrind-3.12.0/
patch -p0 < valgrind-3.12.0.diff
cd valgrind-3.12.0/
./autogen.sh
./configure --prefix=/usr
make -j4
sudo make install
```

### TextTrace

TextTrace requires [Capstone](http://www.capstone-engine.org/) (either 2.X or 3.X).

```bash
make
sudo make install PREFIX=/usr
```

### SqliteTrace

SqliteTrace requires [Capstone](http://www.capstone-engine.org/) (either 2.X or 3.X) and 
[Sqlite] (https://www.sqlite.org/) (tested with 3.11).

```bash
make
sudo make install PREFIX=/usr
```


Usage
-----

Here's the basic command line you would use to trace the `ls` program and generate a binary trace 
file called `ls.trace`.

`valgrind --tool=tracergrind --output=ls.trace ls`

The format of this trace file is described in the `trace_protocol.h` header.

### TextTrace

To view this trace in human readeable format you can use the `TextTrace` utility.

`texttrace ls.trace ls.texttrace`

The text format is relatively easy to read. Each line start with a tag indicating the information 
type:

* `[!]` Information
* `[B]` Basic block
* `[M]` Memory operation
* `[I]` Instruction execution
* `[T]` Thread event
* `[L]` Library load (always at the end)

### SqliteTrace

To visualize this trace with TraceGraph, you need to generate a sqlite database with the 
`sqlitetrace` utility.

`sqlitetrace ls.trace ls.db`

### Filtering

If you trace a large binary you might notice the trace size increase very fast and you might want 
to only trace specific address ranges or binaries. TracerGrind accepts a comma separated list of 
address ranges or binaries in the `--filter=` command line option. Here's an example:

`valgrind --tool=tracergrind --output=ls.trace --filter=0x400000-0x600000,libc.so.6 ls`

You should see lines like this at the start of Valgrind indicating the filters are in effect:

```
==6862== Filtering address range from 0x0000000000400000 to 0x0000000000600000
==6862== Filtering libc.so.6 from 0x0000000004e4a870 to 0x0000000004f76ab4
```
