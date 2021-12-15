TraceGraph
==========

TraceGraph is a GUI for visualizing execution traces produced by TracerGrind and TracerPin.

Installation
------------

TraceGraph requires [Qt5] (http://www.qt.io/) and [Sqlite] (https://www.sqlite.org/).

For example on a Debian Jessie one would do:

```bash
sudo apt-get install build-essential qt5-qmake qtbase5-dev-tools qtbase5-dev libsqlite3-dev
```

Then, to compile and install TraceGraph:

```bash
qmake -qt=5
make
sudo make install
```

By default tracegraph installed in /usr/bin. If you want to change destination, edit tracegraph.pro
and adapt `target.path = /usr/bin` to your needs.

Usage
-----

Use the `File > Open Database` menu to open a sqlite database. Once the database is loaded, use
the `Trace > Overview zoom` to display the entire trace on screen (this might take a while on
large traces).

The vertical axis represents the time with the earliest event at the top while the horizontal axis
represents the memory space with the lowest address on the left. There are 3 types of block visible
on the graph:

* Black blocks represent executed instructions.
* Green blocks represent memory reads.
* Red blocks represent memory writes.
* Orange blocks represent memory reads and writes.

There are also vertical orange lines which represent memory space ellipsis. Indeed the memory space
of a binary is usually too sparse to display in full on the screen, this is why TraceGraph cuts the
memory pages which are never addressed in the trace from the graph. Those cuts are represented by
orange vertical lines with the start address of the visible block written at the bottom.

You can also click on a block (*) to obtain informations which
will be displayed on the right pane. The complete command list:

* arrow keys: move arround.
* left click: select block.
* left click drag: move arround.
* ctrl + left click: dump data (max 1024 bytes)
* scroll up: zoom in.
* scroll down: zoom out.
* ctrl + scroll up: zoom in on address axis only.
* ctrl + scroll down: zoom out on address axis only.
* shift + scroll up: zoom in on time axis only.
* shift + scroll down: zoom out on time axis only.
* right click drag: zoom in the dragged rectangle.
* ctrl + right click drag: zoom out form the dragged rectangle.
* +: increase block size
* -: decrease block size

Additionally you can save a image of the graph currently on screen (you know, for making slides
and stuff ;D).

(*) to ease that process, you can increase temporarily the blocks size (press "+" several times).
