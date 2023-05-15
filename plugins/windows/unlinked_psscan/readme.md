In normal operation, the psActiveProcessList is a doubly linked list of all
active processes in the system. If a process has been unlinked from this
list, it may indicate malicious activity, such as an attempt to hide the
process from system monitoring tools.

The idea fopr this plugin is to be the volatility3 version of volatility2 psxview.
It compares the psActiveProcessList to various other ways to enumerate processes in
memory, to find processes that have been unlinked.
Any such processes are reported as potentially suspicious.
- Such processes' memory could be then dumped, with procdump for example.

Note that there may be legitimate reasons for a process to be unlinked from
the process list, such as during the process creation or termination
phases. Therefore, this plugin should be used as one tool among many for
detecting malicious activity, and its results should be interpreted in the
context of other system monitoring and analysis tools.


* This plugin currently supports comparison of psActiveProcessList only to pool tag carving of _EProcess structures from memory, performed by windows.psscan.PsScan.
More ways are coming in the future.
