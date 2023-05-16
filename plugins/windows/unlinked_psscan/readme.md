# unlinked_psscan

The ***`unlinked_psscan`*** is a windows volatility plugin, designed to identify potentially suspicious processes that have been unlinked from various structures - which might indicate malicious activity, such as  achieving defense evasion. in other words, an attempt to hide from system monitoring tools.

The purpose of this plugin is to be the volatility3 equivalent of volatility2 psxview. It compares the psActiveProcessList to various other ways of enumerating processes in memory to find any unlinked processes. Such processes are then reported as potentially suspicious. If required, their memory could be dumped using the *`procdump`* plugin, for instance.

Note that some legitimate reasons exist for a process to be unlinked from the process list, such as during process creation or termination phases. Therefore, this plugin should be used as one tool among many for detecting malicious activity. Its results should be interpreted in the context of other system monitoring and analysis tools.

**Note:**

Currently, this plugin supports comparing the processes discovered by performing pool tag carving of *_EProcess* structures (by using *`windows.psscan.PsScan`*), to:
* *psActiveProcessList* - a doubly linked list of *_EProcess* structures pointed by the *kdbg structure*.
* handle table of system process - the system process holds in its handle table the handles to all processes, except for its processes (created by the kernel during startup)

More comparison methods may be added in the future.

Usage
---------

**'only-susp'**

by default, this plugin includes all processes found in the image, ommits relatively little info, and mentions weather the process exists in the *psActiveProcessList* or not.

with **'only-susp'** option enabled, the plugin will will display only  processes potentially unlinked from *psActiveProcessList* and with greater verbosity.

**'physical'**

additionally, this plugin also supports `pslist` / `psscan` option **'physical'**, which displays physical offset instead of virtual.
