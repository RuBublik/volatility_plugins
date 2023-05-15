# unlikned_psscan

The ***`unlinked_psscan`*** is a windows volatility plugin, designed to identify potentially suspicious processes that have been unlinked from the *psActiveProcessList*, which is a doubly linked list of all active processes in the system pointed by the *kdbg structure*. If a process is unlinked from this list, it may indicate malicious activity, such as an attempt to hide from system monitoring tools.

The purpose of this plugin is to be the volatility3 equivalent of volatility2 psxview. It compares the psActiveProcessList to various other ways of enumerating processes in memory to find any unlinked processes. Such processes are then reported as potentially suspicious. If required, their memory could be dumped using the *`procdump`* plugin, for instance.

Note that some legitimate reasons exist for a process to be unlinked from the process list, such as during process creation or termination phases. Therefore, this plugin should be used as one tool among many for detecting malicious activity. Its results should be interpreted in the context of other system monitoring and analysis tools.

**Note:**

Currently, this plugin only supports comparing the *psActiveProcessList* to pool tag carving of *_EProcess* structures from memory, performed by *`windows.psscan.PsScan`*. 

More comparison methods may be added in the future.
