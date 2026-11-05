/* latedll fixture (regress `latedll-*`): probed functions in DLLs the target loads at RUN
 * time with LoadLibrary, called LD_CALLS times each right after the load (and from inside
 * DllMain, under the loader lock). Every call must be counted and logged on every backend.
 * Each site is called as Site(id, i); the callback logs "ld <id>". */
#pragma once
#define LD_CALLS 300
#define LD_NSITES 8        /* latedll_fix.dll!LdSite0..7: more inline sites than debug registers */
#define LD_HV_ID 100       /* latedll_heavy.dll!HvSite */
