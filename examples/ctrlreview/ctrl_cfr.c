/* ctrl_cfr_a.dll / ctrl_cfr_b.dll (regress cdx-cfreuse-*): two DLLs the target loads in turn
   under ONE name (cfr.dll, from two directories) at ONE fixed base. call_func of
   "cfr.dll!CfrValue" must reach A's (1) while A is loaded, nothing once it is unloaded, and B's
   (2) once B is mapped where A was -- never A's address in B, where CfrDecoy (99) now is. No CRT,
   no entry point: .text holds just these functions, in this order. */
#ifdef CFR_B
__declspec(dllexport) __declspec(noinline) int CfrDecoy(void) { return 99; }   /* where A's CfrValue was */
__declspec(dllexport) __declspec(noinline) int CfrPad(void) { return 98; }
__declspec(dllexport) __declspec(noinline) int CfrValue(void) { return 2; }
#else
__declspec(dllexport) __declspec(noinline) int CfrValue(void) { return 1; }
#endif
