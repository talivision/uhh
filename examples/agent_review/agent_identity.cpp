// Legitimate alternate build for session-agentipc-identity. An extra export makes
// the image distinct even with reproducible linker timestamps.
extern "C" __declspec(dllexport) unsigned uhh_test_agent_identity() { return 0x4944454eU; }
