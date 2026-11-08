// A forwarding image with no dependency/import: the target loads the owner independently.
// Emit the forwarder directly in the object's linker directives, with a named export
// at ordinal 1. CMake supplies the owner's actual output basename, without .dll.
#pragma comment(linker, "/export:ForwardValue=" MODREL_FORWARD_OWNER ".ModValue,@1")
int modrel_forward_dummy;
// Retain an absolute address even under /OPT:REF. With /FIXED this image really
// requires its preferred base; it is not an address-independent export-only image.
__declspec(dllexport) int *ModForwardRelocation = &modrel_forward_dummy;
