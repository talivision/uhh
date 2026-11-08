// Each image owns ModValue and forwards ForwardValue to the OTHER image.
// No import dependency: the target loads and unloads the images independently.
// Emit the forwarder directly in the object's linker directives, with a named export
// at ordinal 1. CMake supplies the owner's actual output basename, without .dll.
#pragma comment(linker, "/export:ForwardValue=" MODREL_FORWARD_OWNER ".ModValue,@1")
int modrel_forward_dummy;
// Retain a relocation even under /OPT:REF so either image can load at a new base.
__declspec(dllexport) int *ModForwardRelocation = &modrel_forward_dummy;

__declspec(dllexport) __declspec(noinline) int ModValue(int x) {
    volatile int value = x;
    return value + 7;
}
