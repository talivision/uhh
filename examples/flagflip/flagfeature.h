#pragma once
// flagfeature.dll -- a feature-flag object as an application would ship it. IsEnabled is
// virtual (the caller dispatches through the vtable) and is NOT exported: tools find it by
// name in flagfeature.pdb ("flagfeature.dll!Feature::IsEnabled"). Every feature ships off.
class Feature {
public:
    explicit Feature(const char *name) : name_(name) {}
    virtual ~Feature() = default;
    virtual bool IsEnabled() const;      // x86: __thiscall, `this` in ECX; x64: RCX
    const char *name() const { return name_; }
private:
    const char *name_;                   // at this + sizeof(void *) (after the vtable pointer)
    bool enabled_ = false;
};

/* Exported factory (C linkage), looked up with GetProcAddress by the late-loading target. */
extern "C" __declspec(dllexport) Feature *CreateFeature(const char *name);
