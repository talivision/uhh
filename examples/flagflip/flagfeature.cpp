// flagfeature.dll: see flagfeature.h.
#include "flagfeature.h"

__declspec(noinline) bool Feature::IsEnabled() const { return enabled_; }

extern "C" __declspec(dllexport) Feature *CreateFeature(const char *name) { return new Feature(name); }
