#pragma once
#include <windows.h>
struct ArEpochControl { HANDLE entered, release; volatile LONG observed; };
