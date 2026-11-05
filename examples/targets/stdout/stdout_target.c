/* stdout_target -- writes its stdout/stderr in the ways that used to get live log records
   spliced into its lines (ROADMAP D2/F8): one byte per WriteFile, unbuffered UCRT printf,
   4 KiB CRT buffer chunks that split lines, binary bytes, a prompt without a newline, and
   writes that continue an unfinished line after a pause. A worker thread calls a probed
   function (GetFileAttributesA) at a high rate meanwhile, so records arrive all the time.

     stdout_target run [--prompt]   all phases; --prompt reads a line from stdin at the prompt
     stdout_target mixed            stdout and stderr partial lines interleaved (for 2>&1)
     stdout_target orphan           start a grandchild that keeps the stdout/stderr handles
                                    open for 20 s, print its pid, exit
     stdout_target sleep <ms>       (the grandchild)
   The output is deterministic: an uninstrumented run is the ground truth. */
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HANDLE out, err;
static volatile LONG stop_worker;
static volatile LONG worker_calls;

static void raw(HANDLE h, const char *p, DWORD n) { DWORD w; WriteFile(h, p, n, &w, NULL); }
static void bytewise(HANDLE h, const char *text) { for (; *text; ++text) raw(h, text, 1); }

static DWORD WINAPI worker(void *arg) {
    (void)arg;
    while (!stop_worker && worker_calls < 20000) { GetFileAttributesA("C:\\uhh-stdout-target-nonexistent"); InterlockedIncrement(&worker_calls); Sleep(0); }
    return 0;
}

static int run(int prompt) {
    char line[256];
    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    /* 1: one byte per WriteFile, stdout and stderr */
    for (int i = 0; i < 40; ++i) {
        snprintf(line, sizeof line, "bytewise line %d: the quick brown fox jumps over the lazy dog\n", i);
        bytewise(out, line);
        if (i % 4 == 0) { snprintf(line, sizeof line, "E bytewise stderr %d\n", i); bytewise(err, line); }
    }
    /* 2: unbuffered UCRT stream */
    FILE *unbuf = _fdopen(_dup(1), "w");
    setvbuf(unbuf, NULL, _IONBF, 0);
    for (int i = 0; i < 40; ++i) fprintf(unbuf, "unbuffered %d %s %08x\n", i, "lorem ipsum dolor sit amet", i * 2654435761u);
    fclose(unbuf);
    /* 3: fully buffered 4 KiB CRT stream: every flush ends mid-line */
    FILE *buf = _fdopen(_dup(1), "w");
    setvbuf(buf, NULL, _IOFBF, 4096);
    for (int i = 0; i < 1500; ++i) fprintf(buf, "buffered %d %s\n", i, (i % 7) ? "abcdefghijklmnopqrstuvwxyz" : "x");
    fclose(buf);
    /* 4: binary bytes, odd chunk sizes, \r \n \0 and high bytes included */
    unsigned char bin[256 * 8];
    for (int i = 0; i < (int)sizeof bin; ++i) bin[i] = (unsigned char)((i * 37 + i / 256) & 0xff);
    for (int i = 0, n = 1; i < (int)sizeof bin; i += n, n = n % 29 + 1)
        raw(out, (const char *)bin + i, (DWORD)min(n, (int)sizeof bin - i));
    raw(out, "\n", 1);
    /* 5: a prompt without a newline, then the line continues after a pause / an answer */
    bytewise(out, "prompt> ");
    char answer[64] = "none";
    if (prompt) {
        DWORD got = 0, n = 0; char c;
        HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
        while (n + 1 < sizeof answer && ReadFile(in, &c, 1, &got, NULL) && got && c != '\n') if (c != '\r') answer[n++] = c;
        answer[n] = 0;
    } else Sleep(300);
    snprintf(line, sizeof line, "answer=%s, and this line goes on byte by byte after the pause\n", answer);
    bytewise(out, line);
    /* 6: an unfinished stderr line that is finished later */
    bytewise(err, "E partial stderr ");
    Sleep(120);
    bytewise(err, "finished\n");
    stop_worker = 1;
    WaitForSingleObject(t, INFINITE);
    bytewise(out, "END stdout_target\n");
    return 0;
}

static int mixed(void) {
    char line[128];
    for (int i = 0; i < 60; ++i) {
        snprintf(line, sizeof line, "O%d part", i); bytewise(out, line);
        snprintf(line, sizeof line, "E%d\n", i); bytewise(err, line);
        bytewise(out, " rest\n");
    }
    bytewise(out, "END mixed\n");
    return 0;
}

static int orphan(void) {
    wchar_t self[MAX_PATH], cmd[MAX_PATH + 32];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    _snwprintf(cmd, sizeof cmd / sizeof *cmd, L"\"%s\" sleep 20000", self);
    STARTUPINFOW si = {sizeof si}; PROCESS_INFORMATION pi;
    if (!CreateProcessW(self, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) return 2;
    char line[64]; snprintf(line, sizeof line, "grandchild %lu\n", pi.dwProcessId);
    bytewise(out, line);
    return 0;
}

int main(int argc, char **argv) {
    out = GetStdHandle(STD_OUTPUT_HANDLE); err = GetStdHandle(STD_ERROR_HANDLE);
    if (argc >= 2 && !strcmp(argv[1], "run")) return run(argc >= 3 && !strcmp(argv[2], "--prompt"));
    if (argc >= 2 && !strcmp(argv[1], "mixed")) return mixed();
    if (argc >= 2 && !strcmp(argv[1], "orphan")) return orphan();
    if (argc >= 3 && !strcmp(argv[1], "sleep")) { Sleep((DWORD)atoi(argv[2])); return 0; }
    fprintf(stderr, "usage: stdout_target run [--prompt] | mixed | orphan | sleep <ms>\n");
    return 2;
}
