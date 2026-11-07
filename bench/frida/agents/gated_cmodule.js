// gated_cmodule.js -- the WHOLE examples/gated_config in Frida with the hot callbacks in C
// (CModule): the same three parts as gated_js.js, record for record, but the NtOpenProcess /
// NtClose / NtReadVirtualMemory callbacks run natively and concurrently on the target's
// threads (no JavaScript on the hot path, no JS lock).
//
// Records go into a lock-free multi-producer ring (shared memory allocated by JS, passed to C
// as extern symbols): a producer reserves a slot with an atomic add, fills it and publishes it
// with its sequence number; when the ring is full it WAITS (yields) for the drain -- backpressure,
// never a drop. JavaScript drains the ring on a timer (immediately again while it is busy) and
// sends each chunk as ONE binary message: send(meta, ArrayBuffer). The flag flip stays an
// instruction probe in JS: it fires once.
//
// Record (80 bytes): u32 seq, u32 tid, u32 kind (1 read, 2 open+map), u32 0,
//                    u64 handle, u64 pid, u64 addr, u64 size, char name[32].
const RING = 65536;                              // records, a power of two
const REC = 80;
const is64 = Process.pointerSize === 8;
const ntdll = Process.getModuleByName('ntdll.dll');

const ring = Memory.alloc(RING * REC);
const ctl = Memory.alloc(64);                    // head (reserve), tail (drain), stats
const map = Memory.alloc(0x10000 * 48);          // direct table: one slot per handle >> 2
const out = Memory.alloc(RING * REC);

const cm = new CModule(`
#include <gum/guminterceptor.h>
#include <glib.h>
#include <string.h>

#define RING ${RING}
#define SLOTS 0x10000

typedef struct { guint32 seq, tid, kind, pad; guint64 handle, pid, addr, size; gchar name[32]; } Rec;
typedef struct { volatile guint64 pid; volatile guint64 handle; gchar name[32]; } Slot;
typedef struct { gpointer pid; gushort len, maxlen; gpointer buf; } SysProcIdInfo;
typedef struct { gpointer out; guint64 pid; } OpenState;

extern Rec ring[];
extern volatile guint head;
extern volatile guint tail;
extern volatile gint reads;
extern volatile gint opens;
extern volatile gint waits;
extern Slot map[];
#if GLIB_SIZEOF_VOID_P == 4
extern int __attribute__((stdcall)) NtQuerySystemInformation (int, void *, unsigned int, void *);
#else
extern int NtQuerySystemInformation (int, void *, unsigned int, void *);
#endif

static Rec *
reserve (void)
{
  guint pos = (guint) g_atomic_int_add ((volatile gint *) &head, 1);
  while (pos - tail >= RING)
  {
    g_atomic_int_add (&waits, 1);
    g_thread_yield ();
  }
  Rec * r = &ring[pos & (RING - 1)];
  r->pad = pos;                                 /* its position; publish() turns it into seq */
  return r;
}

static void
publish (Rec * r)
{
  /* x86/x64 keep stores in order: the fields are visible before the sequence number. */
  *(volatile guint32 *) &r->seq = r->pad + 1;
}

static void
image_name_of (guint64 pid, gchar * name)
{
  gunichar2 path[260];
  SysProcIdInfo info;
  int i, start = 0, n = 0, len;

  info.pid = GSIZE_TO_POINTER ((gsize) pid);
  info.len = 0;
  info.maxlen = sizeof (path);
  info.buf = path;
  if (NtQuerySystemInformation (88, &info, sizeof (info), NULL) >= 0)
  {
    len = info.len / 2;
    for (i = 0; i != len; i++)
      if (path[i] == '\\\\')
        start = i + 1;
    for (i = start; i < len && n < 31; i++)
      name[n++] = path[i] < 0x80 ? (gchar) path[i] : '?';
  }
  if (n == 0)
    name[n++] = '?';
  name[n] = 0;
}

void
open_enter (GumInvocationContext * ic)
{
  OpenState * st = GUM_IC_GET_INVOCATION_DATA (ic, OpenState);
  gsize * cid = gum_invocation_context_get_nth_argument (ic, 3);

  st->out = gum_invocation_context_get_nth_argument (ic, 0);
  st->pid = (cid != NULL) ? (guint64) cid[0] : 0;
}

void
open_leave (GumInvocationContext * ic)
{
  OpenState * st = GUM_IC_GET_INVOCATION_DATA (ic, OpenState);
  gint32 status = (gint32) GPOINTER_TO_SIZE (gum_invocation_context_get_return_value (ic));
  guint64 handle;
  Slot * s;
  Rec * r;

  if (status < 0 || st->out == NULL || st->pid == 0)
    return;
  handle = *(gsize *) st->out;
  if (handle == 0)
    return;

  s = &map[(handle >> 2) % SLOTS];
  s->pid = 0;                                   /* unpublish while rewriting */
  image_name_of (st->pid, s->name);
  s->handle = handle;
  s->pid = st->pid;
  g_atomic_int_add (&opens, 1);

  r = reserve ();
  r->tid = gum_invocation_context_get_thread_id (ic);
  r->kind = 2;
  r->handle = handle;
  r->pid = st->pid;
  r->addr = 0;
  r->size = 0;
  memcpy (r->name, s->name, 32);
  publish (r);
}

void
close_enter (GumInvocationContext * ic)
{
  guint64 handle = (gsize) gum_invocation_context_get_nth_argument (ic, 0);
  Slot * s = &map[(handle >> 2) % SLOTS];

  if (handle != 0 && s->handle == handle)
    s->pid = 0;
}

void
read_enter (GumInvocationContext * ic)
{
  guint64 handle = (gsize) gum_invocation_context_get_nth_argument (ic, 0);
  Slot * s = &map[(handle >> 2) % SLOTS];
  guint64 pid = 0, again;
  gchar name[32];
  int tries;
  Rec * r;

  name[0] = '?'; name[1] = 0;
  for (tries = 0; tries != 4 && handle != 0; tries++)
  {
    pid = s->pid;
    guint64 h = s->handle;
    memcpy (name, s->name, 32);
    again = s->pid;
    if (again == pid)
    {
      if (h != handle || pid == 0)
      {
        pid = 0;
        name[0] = '?'; name[1] = 0;
      }
      break;
    }
  }

  r = reserve ();
  r->tid = gum_invocation_context_get_thread_id (ic);
  r->kind = 1;
  r->handle = handle;
  r->pid = pid;
  r->addr = (gsize) gum_invocation_context_get_nth_argument (ic, 1);
  r->size = (gsize) gum_invocation_context_get_nth_argument (ic, 3);
  memcpy (r->name, name, 32);
  g_atomic_int_add (&reads, 1);
  publish (r);
}

/* Called from JS: copy every published record, in order, to dst; return how many. */
guint
drain (Rec * dst, guint max)
{
  guint n = 0;

  while (n != max)
  {
    Rec * r = &ring[tail & (RING - 1)];
    if (*(volatile guint32 *) &r->seq != tail + 1)
      break;
    memcpy (&dst[n], r, sizeof (Rec));
    dst[n].seq = tail;
    n++;
    tail = tail + 1;
  }
  return n;
}
`, {
    ring,
    head: ctl,
    tail: ctl.add(4),
    reads: ctl.add(8),
    opens: ctl.add(12),
    waits: ctl.add(16),
    map,
    NtQuerySystemInformation: ntdll.getExportByName('NtQuerySystemInformation'),
});

const drain = new NativeFunction(cm.drain, 'uint', ['pointer', 'uint']);

// --- 1. the flag (fires once: JS) -----------------------------------------------------------
let overrides = 0, flagHits = 0;
function hookFlag(m) {
    Interceptor.attach(m.getExportByName('ParseConfig').add(0x16), function () {
        flagHits++;
        const ctx = this.context;
        if (is64) { if (ctx.rax.and(0xffffffff).isNull()) { ctx.rax = ptr(1); overrides++; } }
        else if (ctx.eax.isNull()) { ctx.eax = ptr(1); overrides++; }
    });
}
Process.attachModuleObserver({
    onAdded(m) { if (m.name.toLowerCase() === 'configparse.dll') hookFlag(m); },
});

// --- 2. + 3. native callbacks ----------------------------------------------------------------
Interceptor.attach(ntdll.getExportByName('NtOpenProcess'), { onEnter: cm.open_enter, onLeave: cm.open_leave });
Interceptor.attach(ntdll.getExportByName('NtClose'), { onEnter: cm.close_enter });
Interceptor.attach(ntdll.getExportByName('NtReadVirtualMemory'), { onEnter: cm.read_enter });

// --- delivery -----------------------------------------------------------------------------------
let sent = 0, batches = 0;
function pump() {
    let total = 0;
    for (;;) {
        const n = drain(out, RING);
        if (n === 0) break;
        send({ type: 'bin', n }, out.readByteArray(n * REC));
        sent += n; batches++; total += n;
        if (n < RING) break;
    }
    return total;
}
function tick() {
    const n = pump();
    setTimeout(tick, n > 0 ? 0 : 2);
}
setTimeout(tick, 2);

onProcessExit(() => {
    while (pump() > 0) {}
    send({ type: 'done', reads: ctl.add(8).readS32(), opens: ctl.add(12).readS32(), waits: ctl.add(16).readS32(),
           sent, batches, overrides, flagHits });
});
send({ type: 'ready', runtime: Script.runtime });
