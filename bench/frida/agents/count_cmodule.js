// count_cmodule.js -- Interceptor.attach with a CModule (C) onEnter: the hot callback runs
// natively on the calling thread, no JavaScript. Same work as count_js.js: read argument 0 and
// argument 3, bump a counter. Writable state lives in memory allocated by JS and handed to the
// C code as `extern` symbols (CModule data is read-only), and the count is atomic: the hook runs
// on all 8 worker threads at once.
const target = resolveTarget(PARAMS.target);
const state = Memory.alloc(Process.pointerSize * 2);   // calls, sink

const cm = new CModule(`
#include <gum/guminterceptor.h>
#include <glib.h>

extern volatile gint calls;
extern volatile gsize sink;

void
on_enter (GumInvocationContext * ic)
{
  gsize handle = (gsize) gum_invocation_context_get_nth_argument (ic, 0);
  gsize size = (gsize) gum_invocation_context_get_nth_argument (ic, 3);

  sink ^= handle ^ size;
  g_atomic_int_add (&calls, 1);
}
`, {
    calls: state,
    sink: state.add(Process.pointerSize),
});

Interceptor.attach(target, { onEnter: cm.on_enter });

onProcessExit(() => send({ type: 'done', calls: state.readS32() }));
send({ type: 'ready', target: target.toString(), runtime: Script.runtime });
