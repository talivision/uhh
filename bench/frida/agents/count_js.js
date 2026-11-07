// count_js.js -- Interceptor.attach with a JavaScript onEnter: read argument 0 (the handle)
// and argument 3 (the size), bump a counter. No send() per call (count only).
const target = resolveTarget(PARAMS.target);
let calls = 0, sink = 0;

Interceptor.attach(target, {
    onEnter(args) {
        const handle = args[0], size = args[3];
        sink ^= handle.toInt32() ^ size.toInt32();
        calls++;
    },
});

onProcessExit(() => send({ type: 'done', calls, sink }));
send({ type: 'ready', target: target.toString(), runtime: Script.runtime });
