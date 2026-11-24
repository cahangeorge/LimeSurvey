(function () {
    'use strict';

    var namePrefix = 'georgianadaycare:parent-origin:';

    function parseOrigin(address, requireOriginOnly) {
        try {
            var url = new URL(address);
            if ((url.protocol !== 'http:' && url.protocol !== 'https:') ||
                url.username || url.password ||
                (requireOriginOnly && (!/^https?:\/\/[^/?#]+$/i.test(address) ||
                    url.pathname !== '/' || url.search || url.hash)) ||
                url.origin === window.location.origin) return '';
            return url.origin;
        } catch (_) {
            return '';
        }
    }

    if (window.parent === window) return;
    var hasNamedOrigin = window.name.startsWith(namePrefix);
    var targetOrigin = parseOrigin(
        hasNamedOrigin ? window.name.slice(namePrefix.length) : document.referrer,
        hasNamedOrigin
    );
    if (!targetOrigin) return;

    var completed = false;
    var frame = 0;

    function send(message) {
        window.parent.postMessage(message, targetOrigin);
    }

    function checkCompletion() {
        if (!completed && document.querySelector('#completed-wrapper, .completed-wrapper, .submit-wrapper')) {
            completed = true;
            send({ type: 'georgianadaycare:completion' });
        }
    }

    function report() {
        frame = 0;
        var height = Math.min(100000, Math.ceil(Math.max(
            1,
            document.documentElement.scrollHeight,
            document.documentElement.offsetHeight,
            document.documentElement.clientHeight,
            document.body ? document.body.scrollHeight : 0,
            document.body ? document.body.offsetHeight : 0,
            document.body ? document.body.clientHeight : 0
        )));
        send({ type: 'georgianadaycare:resize', height: height });
        checkCompletion();
    }

    function schedule() {
        if (!frame) frame = window.requestAnimationFrame(report);
    }

    function start() {
        if (document.documentElement.dataset.georgianadaycareEmbed) {
            schedule();
            return;
        }
        document.documentElement.dataset.georgianadaycareEmbed = '1';
        if (!document.documentElement.dataset.georgianadaycareReady) {
            document.documentElement.dataset.georgianadaycareReady = '1';
            send({ type: 'georgianadaycare:ready' });
        }
        if (window.ResizeObserver) new ResizeObserver(schedule).observe(document.documentElement);
        new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
        window.addEventListener('resize', schedule, { passive: true });
        document.addEventListener('pjax:scriptcomplete', schedule);
        schedule();
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
    else start();
}());
