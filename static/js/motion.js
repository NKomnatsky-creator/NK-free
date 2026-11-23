/* =========================================================================
   NKMotion — утилиты для плавного UX на 60/120+ Гц.

   • flip()     — анимирует перемещение элементов через transform (WAAPI),
                  не трогая layout. Используется при фильтрации сетки паролей.
   • rafThrottle() — группирует частые события (scroll/resize) в один кадр.
   • is-scrolling  — класс на <html>, позволяет CSS снять backdrop-filter
                  на время скролла.

   Модуль не ломает страницу, если WAAPI или matchMedia недоступны.
   ========================================================================= */

(function () {
    'use strict';

    const root = document.documentElement;
    const reduceQuery = window.matchMedia
        ? window.matchMedia('(prefers-reduced-motion: reduce)')
        : { matches: false };
    const canAnimate = typeof Element.prototype.animate === 'function';

    const DURATION = 260;
    const EASING = 'cubic-bezier(0.2, 0, 0, 1)';

    /** Сгруппировать частые вызовы в один requestAnimationFrame. */
    function rafThrottle(fn) {
        let queued = false;
        let lastArgs = null;
        return function () {
            lastArgs = arguments;
            if (queued) return;
            queued = true;
            requestAnimationFrame(function () {
                queued = false;
                fn.apply(this, lastArgs);
            });
        };
    }

    function keyOf(el) {
        return el.dataset.flipKey || el.dataset.id ||
            (el.tagName + ':' + String(el.className || ''));
    }

    /**
     * FLIP: запоминаем позиции, выполняем mutate(), затем анимируем
     * разницу через transform. Новые элементы плавно появляются.
     *
     * @param {Element} container
     * @param {Function} mutate    — функция, меняющая содержимое container
     * @param {Object} [options]   — { selector: ':scope > *' }
     */
    function flip(container, mutate, options) {
        const opts = options || {};
        const selector = opts.selector || ':scope > *';

        if (!container || reduceQuery.matches || !canAnimate ||
            typeof container.querySelectorAll !== 'function') {
            mutate();
            return;
        }

        let before = new Map();
        try {
            before = new Map(Array.from(container.querySelectorAll(selector)).map(function (el) {
                return [keyOf(el), el.getBoundingClientRect()];
            }));
        } catch (_) {
            before = new Map();
        }

        mutate();

        let items;
        try {
            // Сначала читаем все прямоугольники, потом пишем анимации —
            // так не чередуются layout read и write.
            items = Array.from(container.querySelectorAll(selector)).map(function (el) {
                return [el, el.getBoundingClientRect()];
            });
        } catch (_) {
            return;
        }

        items.forEach(function (pair) {
            const el = pair[0];
            const rect = pair[1];
            const prev = before.get(keyOf(el));

            // Отменяем предыдущую анимацию, чтобы не копить их при быстром вводе.
            if (typeof el.getAnimations === 'function') {
                el.getAnimations().forEach(function (a) { a.cancel(); });
            }

            if (!prev) {
                el.animate([
                    { opacity: 0, transform: 'translateY(10px) scale(0.985)' },
                    { opacity: 1, transform: 'none' }
                ], { duration: DURATION, easing: EASING });
                return;
            }

            const dx = prev.left - rect.left;
            const dy = prev.top - rect.top;
            if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;

            el.classList.add('is-flipping');
            const anim = el.animate([
                { transform: 'translate(' + dx + 'px, ' + dy + 'px)' },
                { transform: 'translate(0, 0)' }
            ], { duration: DURATION, easing: EASING });

            const done = function () { el.classList.remove('is-flipping'); };
            if (anim && anim.finished && typeof anim.finished.then === 'function') {
                anim.finished.then(done, done);
            } else {
                setTimeout(done, DURATION);
            }
        });
    }

    /* --- Состояние скролла ------------------------------------------------ */

    let scrollTimer = 0;
    const onScroll = rafThrottle(function () {
        root.classList.add('is-scrolling');
        clearTimeout(scrollTimer);
        scrollTimer = setTimeout(function () {
            root.classList.remove('is-scrolling');
        }, 140);
    });

    window.addEventListener('scroll', onScroll, { passive: true });

    window.NKMotion = {
        flip: flip,
        rafThrottle: rafThrottle,
        get reduced() { return !!reduceQuery.matches; }
    };
})();
