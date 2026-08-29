(function () {
    var THEME_STORAGE_KEY = 'theme';
    var DEFAULT_THEME = 'dark';

    /** The persisted theme, or the default when nothing valid is stored. */
    function getTheme() {
        var persisted = localStorage.getItem(THEME_STORAGE_KEY);
        if (persisted === 'dark' || persisted === 'light') return persisted;
        return DEFAULT_THEME;
    }

    /** Persist a theme choice. */
    function setTheme(theme) {
        localStorage.setItem(THEME_STORAGE_KEY, theme);
        applyTheme(theme);
        document.dispatchEvent(new CustomEvent('themechange', { detail: { theme: theme } }));
    }

    /** Put the theme on the document, which is what the CSS variables key off. */
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }

    /** Draw the sun/moon toggle icon into its canvas at device resolution. */
    function drawThemeIcon(canvas, theme, color) {
        if (!canvas) return;

        var size = 20;
        var dpr = Math.max(1, window.devicePixelRatio || 1);
        var pixelSize = Math.round(size * dpr);

        if (canvas.width !== pixelSize || canvas.height !== pixelSize) {
            canvas.width = pixelSize;
            canvas.height = pixelSize;
            canvas.style.width = size + 'px';
            canvas.style.height = size + 'px';
        }

        var ctx = canvas.getContext('2d');
        if (!ctx) return;

        var iconColor = color || '#ffffff';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, size, size);

        if (theme === 'dark') {
            ctx.fillStyle = iconColor;
            ctx.beginPath();
            ctx.arc(10, 10, 5.8, 0, Math.PI * 2);
            ctx.fill();

            ctx.globalCompositeOperation = 'destination-out';
            ctx.beginPath();
            ctx.arc(12.5, 8.2, 5.8, 0, Math.PI * 2);
            ctx.fill();
            ctx.globalCompositeOperation = 'source-over';
            return;
        }

        ctx.strokeStyle = iconColor;
        ctx.lineWidth = 1.7;
        ctx.lineCap = 'round';

        ctx.beginPath();
        ctx.arc(10, 10, 4.1, 0, Math.PI * 2);
        ctx.stroke();

        var rays = [
            [10, 1.6, 10, 4],
            [10, 16, 10, 18.4],
            [1.6, 10, 4, 10],
            [16, 10, 18.4, 10],
            [3.6, 3.6, 5.4, 5.4],
            [14.6, 14.6, 16.4, 16.4],
            [3.6, 16.4, 5.4, 14.6],
            [14.6, 5.4, 16.4, 3.6]
        ];

        rays.forEach(function (ray) {
            ctx.beginPath();
            ctx.moveTo(ray[0], ray[1]);
            ctx.lineTo(ray[2], ray[3]);
            ctx.stroke();
        });
    }

    /** Redraw the toggle so its icon and label match the active theme. */
    function updateThemeToggleUI(theme) {
        var btn = document.getElementById('themeToggle');
        if (!btn) return;
        var label = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
        btn.setAttribute('aria-label', label);
        btn.setAttribute('title', label);
        var canvas = btn.querySelector('.theme-icon');
        drawThemeIcon(canvas, theme, getComputedStyle(btn).color || '#ffffff');
    }

    /** Wire the toggle button and keep its icon correct across resizes. */
    function initThemeToggle() {
        var btn = document.getElementById('themeToggle');
        if (!btn) return;

        var theme = getTheme();
        applyTheme(theme);
        updateThemeToggleUI(theme);

        btn.addEventListener('click', function () {
            var current = getTheme();
            var next = current === 'dark' ? 'light' : 'dark';
            setTheme(next);
            updateThemeToggleUI(next);
        });

        ['mouseenter', 'mouseleave', 'focus', 'blur'].forEach(function (eventName) {
            btn.addEventListener(eventName, function () {
                updateThemeToggleUI(getTheme());
            });
        });

        var resizeTimer;
        window.addEventListener('resize', function () {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function () {
                updateThemeToggleUI(getTheme());
            }, 100);
        });
    }

    applyTheme(getTheme());
    initThemeToggle();
})();
