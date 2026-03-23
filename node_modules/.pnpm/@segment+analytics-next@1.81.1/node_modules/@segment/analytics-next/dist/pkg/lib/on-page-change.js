/**
 * Register event listener on document that fires when:
 * * tab change or tab close (in mobile or desktop)
 * * click back / forward button
 * * click any link or perform any other navigation action
 * * soft refresh / hard refresh
 *
 * adapted from https://stackoverflow.com/questions/3239834/window-onbeforeunload-not-working-on-the-ipad/52864508#52864508,
 */
export var onPageChange = function (cb) {
    var unloaded = false; // prevents double firing if both are supported
    window.addEventListener('pagehide', function () {
        if (unloaded)
            return;
        unloaded = true;
        cb(unloaded);
    });
    // using document instead of window because of bug affecting browsers before safari 14 (detail in footnotes https://caniuse.com/?search=visibilitychange)
    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState == 'hidden') {
            if (unloaded)
                return;
            unloaded = true;
        }
        else {
            unloaded = false;
        }
        cb(unloaded);
    });
};
//# sourceMappingURL=on-page-change.js.map