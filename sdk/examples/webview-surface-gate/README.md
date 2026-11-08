# WebView surface fixture

This local-only page is embedded as immutable resources by the desktop acceptance build.
Its readiness receipt requires a real module import; the native pixel gate requires its
separate CSS file to load. It uses no network, host secrets or installation state.
A small same-origin POST probe must fail with a browser `connect-src` policy event;
receiving a host 404 does not satisfy that check. No large request body is tested.

Run the existing WebView native/offscreen acceptance runners against a copied candidate.
The offscreen run measures visual and instance preservation only, not OS input or IME.
This fixture is not an installable plugin and does not prove production factory/SDK wiring.
