// jQuery sees `module` (nodeIntegration) and does not set window.$ by itself.
// It has to exist before bootstrap loads, so bootstrap triggers its modal events on it.
window.jQuery = window.$ = require('jquery');
