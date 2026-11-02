// jquery_dom_guard.py's main motivating shape (see its module docstring,
// found against WebGoat's own hand-written static/js/goatApp/view/
// MenuView.js): a plain client-side JS function whose only parameter is
// literally named "id" (an HTML element id, not a database row id), and
// whose body calls jQuery's own `.find()` DOM-selector method — which
// textually collides with idor.py's LOOKUP_SINK_RE (`find(` exists there
// for `Model.find(id)`-style ORM calls). This file deliberately contains
// none of the HTTP-request-handling vocabulary jquery_dom_guard.py scans
// for (no "request" object property access, no server-framework import,
// no route-registration call anywhere), so it's unambiguously client-
// side — exactly the condition jquery_dom_guard.py requires before
// suppressing idor.py's bare-parameter-name-fallback finding. (Careful:
// don't spell any of those trigger shapes out literally in this prose,
// or this fixture would self-match the very signal it's demonstrating
// the ABSENCE of — the same trap loot.py's and vendor_guard.py's own
// docstrings fell into earlier in this project.)

var MenuView = {
  accordionMenu: function(id) {  // safe: Missing Authorization / IDOR
    // no ownership/authorization concept here at all — this toggles a
    // CSS accordion panel by its DOM element id, not a database record.
    this.$el.find('#' + this.openMenu).slideUp(200);
    this.$el.find('#' + id).slideDown(300);
    this.openMenu = id;
  },
};
