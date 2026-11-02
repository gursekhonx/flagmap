// jquery_dom_guard.py's secondary motivating shape (see its module
// docstring): the real jQuery UI source has an Autocomplete widget whose
// `source` option callback is conventionally named `function(request,
// response)` — a plain local-variable naming convention with nothing to
// do with HTTP. That coincidental match used to make
// jquery_dom_guard.py's whole-file "is this server code" scan treat the
// ENTIRE file as server-side, which blocked it from ever reaching the
// real false positive (the accordion-style DOM-id case, same shape as
// clientside_dom_cases.js) elsewhere in the same file. Fixed by skipping
// that scan entirely — straight to the per-function check — whenever
// vendor_guard.py's own is_vendor_file() already recognizes the file as
// vendored by filename convention; this file is named to match that
// convention (see vendor_guard.py's jQuery-plugin naming regex) so the
// regression suite exercises that exact bypass path, not just the
// plain client-side case clientside_dom_cases.js already covers.

var FakeAutocompleteWidget = {
  // The red herring: an unrelated local-variable naming convention that
  // used to make the whole file look server-side to a naive keyword scan.
  _source: function(request, response) {
    response(this._filter(request.term));
  },

  // The real false-positive shape: bare "id" parameter, jQuery .find().
  accordionMenu: function(id) {  // safe: Missing Authorization / IDOR
    this.$el.find('#' + this.openMenu).slideUp(200);
    this.$el.find('#' + id).slideDown(300);
    this.openMenu = id;
  },
};
