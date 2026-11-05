// dangerouslySetInnerHTML coverage (patterns.py, v1.23.0). Found via the
// real CyberSci nationals-2024-25 "candidate_registry" defence challenge's
// frontend/src/pages/questions/Questions.js: a voter's submitted question
// text and a candidate's answer text are both rendered through this prop
// straight from an API response, with no sanitization anywhere — stored
// XSS. React does not escape this value itself; that is the entire point
// of the "dangerously" in the prop's name.

function Question({ question }) {
  // A hardcoded, static markup fragment — a common, legitimate use of this
  // prop (inserting a fixed decorative element) that carries no attacker
  // input at all. Must NOT fire.
  const divider = <hr dangerouslySetInnerHTML={{ __html: '<hr/>' }} />;  // safe: Cross-Site Scripting (XSS) — DOM-based

  // The real shape: a plain member-expression value traced back to data
  // that came from another user (a question someone else submitted).
  return (
    <span dangerouslySetInnerHTML={{ __html: question.question_text }} />  // ruleid: Cross-Site Scripting (XSS) — DOM-based
  );
}

function Answer({ answer }) {
  // Same sink reached via a backtick template literal with a real
  // interpolated expression — must still fire; a template literal is
  // never "just a static string" the way a single/double-quoted one is.
  return (
    <span dangerouslySetInnerHTML={{ __html: `${answer.answer_text}` }} />  // ruleid: Cross-Site Scripting (XSS) — DOM-based
  );
}
