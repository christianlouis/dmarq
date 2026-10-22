"""Execute mail-source template expressions with the shipped Alpine CSP parser."""

import json
import subprocess
from html.parser import HTMLParser
from pathlib import Path


class _AlpineExpressions(HTMLParser):
    def __init__(self):
        super().__init__()
        self.expressions = []

    def handle_starttag(self, tag, attrs):
        self.expressions.extend(
            (name, value) for name, value in attrs if name in {"x-text", "x-show"}
        )


def test_import_diagnostics_and_empty_recovery_use_supported_csp_expressions():
    """Hidden x-show children must also evaluate safely before an import exists."""
    app_root = Path(__file__).parents[1]
    parser = _AlpineExpressions()
    parser.feed((app_root / "templates" / "mail_sources.html").read_text())
    diagnostics = [
        expression for expression in parser.expressions if "source.latest_import" in expression[1]
    ]
    empty_recovery = [
        expression for expression in parser.expressions if "entry.recovery_items" in expression[1]
    ]
    assert len(diagnostics) == 6
    assert len(empty_recovery) == 1

    runtime = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const Element = class {};
// Keep the real evaluator, while suppressing automatic DOM initialization.
const context = {
  window: { Element }, document: { createElement: () => ({}) },
  Element, ShadowRoot: class {}, HTMLIFrameElement: class {}, HTMLScriptElement: class {},
  MutationObserver: class {}, queueMicrotask: () => {},
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const Alpine = context.window.Alpine;
Alpine.setErrorHandler(error => { throw error; });
const expressions = JSON.parse(process.argv[2]);
const evaluate = (expression, scope) => {
  const value = Alpine.evaluate({ _x_dataStack: [scope] }, expression[1]);
  return expression[0] === 'x-show' ? Boolean(value) : value;
};
const fallback = [false, 'The latest import needs attention.', 0, 0, 0, false];
for (const source of [{}, { latest_import: null }, { latest_import: {} }]) {
  assert.deepStrictEqual(expressions.diagnostics.map(expr => evaluate(expr, { source })), fallback);
}
for (const category of ['parsing', 'connection', 'ok']) {
  const source = { latest_import: {
    diagnostic_category: category, diagnostic_summary: 'Import diagnostic',
    processed: 7, reports_found: 2, error_count: 1,
  } };
  assert.deepStrictEqual(
    expressions.diagnostics.map(expr => evaluate(expr, { source })),
    [category !== 'ok', 'Import diagnostic', 7, 2, 1, category === 'parsing'],
  );
}
for (const entry of [{}, { recovery_items: null }, { recovery_items: [] }]) {
  assert.strictEqual(evaluate(expressions.emptyRecovery[0], { entry }), true);
}
assert.strictEqual(evaluate(expressions.emptyRecovery[0], {
  entry: { recovery_items: [{ message_id: 'synthetic-message' }] },
}), false);
"""
    result = subprocess.run(
        [
            "node",
            "-e",
            runtime,
            str(app_root / "static" / "js" / "vendor" / "alpine.min.js"),
            json.dumps({"diagnostics": diagnostics, "emptyRecovery": empty_recovery}),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
