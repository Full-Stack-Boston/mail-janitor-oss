"""Regression: Jinja tojson must not HTML-escape quotes inside <script>."""

from markupsafe import Markup

from mail_janitor.web.app import _tojson


def test_tojson_returns_markup_not_escaped():
    out = _tojson("MOVE TO READY2DELETE")
    assert isinstance(out, Markup)
    assert str(out) == '"MOVE TO READY2DELETE"'
    assert "&#34;" not in str(out)


def test_tojson_objects():
    out = _tojson({"q": "", "rule_id": ""})
    assert isinstance(out, Markup)
    assert '"q"' in str(out)
    assert "&#34;" not in str(out)
