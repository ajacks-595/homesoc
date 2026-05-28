"""render_md must sanitize HTML (XSS defense) while preserving markdown formatting.

These guard the root-cause fix for the stored-XSS surface: briefings, AI
explanations, exec summary and chat all flow through render_md and are then
injected into the DOM via innerHTML on the client.
"""
import app


def test_script_tag_stripped():
    out = app.render_md("Hello <script>alert(document.cookie)</script> world")
    assert "<script" not in out.lower()
    assert "alert(document.cookie)" not in out


def test_img_onerror_handler_stripped():
    out = app.render_md('text <img src=x onerror="alert(1)"> more')
    assert "onerror" not in out.lower()


def test_svg_onload_stripped():
    out = app.render_md('<svg onload="alert(1)"></svg>')
    assert "onload" not in out.lower()
    assert "<svg" not in out.lower()


def test_javascript_href_stripped():
    out = app.render_md("[click me](javascript:alert(1))")
    assert "javascript:" not in out.lower()


def test_data_uri_link_stripped():
    out = app.render_md("[x](data:text/html;base64,PHN2Zz4=)")
    assert "data:" not in out.lower()


def test_formatting_preserved():
    out = app.render_md("# Title\n\n**bold** and `code`\n\n- a\n- b")
    assert "<h1>" in out
    assert "<strong>bold</strong>" in out
    assert "<code>code</code>" in out
    assert "<li>a</li>" in out


def test_safe_external_link_preserved_with_rel():
    out = app.render_md("[VT](https://www.virustotal.com)")
    assert 'href="https://www.virustotal.com"' in out
    assert "noopener" in out


def test_table_rendered():
    out = app.render_md("| a | b |\n|---|---|\n| 1 | 2 |")
    assert "<table>" in out
    assert "<td>1</td>" in out


def test_fenced_code_preserved():
    out = app.render_md("```\nrm -rf /\n```")
    assert "<pre>" in out
    assert "<code>" in out
    assert "rm -rf /" in out


def test_none_and_empty_input_safe():
    assert app.render_md(None) == ""
    assert app.render_md("") == ""
