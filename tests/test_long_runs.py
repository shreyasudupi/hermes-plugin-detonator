"""Slow first runs must not lose the report in chat apps with a short slash-command timeout
(Hermes Desktop gives a command ~30 s; building the sandbox image takes minutes)."""

import threading

from test_skeleton import SHA, FakeCtx, _load_plugin

EVAL = {"verdict": "DANGEROUS", "findings": [{"rule": "x", "severity": "critical", "title": "Read keys",
                                              "why": "w", "attack": ["T1552"], "atlas": []}]}


class Note:
    def __init__(self, text):
        self.ok, self.texts, self.done = True, [text], threading.Event()

    def edit(self, text):
        self.texts.append(text)
        self.done.set()
        return {"ok": True}


class PostingCtx(FakeCtx):
    def __init__(self, choice="run", can_post=True):
        super().__init__(choice)
        self.can_post, self.notes = can_post, []

    def post_message(self, text):
        note = Note(text)
        note.ok = self.can_post
        self.notes.append(note)
        return note


def _ready(ctx, monkeypatch, tmp_path):
    plugin = _load_plugin()
    gate = threading.Event()

    def slow_run(repo, sha, subdir, with_raw=False):
        gate.wait(5)  # still "building" when the slash command must answer
        return EVAL, "", tmp_path / "r.md"

    monkeypatch.setattr(plugin.commands, "run_detonation", slow_run)
    plugin.register(ctx)
    return ctx.commands["detonate"], gate


def test_desktop_gets_a_quick_answer_and_the_report_later(monkeypatch, tmp_path):
    ctx = PostingCtx()
    detonate, gate = _ready(ctx, monkeypatch, tmp_path)
    out = detonate(f"a/b {SHA}")
    assert out.startswith("Started")                    # answered before the run finished
    note = ctx.notes[0]
    assert "running the plugin in the sandbox" in note.texts[0]
    gate.set()
    assert note.done.wait(5)
    assert "DANGEROUS" in note.texts[-1] and "r.md" in note.texts[-1]


def test_terminal_chat_without_post_message_still_answers_directly(monkeypatch, tmp_path):
    ctx = PostingCtx(can_post=False)
    detonate, gate = _ready(ctx, monkeypatch, tmp_path)
    gate.set()
    assert "DANGEROUS" in detonate(f"a/b {SHA}")


def test_no_approval_means_nothing_posted_and_nothing_run(monkeypatch, tmp_path):
    ctx = PostingCtx(choice="cancel")
    detonate, _gate = _ready(ctx, monkeypatch, tmp_path)
    assert detonate(f"a/b {SHA}").startswith("Not run")
    assert ctx.notes == []
