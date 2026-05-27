from magicmatch.signatures import Candidate, Signature


def test_signature_fields():
    sig = Signature(
        name="PNG image",
        mime_type="image/png",
        magic=b"\x89PNG\r\n\x1a\n",
        offset=0,
        extensions=[".png"],
        mode="binary",
    )
    assert sig.name == "PNG image"
    assert sig.mime_type == "image/png"
    assert sig.magic == b"\x89PNG\r\n\x1a\n"
    assert sig.offset == 0
    assert sig.extensions == [".png"]
    assert sig.mode == "binary"


def test_signature_defaults():
    sig = Signature(name="Test", mime_type="application/octet-stream", magic=b"\x00\x01")
    assert sig.offset == 0
    assert sig.extensions == []
    assert sig.mode == "binary"


def test_candidate_fields():
    c = Candidate(
        confidence=100,
        name="PNG image",
        mime_type="image/png",
        extensions=[".png"],
        matched_bytes=b"\x89PNG\r\n\x1a\n",
        offset=0,
    )
    assert c.confidence == 100
    assert c.name == "PNG image"
    assert c.matched_bytes == b"\x89PNG\r\n\x1a\n"
