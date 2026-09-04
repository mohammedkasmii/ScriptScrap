"""Stable page/frame identity. No browser: fakes stand in for Playwright objects."""

from __future__ import annotations

from scriptscrap.sensors import PageRegistry


class FakeFrame:
    def __init__(self, name="", url="", parent=None, page=None):
        self.name = name
        self.url = url
        self.parent_frame = parent
        self.page = page


class FakePage:
    def __init__(self, url=""):
        self.url = url


def test_ids_are_allocated_in_observation_order():
    r = PageRegistry()
    p1, p2 = FakePage(), FakePage()
    assert r.page_id(p1) == "p1"
    assert r.page_id(p2) == "p2"
    assert r.page_id(p1) == "p1", "id must be stable for the same object"


def test_frames_with_identical_names_get_distinct_ids():
    """The M1 derived label collapsed these into one identity."""
    r = PageRegistry()
    page = FakePage()
    main = FakeFrame(name="", url="http://h/", page=page)
    a = FakeFrame(name="child", url="http://h/x", parent=main, page=page)
    b = FakeFrame(name="child", url="http://h/x", parent=main, page=page)
    assert r.frame_id(a) != r.frame_id(b)


def test_frame_id_survives_navigation():
    r = PageRegistry()
    page = FakePage()
    frame = FakeFrame(name="", url="http://h/one", page=page)
    first = r.frame_id(frame)
    frame.url = "http://h/two"
    assert r.frame_id(frame) == first


def test_frame_tree_relationships_are_recorded():
    r = PageRegistry()
    page = FakePage()
    main = FakeFrame(url="http://h/", page=page)
    child = FakeFrame(url="http://h/outer", parent=main, page=page)
    grandchild = FakeFrame(url="http://h/inner", parent=child, page=page)

    main_id, child_id, grand_id = r.frame_id(main), r.frame_id(child), r.frame_id(grandchild)
    assert r.parent_frame_id(main_id) is None
    assert r.parent_frame_id(child_id) == main_id
    assert r.parent_frame_id(grand_id) == child_id
    assert r.frame_page_id(grand_id) == r.page_id(page)


def test_forgetting_releases_ids_without_reusing_them():
    r = PageRegistry()
    page, other = FakePage(), FakePage()
    assert r.page_id(page) == "p1"
    assert r.forget_page(page) == "p1"
    assert r.page_id(other) == "p2", "ids must not be recycled"


def test_broken_playwright_objects_do_not_raise():
    class Exploding:
        @property
        def parent_frame(self):
            raise RuntimeError("detached")

        @property
        def page(self):
            raise RuntimeError("detached")

    r = PageRegistry()
    fid = r.frame_id(Exploding())
    assert fid == "f1"
    assert r.parent_frame_id(fid) is None


def test_request_frame_failure_yields_none():
    class ServiceWorkerRequest:
        @property
        def frame(self):
            raise RuntimeError("service worker request has no frame")

    assert PageRegistry().frame_of_request(ServiceWorkerRequest()) is None
