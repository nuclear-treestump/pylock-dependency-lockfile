import types
import pytest

@pytest.fixture(autouse=True)
def reset_mappingproxytype():
    """Ensure MappingProxyType is restored after each test."""
    yield
    from pydepguardnext.api.factories.mappingproxy_ovr import restore_mpt
    restore_mpt()

def test_basic_behavior():
    from pydepguardnext.api.factories.mappingproxy_ovr import ZebraProxy
    d = {"a": 1, "b": 2}
    zp = ZebraProxy(d)
    assert zp["a"] == 1
    assert list(zp.keys()) == ["a", "b"]
    assert list(zp.values()) == [1, 2]
    assert "b" in zp

def test_spoof_type_identity():
    from pydepguardnext.api.factories.mappingproxy_ovr import ZebraProxy, _ORIGINAL_MPT, GuardedMappingProxyFactory, ZebraMeta
    d = {"x": 99}
    zp = ZebraProxy(d)
    print("zp type: ", type(zp))
    print("MappingProxyType: ", types.MappingProxyType)
    print("ORIGINAL_MPT: ", _ORIGINAL_MPT)
    print("type of types MPT types: ", type(types.MappingProxyType))
    print("type of type _ORIGINAL_MPT: ", type(_ORIGINAL_MPT))
    print("type of type ZebraProxy: ", type(ZebraProxy))
    print("type of type GuardedMappingProxyFactory: ", type(GuardedMappingProxyFactory))
    print("type of type ZebraMeta: ", type(ZebraMeta))
    print("type of type zp: ", type(zp))
    print("zp class: ", zp.__class__)
    print(f"isinstance(zp, Mapping): {isinstance(zp, types.MappingProxyType)}")
    print(f"type(zp) is MappingProxyType: {type(zp) is types.MappingProxyType}")
    print(f"zp.__class__ is MappingProxyType: {zp.__class__ is types.MappingProxyType}")
    assert isinstance(zp, types.MappingProxyType)  # Spoofed

def test_repr_contains_mappingproxy():
    from pydepguardnext.api.factories.mappingproxy_ovr import ZebraProxy
    d = {"a": 123}
    zp = ZebraProxy(d)
    assert "mappingproxy" in repr(zp)

def test_protected_key_blocking(monkeypatch):
    import json, os, inspect
    from importlib import reload

    # Set hardened mode
    os.environ["PYDEP_MANIFEST"] = json.dumps({
        "locks": {
            "hardened": True
        }
    })

    # Prepare fake stack & module


    # Reload to re-initialize after monkeypatching
    from pydepguardnext.api.factories import mappingproxy_ovr
    reload(mappingproxy_ovr)
    from pydepguardnext import PyDepBullshitDetectionError

    class DummyFrame: pass
    dummy_frame = DummyFrame()

    monkeypatch.setattr(inspect, "stack", lambda: [(dummy_frame, None, None, None, None, None)])

    class DummyMod:
        __name__ = "malicious.actor"

    monkeypatch.setattr(inspect, "getmodule", lambda frame: DummyMod())

    VAULT = mappingproxy_ovr.VAULT
    VAULT_KEY = mappingproxy_ovr.VAULT_KEY

    # ✅ Now import only *after* reload and inside test context
    try:

        print(f"TEST CONTEXT: Attempting unsafe access to protected key {VAULT_KEY}...")
        _ = VAULT[VAULT_KEY]  # <-- This triggers the exception
        assert False, "Expected PyDepBullshitDetectionError but got value instead"
    except PyDepBullshitDetectionError as e:
        message = str(e)
        print("TEST CONTEXT: Caught expected exception:", message)
        assert "Runtime Disrespected" in message
        assert "__getitem__" in message
        assert "malicious.actor" in message

def test_allow_internal_access(monkeypatch):
    d = {"__pydepguard_uuid__": "sensitive", "safe": 10}
    from pydepguardnext.api.factories.mappingproxy_ovr import ZebraProxy
    zp = ZebraProxy(d)

    # Create a dummy frame
    class DummyFrame:
        pass

    dummy_frame = DummyFrame()

    # Fake stack returns a few dummy frames
    monkeypatch.setattr("inspect.stack", lambda: [(dummy_frame, None, None, None, None, None)])

    # Patch getmodule to simulate internal module access
    class DummyMod:
        __name__ = "pydepguardnext.api.fake"

    monkeypatch.setattr("inspect.getmodule", lambda frame: DummyMod())

    assert zp["__pydepguard_uuid__"] == "sensitive"
