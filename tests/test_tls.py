"""Every download trusts only the bundled certifi list, never the operating system's store (Python reads the trusted
part of the Windows store but not Windows' list of blocked authorities)."""

import ssl

import certifi
import pytest

from sentinel_vision import updater


def test_only_the_bundled_certificate_list_is_trusted(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("the system certificate store must not be loaded")

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", boom)
    ctx = updater._ssl_context()
    expected = open(certifi.where(), encoding="ascii").read().count("BEGIN CERTIFICATE")
    assert len(ctx.get_ca_certs()) == expected
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_compromised_emsign_roots_are_not_trusted():
    """certifi 2026.10.23 removed the emSign roots tied to the October 2026 eMudhra key compromise."""
    names = {dict(x[0] for x in c["subject"]).get("commonName", "") for c in updater._ssl_context().get_ca_certs()}
    assert "emSign Root CA - C1" not in names
    assert "emSign ECC Root CA - C3" not in names


def test_no_download_without_the_certificate_list(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_certifi(name, *a, **k):
        if name == "certifi":
            raise ImportError("certifi missing")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_certifi)
    with pytest.raises(ImportError):
        updater._ssl_context()  # fails closed instead of falling back to the system store
