import pytest

from porthunter.targets import TargetError, contains, count_addresses, ip_sort_key, parse_targets


def test_parse_targets_splits_on_whitespace_and_semicolons():
    assert parse_targets("10.10.0.0/17  pc1.local;10.0.0.1-5\n10.0.0.1,5,9") == [
        "10.10.0.0/17", "pc1.local", "10.0.0.1-5", "10.0.0.1,5,9"]


@pytest.mark.parametrize("bad", ["", "   ", "-oN x", "10.0.0.1 --script=/tmp/x", "10.0.0.1|calc", "a&b"])
def test_parse_targets_rejects_options_and_garbage(bad):
    with pytest.raises(TargetError):
        parse_targets(bad)


def test_count_addresses():
    assert count_addresses(["10.10.0.0/17"]) == 32768
    assert count_addresses(["10.0.0.1-10"]) == 10
    assert count_addresses(["10.0.0-1.*"]) == 512
    assert count_addresses(["10.0.0.1,5,9", "pc.local"]) == 4
    assert count_addresses(["host.local/24"]) is None


def test_contains():
    assert contains(["10.10.0.0/17"], "10.10.100.3")
    assert not contains(["10.10.0.0/17"], "10.10.200.3")
    assert contains(["10.0.0-3.1-254"], "10.0.2.50")
    assert not contains(["10.0.0-3.1-254"], "10.0.2.255")
    assert contains(["10.0.0.1,5,9"], "10.0.0.5")
    assert not contains(["pc.local"], "10.0.0.5")


def test_ip_sort_key_orders_numerically():
    ips = ["10.0.0.10", None, "10.0.0.9", "10.0.0.100"]
    assert sorted(ips, key=ip_sort_key) == ["10.0.0.9", "10.0.0.10", "10.0.0.100", None]
