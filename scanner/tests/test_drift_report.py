"""Tests for the state-tier Terraform drift report."""

import json

import pytest

from scanner.drift_report import (
    _index_by_address,
    _index_values,
    _interpret,
    _is_sensitive_marker,
    _values_set_of_interest,
    build_report,
    diff_attributes,
    main,
)


RESOURCE = "azurerm_storage_account.example"


def plan_resource(address=RESOURCE, values=None):
    return {"address": address, "values": values or {}}


def terraform_plan(resources):
    return {"planned_values": {"root_module": {"resources": resources}}}


def state_converter_plan(resources):
    return {
        "resource_changes": [
            {"address": address, "change": {"after": values}}
            for address, values in resources.items()
        ]
    }


@pytest.mark.parametrize(
    ("plan", "expected"),
    [
        (
            terraform_plan([plan_resource(values={"enabled": True})]),
            {RESOURCE: plan_resource(values={"enabled": True})},
        ),
        (
            {
                "planned_values": {
                    "root_module": {
                        "resources": [],
                        "child_modules": [
                            {"resources": [plan_resource(values={"enabled": True})]}
                        ],
                    }
                }
            },
            {RESOURCE: plan_resource(values={"enabled": True})},
        ),
        (
            state_converter_plan({RESOURCE: {"enabled": True}}),
            {RESOURCE: plan_resource(values={"enabled": True})},
        ),
        ({"planned_values": {}, "resource_changes": ["bad", {}]}, {}),
    ],
)
def test_index_by_address(plan, expected):
    assert _index_by_address(plan) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("<sensitive>", True), ("plain", False), (None, False), (1, False)],
)
def test_is_sensitive_marker(value, expected):
    assert _is_sensitive_marker(value) is expected


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"enabled": True, "uninteresting": "ignored"}, {"enabled": True}),
        ({}, {}),
        (None, {}),
    ],
)
def test_values_set_of_interest(values, expected):
    assert _values_set_of_interest(values) == expected


@pytest.mark.parametrize(
    ("source", "state", "keys", "expected"),
    [
        ({"enabled": True}, {"enabled": False}, ["enabled"], [{"attribute": "enabled", "source": True, "state": False, "note": ""}]),
        ({"password": "<sensitive>"}, {"password": "value"}, ["password"], [{"attribute": "password", "source": "<sensitive>", "state": "value", "note": "source deferred to state (likely ignore_changes)"}]),
        ({"password": "value"}, {"password": "<sensitive>"}, ["password"], [{"attribute": "password", "source": "value", "state": "<sensitive>", "note": "source had value, state marked sensitive"}]),
        ({"password": "<sensitive>"}, {"password": "<sensitive>"}, ["password"], []),
        ({}, {}, ["missing"], []),
    ],
)
def test_diff_attributes(source, state, keys, expected):
    assert diff_attributes(source, state, keys) == expected


@pytest.mark.parametrize(
    ("src", "state", "expected"),
    [
        (
            terraform_plan([plan_resource(values={"enable_https_traffic_only": True})]),
            terraform_plan([plan_resource(values={"enable_https_traffic_only": False})]),
            {"attribute_drift": 1, "sensitive": 0, "state_only": 0, "source_only": 0},
        ),
        (
            terraform_plan([plan_resource(values={"enable_https_traffic_only": True})]),
            state_converter_plan({RESOURCE: {"enable_https_traffic_only": False}}),
            {"attribute_drift": 1, "sensitive": 0, "state_only": 0, "source_only": 0},
        ),
        (
            terraform_plan([plan_resource(values={"enable_https_traffic_only": "<sensitive>"})]),
            terraform_plan([plan_resource(values={"enable_https_traffic_only": True})]),
            {"attribute_drift": 1, "sensitive": 1, "state_only": 0, "source_only": 0},
        ),
        (
            terraform_plan([plan_resource("azurerm_storage_account.source")]),
            terraform_plan([plan_resource("azurerm_storage_account.state")]),
            {"attribute_drift": 0, "sensitive": 0, "state_only": 1, "source_only": 1},
        ),
        ({}, terraform_plan([]), {"attribute_drift": 0, "sensitive": 0, "state_only": 0, "source_only": 0}),
    ],
)
def test_build_report_shapes_and_categories(src, state, expected):
    report = build_report(src, state)
    assert len(report["attribute_drift"]) == expected["attribute_drift"]
    assert len(report["sensitive_findings"]) == expected["sensitive"]
    assert len(report["address_in_state_only"]) == expected["state_only"]
    assert len(report["address_in_source_only"]) == expected["source_only"]
    assert report["summary"]["sensitive_attribute_findings"] == expected["sensitive"]


def test_build_report_surfaces_sensitive_attribute():
    report = build_report(
        terraform_plan([plan_resource(values={"enable_https_traffic_only": "<sensitive>"})]),
        terraform_plan([plan_resource(values={"enable_https_traffic_only": True})]),
    )
    assert report["sensitive_findings"] == [
        {
            "address": RESOURCE,
            "attribute": "enable_https_traffic_only",
            "state_value_type": "bool",
            "note": "Source plan markers <sensitive>; state has concrete value",
        }
    ]


@pytest.mark.parametrize(
    ("resource", "expected"),
    [({"values": {"enabled": 0}}, {"enabled": 0}), ({"values": None}, {}) , ({}, {})],
)
def test_index_values(resource, expected):
    assert _index_values(resource) == expected


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        ((0, 0, 0), "no drift; source plan matches state"),
        ((0, 0, 1), "drift: ignore_changes is masking live changes; review attribute_drift"),
        ((1, 0, 0), "drift: resources exist in state but not in source; they will be destroyed on next apply"),
        ((0, 1, 0), "drift: resources in source but not in state; they will be created on next apply"),
        ((0, 0, 2), "drift: ignore_changes is masking live changes; review attribute_drift"),
    ],
)
def test_interpret(counts, expected):
    assert _interpret(*counts) == expected


def test_main_writes_report_and_parses_argv(tmp_path, monkeypatch, capsys):
    src_path = tmp_path / "source.json"
    state_path = tmp_path / "state.json"
    out_path = tmp_path / "report.json"
    src_path.write_text(json.dumps({}), encoding="utf-8")
    state_path.write_text(json.dumps({}), encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["drift_report", str(src_path), str(state_path), str(out_path)])

    assert main() == 0
    assert json.loads(out_path.read_text(encoding="utf-8"))["summary"]["addresses_with_attribute_drift"] == 0
    assert str(out_path) in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["drift_report"], ["drift_report", "a", "b"]])
def test_main_argparse_failure(argv, monkeypatch):
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code != 0
