import collections
import datetime
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, call, patch

from test_panel_performance import load_backend


class AttackGeographyTest(unittest.TestCase):
    def setUp(self):
        self.public = types.SimpleNamespace(
            writeFile=Mock(side_effect=AssertionError("overview must not write configuration")),
            M=Mock(side_effect=AssertionError("overview must not query domain tables")),
        )
        self.backend = load_backend(self.public)
        self.backend.get_waf_drop_ip = Mock(return_value=[])
        self.today = datetime.date.today().isoformat()

    def report(self, ips, records=None, database_error=None, logs=None, missing_logs=False):
        records = records or {}

        def lookup(ip):
            record = records.get(ip)
            if isinstance(record, Exception):
                raise record
            return record

        self.reader = types.SimpleNamespace(get=Mock(side_effect=lookup), close=Mock())
        self.open_database = Mock(return_value=self.reader, side_effect=database_error)
        maxmind = types.SimpleNamespace(open_database=self.open_database)
        virtual_logs = "/www/wwwlogs/free_waf_log/"
        virtual_drop = "/www/server/free_waf/drop_ip.log"
        original_open, original_exists, original_listdir = open, os.path.exists, os.listdir
        opened_modes = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log_root = root / "logs"
            if not missing_logs:
                log_root.mkdir()
            if logs is None:
                logs = {"example_" + self.today + ".log": ips}
            for filename, file_ips in logs.items():
                rows = [[self.today + " 12:00:00", ip, "GET", "/blocked", "test", "args"]
                        for ip in file_ips]
                (log_root / filename).write_text(
                    "\n".join(json.dumps(row) for row in rows), encoding="utf-8"
                )
            before = {path.name: path.read_bytes() for path in log_root.glob("*")}

            def redirect(path):
                value = str(path).replace("\\", "/")
                if value.startswith(virtual_logs):
                    return str(log_root / value[len(virtual_logs):])
                if value == virtual_drop:
                    return str(root / "drop_ip.log")
                return path

            def read_only_open(path, mode="r", *args, **kwargs):
                opened_modes.append(mode)
                if any(flag in mode for flag in "wax+"):
                    raise AssertionError("overview opened a file for writing")
                return original_open(redirect(path), mode, *args, **kwargs)

            with patch.dict(sys.modules, {"maxminddb": maxmind}), \
                 patch("builtins.open", side_effect=read_only_open), \
                 patch.object(os.path, "exists", side_effect=lambda path: original_exists(redirect(path))), \
                 patch.object(os, "listdir", side_effect=lambda path: original_listdir(redirect(path))):
                result = self.backend.get_overview_report(None)

            self.assertEqual(before, {path.name: path.read_bytes() for path in log_root.glob("*")})
            self.assertFalse((root / "drop_ip.log").exists())
        self.assertTrue(all(not any(flag in mode for flag in "wax+") for mode in opened_modes))
        self.public.writeFile.assert_not_called()
        self.public.M.assert_not_called()
        self.backend.get_waf_drop_ip.assert_called_once_with(None)
        self.open_database.assert_called_once_with("/www/server/panel/config/GeoLite2-City.mmdb")
        if database_error is None:
            self.reader.close.assert_called_once_with()
        else:
            self.reader.get.assert_not_called()
            self.reader.close.assert_not_called()
        self.assertIsInstance(result.get("attack_geography"), dict, "overview must expose attack_geography")
        geography = result["attack_geography"]
        self.assertEqual(set(geography), {
            "countries", "total", "located", "unlocated", "database_available", "period_days"
        })
        self.assertEqual(geography["total"], result["summary"]["total_protection"])
        self.assertEqual(geography["located"] + geography["unlocated"], geography["total"])
        self.assertEqual(sum(row["count"] for row in geography["countries"]), geography["located"])
        self.assertEqual(geography["period_days"], 7)
        self.assertIs(geography["database_available"], database_error is None)
        for row in geography["countries"]:
            self.assertEqual(set(row), {"code", "name", "count"})
            self.assertRegex(row["code"], r"^[A-Z]{2}$")
        return result

    def test_panel_custom_record_preserves_legacy_overview_fields(self):
        result = self.report(["192.0.2.1"] * 3, {
            "192.0.2.1": {"country": {
                "country": "United States", "en_short_code": "US", "city": "Seattle",
                "province": "Washington", "longitude": -122.33, "latitude": 47.61,
            }},
        })
        self.assertEqual(result["attack_geography"]["countries"], [
            {"code": "US", "name": "United States", "count": 3},
        ])
        self.assertEqual(result["attack_regions"], [
            {"region": "United States Washington Seattle", "count": 3},
        ])
        self.assertEqual(result["summary"]["total_protection"], 3)
        self.assertEqual(result["top_sites"], [{"site": "example", "count": 3}])
        self.assertEqual(result["today_top_sites"], result["top_sites"])
        self.assertEqual(result["top_rules"], [{"rule_type": "args", "count": 3}])
        self.assertEqual(len(result["dynamics"]), 3)
        self.assertEqual(sum(row["count"] for row in result["trend"]), 3)
        self.assertEqual(result["blocked_ips"], [])
        self.assertEqual(result["active_bans"], 0)
        self.reader.get.assert_called_once_with("192.0.2.1")

    def test_standard_maxmind_record_uses_country_code_and_english_name(self):
        result = self.report(["192.0.2.1", "192.0.2.2", "192.0.2.3"], {
            "192.0.2.1": {
                "country": {"iso_code": "US", "names": {"zh-CN": "\u7f8e\u56fd", "en": "United States"}},
                "city": {"names": {"en": "Seattle"}},
                "subdivisions": [{"iso_code": "WA", "names": {"en": "Washington"}}],
                "location": {"longitude": -122.33, "latitude": 47.61},
            },
            "192.0.2.2": {"country": {"iso_code": "CN", "names": {"zh-CN": "\u4e2d\u56fd"}}},
            "192.0.2.3": {"country": {"iso_code": "JP"}},
        })
        self.assertEqual({row["code"]: row for row in result["attack_geography"]["countries"]}, {
            "US": {"code": "US", "name": "United States", "count": 1},
            "CN": {"code": "CN", "name": "\u4e2d\u56fd", "count": 1},
            "JP": {"code": "JP", "name": "JP", "count": 1},
        })
        self.assertEqual(result["attack_regions"], [{"region": "\u672a\u77e5\u6765\u6e90", "count": 3}])

    def test_multiple_cities_and_record_formats_aggregate_by_country(self):
        result = self.report(["192.0.2.1"] * 4 + ["192.0.2.2"] * 2 + ["192.0.2.3"], {
            "192.0.2.1": {"country": {"country": "United States", "en_short_code": "US", "city": "Seattle"}},
            "192.0.2.2": {"country": {"country": "United States", "en_short_code": "US", "city": "Boston"}},
            "192.0.2.3": {"country": {"iso_code": "US", "names": {"en": "United States"}}},
        })
        self.assertEqual(result["attack_geography"]["countries"], [
            {"code": "US", "name": "United States", "count": 7},
        ])
        self.assertEqual(len(result["attack_regions"]), 3)
        self.assertEqual(collections.Counter(item.args[0] for item in self.reader.get.call_args_list), {
            "192.0.2.1": 1, "192.0.2.2": 1, "192.0.2.3": 1,
        })

    def test_missing_database_counts_every_attack_as_unlocated(self):
        result = self.report(["192.0.2.1"] * 2 + ["192.0.2.2"], database_error=OSError("missing database"))
        self.assertEqual(result["attack_geography"], {
            "countries": [], "total": 3, "located": 0, "unlocated": 3,
            "database_available": False, "period_days": 7,
        })
        self.assertEqual(result["attack_regions"], [{"region": "\u672a\u77e5\u6765\u6e90", "count": 3}])

    def test_unknown_lookup_reconciles_with_located_attacks(self):
        result = self.report(["192.0.2.1"] * 3 + ["192.0.2.2"] * 2, {
            "192.0.2.1": {"country": {"country": "Canada", "en_short_code": "CA"}},
            "192.0.2.2": None,
        })
        self.assertEqual(result["attack_geography"]["located"], 3)
        self.assertEqual(result["attack_geography"]["unlocated"], 2)
        self.assertEqual(self.reader.get.call_count, 2)

    def test_country_name_without_code_is_not_inferred_from_free_text(self):
        result = self.report(["192.0.2.1", "192.0.2.2"], {
            "192.0.2.1": {"country": {"country": "United States", "city": "Seattle"}},
            "192.0.2.2": {
                "country": {"names": {"en": "China", "zh-CN": "\u4e2d\u56fd"}},
                "registered_country": {"iso_code": "CN"},
                "city": {"iso_code": "CN"},
            },
        })
        self.assertEqual(result["attack_geography"]["countries"], [])
        self.assertEqual(result["attack_geography"]["unlocated"], 2)
        self.assertIn({"region": "United States Seattle", "count": 1}, result["attack_regions"])

    def test_includes_all_countries_not_only_legacy_top_eight(self):
        countries = [
            ("US", "United States"), ("CN", "China"), ("DE", "Germany"), ("FR", "France"),
            ("JP", "Japan"), ("GB", "United Kingdom"), ("CA", "Canada"), ("AU", "Australia"),
            ("IN", "India"), ("BR", "Brazil"),
        ]
        ips, records, expected = [], {}, {}
        for index, (code, name) in enumerate(countries, 1):
            ip = "192.0.2.%d" % index
            ips.extend([ip] * index)
            records[ip] = {"country": {"country": name, "en_short_code": code}}
            expected[code] = {"code": code, "name": name, "count": index}
        result = self.report(ips, records)
        self.assertEqual({row["code"]: row for row in result["attack_geography"]["countries"]}, expected)
        self.assertEqual(result["attack_geography"]["total"], 55)
        self.assertEqual(result["attack_geography"]["unlocated"], 0)
        self.assertEqual(len(result["attack_regions"]), 8)
        self.assertEqual([row["count"] for row in result["attack_geography"]["countries"]], list(range(10, 0, -1)))
        self.assertEqual(self.reader.get.call_count, 10)

    def test_country_codes_are_normalized_to_uppercase(self):
        result = self.report(["192.0.2.1", "192.0.2.2"], {
            "192.0.2.1": {"country": {"country": "United States", "en_short_code": "us"}},
            "192.0.2.2": {"country": {"iso_code": "cA", "names": {"en": "Canada"}}},
        })
        self.assertEqual({row["code"] for row in result["attack_geography"]["countries"]}, {"US", "CA"})

    def test_unassigned_and_pseudo_country_codes_remain_unlocated(self):
        invalid_codes = ["ZZ", "XX", "EU", "AP", "A1", "AA", "UK", "XK", "AN", "SU", "zz", "ap"]
        records = {}
        for code in invalid_codes:
            for field in ["en_short_code", "iso_code"]:
                records["192.0.2.%d" % (len(records) + 1)] = {"country": {
                    field: code, "country": "United States", "names": {"en": "United States"},
                }}
        records["192.0.2.250"] = {"country": {"en_short_code": "us", "country": "United States"}}
        result = self.report(list(records) * 2 + ["192.0.2.250"], records)
        self.assertEqual(result["attack_geography"]["countries"], [
            {"code": "US", "name": "United States", "count": 3},
        ])
        self.assertEqual(result["attack_geography"]["located"], 3)
        self.assertEqual(result["attack_geography"]["unlocated"], len(invalid_codes) * 4)
        self.assertEqual(result["attack_regions"], [
            {"region": "United States", "count": len(invalid_codes) * 4 + 3},
        ])
        self.assertEqual(self.reader.get.call_count, len(records))

    def test_all_249_assigned_country_codes_are_supported(self):
        assigned_codes = (
            "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ "
            "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET "
            "FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU "
            "ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY "
            "MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ "
            "OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ "
            "TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"
        ).split()
        self.assertEqual(len(set(assigned_codes)), 249)
        records = {
            "192.0.2.%d" % index: {"country": {"iso_code": code.lower()}}
            for index, code in enumerate(assigned_codes, 1)
        }
        result = self.report(list(records), records)
        self.assertEqual({row["code"] for row in result["attack_geography"]["countries"]}, set(assigned_codes))
        self.assertEqual(result["attack_geography"]["located"], 249)
        self.assertEqual(result["attack_geography"]["unlocated"], 0)
        self.assertEqual(self.reader.get.call_count, 249)

    def test_malformed_codes_cannot_become_world_geometry_keys(self):
        invalid_codes = [None, "", "USA", "U1", "U", "US\n", "<US>", "\uff35\uff33", "\u00e9s", 12, ["US"], {"code": "US"}]
        records = {
            "192.0.2.%d" % index: {"country": {"country": "United States", "en_short_code": code}}
            for index, code in enumerate(invalid_codes, 1)
        }
        result = self.report(list(records), records)
        self.assertEqual(result["attack_geography"]["countries"], [])
        self.assertEqual(result["attack_geography"]["unlocated"], len(invalid_codes))

    def test_lookup_errors_are_cached_and_database_is_closed(self):
        result = self.report(["192.0.2.1"] * 4 + ["192.0.2.2"], {
            "192.0.2.1": ValueError("invalid address"),
            "192.0.2.2": {"country": {"iso_code": "GB", "names": {"en": "United Kingdom"}}},
        })
        self.assertEqual(result["attack_geography"]["located"], 1)
        self.assertEqual(result["attack_geography"]["unlocated"], 4)
        self.assertEqual(self.reader.get.call_args_list, [call("192.0.2.1"), call("192.0.2.2")])

    def test_malformed_records_are_unlocated_without_losing_counts(self):
        records = {
            "192.0.2.1": {}, "192.0.2.2": {"country": None},
            "192.0.2.3": {"country": "US"}, "192.0.2.4": {"country": ["US"]},
            "192.0.2.5": ["country"],
        }
        result = self.report(list(records) * 2, records)
        self.assertEqual(result["attack_geography"]["countries"], [])
        self.assertEqual(result["attack_geography"]["unlocated"], 10)
        self.assertEqual(self.reader.get.call_count, 5)

    def test_seven_day_counts_and_ip_cache_span_sites_and_dates(self):
        dates = self.backend._free_waf_main__date_list(7)
        excluded_date = (datetime.date.today() - datetime.timedelta(days=7)).isoformat()
        logs = {
            "a_" + dates[0] + ".log": ["192.0.2.1"] * 2,
            "b_" + dates[-1] + ".log": ["192.0.2.1", "192.0.2.2"],
            "a_" + excluded_date + ".log": ["192.0.2.3"] * 5,
            "unrelated.log": ["192.0.2.3"],
        }
        result = self.report([], {
            "192.0.2.1": {"country": {"iso_code": "US", "names": {"en": "United States"}}},
        }, logs=logs)
        self.assertEqual(result["attack_geography"]["total"], 4)
        self.assertEqual(result["attack_geography"]["located"], 3)
        self.assertEqual(result["attack_geography"]["unlocated"], 1)
        self.assertEqual({item.args[0] for item in self.reader.get.call_args_list}, {"192.0.2.1", "192.0.2.2"})
        self.assertEqual(self.reader.get.call_count, 2)

    def test_empty_logs_report_zero_counts_with_available_database(self):
        result = self.report([])
        self.assertEqual(result["attack_geography"]["countries"], [])
        self.assertEqual(result["attack_geography"]["total"], 0)
        self.reader.get.assert_not_called()

    def test_missing_log_directory_reports_zero_counts(self):
        result = self.report([], logs={}, missing_logs=True)
        self.assertEqual(result["attack_geography"]["countries"], [])
        self.assertEqual(result["attack_geography"]["total"], 0)
        self.reader.get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
