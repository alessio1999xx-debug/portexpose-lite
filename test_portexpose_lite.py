#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline tests for portexpose-lite. No Docker, no network, no iptables."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

import portexpose_lite as pe

SAMPLE = """\
services:
  db:
    image: postgres:16
    ports:
      - "5432:5432"
  redis:
    image: redis:7
    ports:
      - "6379:6379"
  web:
    image: nginx:alpine
    ports:
      - "127.0.0.1:8080:80"
  adminer:
    image: adminer
    ports:
      - "0.0.0.0:8081:8080"
"""

PRIVATE = """\
services:
  db-private:
    image: postgres:16
    ports:
      - "192.168.1.10:5432:5432"
  db-vpn:
    image: postgres:16
    ports:
      - "10.0.0.5:5432:5432"
  web-lan:
    image: nginx
    ports:
      - "192.168.1.10:8080:80"
  long-loop:
    image: redis
    ports:
      - target: 6379
        published: 6379
        host_ip: 127.0.0.1
        protocol: tcp
  range-pub:
    image: app
    ports:
      - "8000-8002:8000-8002"
  ipv6:
    image: nginx
    ports:
      - "[::]:8088:80"
  only-expose:
    image: nginx
    expose:
      - "80"
"""


class YamlAndPorts(unittest.TestCase):
    def test_sample_ratings(self):
        findings = pe.audit_compose(SAMPLE, "sample")
        by = {f["service"]: f for f in findings}
        self.assertEqual(set(by), {"db", "redis", "web", "adminer"})
        self.assertEqual(by["db"]["level"], "CRITICAL")
        self.assertEqual(by["db"]["host_port"], 5432)
        self.assertEqual(by["db"]["sensitive"], "PostgreSQL")
        self.assertIn("0.0.0.0", by["db"]["reason"])
        self.assertEqual(by["redis"]["level"], "CRITICAL")
        self.assertEqual(by["redis"]["sensitive"], "Redis")
        self.assertEqual(by["web"]["level"], "SAFE")
        self.assertEqual(by["web"]["host_ip"], "127.0.0.1")
        self.assertEqual(by["adminer"]["level"], "HIGH")
        self.assertEqual(by["adminer"]["host_port"], 8081)
        # generic HTTP ports are not treated as sensitive in lite
        self.assertIsNone(by["adminer"]["sensitive"])

    def test_private_loopback_range_ipv6_and_expose(self):
        findings = pe.audit_compose(PRIVATE, "private")
        names = [f["service"] for f in findings]
        self.assertNotIn("only-expose", names)
        by_svc = {}
        for f in findings:
            by_svc.setdefault(f["service"], []).append(f)
        self.assertEqual(by_svc["db-private"][0]["level"], "LOW")
        self.assertEqual(by_svc["db-vpn"][0]["level"], "LOW")
        self.assertEqual(by_svc["web-lan"][0]["level"], "LOW")
        self.assertEqual(by_svc["long-loop"][0]["level"], "SAFE")
        self.assertEqual(by_svc["long-loop"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(by_svc["long-loop"][0]["sensitive"], "Redis")
        range_ports = sorted(f["host_port"] for f in by_svc["range-pub"])
        self.assertEqual(range_ports, [8000, 8001, 8002])
        self.assertTrue(all(f["level"] == "HIGH" for f in by_svc["range-pub"]))
        self.assertEqual(by_svc["ipv6"][0]["level"], "HIGH")
        self.assertEqual(classify_ok := pe.classify_ip("::"), "wildcard")
        self.assertEqual(by_svc["ipv6"][0]["ip_kind"], "wildcard")

    def test_mysql_and_docker_api(self):
        text = """
services:
  mysql:
    ports: ["3306:3306"]
  dockerd:
    ports: ["2375:2375"]
"""
        findings = pe.audit_compose(text, "x")
        kinds = {f["service"]: f for f in findings}
        self.assertEqual(kinds["mysql"]["level"], "CRITICAL")
        self.assertEqual(kinds["mysql"]["sensitive"], "MySQL/MariaDB")
        self.assertEqual(kinds["dockerd"]["level"], "CRITICAL")
        self.assertEqual(kinds["dockerd"]["sensitive"], "Docker API")

    def test_comments_crlf_and_bom(self):
        text = "\ufeff# comment\r\nservices:\r\n  web:\r\n    ports:\r\n      - 127.0.0.1:8080:80  # only local\r\n"
        findings = pe.audit_compose(text, "crlf")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["level"], "SAFE")

    def test_container_only_port_is_public(self):
        text = "services:\n  web:\n    ports:\n      - 80\n"
        findings = pe.audit_compose(text, "rand")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["level"], "HIGH")
        self.assertTrue(findings[0]["random_host_port"])

    def test_protocol_suffix(self):
        text = 'services:\n  dns:\n    ports:\n      - "53:53/udp"\n'
        findings = pe.audit_compose(text, "udp")
        self.assertEqual(findings[0]["protocol"], "udp")
        self.assertEqual(findings[0]["host_port"], 53)
        self.assertEqual(findings[0]["level"], "HIGH")

    def test_v1_top_level_service(self):
        text = "web:\n  image: nginx\n  ports:\n    - 127.0.0.1:8080:80\n"
        findings = pe.audit_compose(text, "v1")
        self.assertEqual(findings[0]["service"], "web")
        self.assertEqual(findings[0]["level"], "SAFE")

    def test_bad_range_exits_parse_error_finding_or_raises(self):
        text = 'services:\n  web:\n    ports:\n      - "8000-8005:80"\n'
        findings = pe.audit_compose(text, "bad")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].get("parse_error"))
        self.assertEqual(findings[0]["level"], "HIGH")


class CliTests(unittest.TestCase):
    def test_demo_exit_1_and_wording(self):
        rc = pe.main(["--demo"])
        # demo Compose has public postgres/redis/adminer
        self.assertEqual(rc, 1)

    def test_file_and_missing(self):
        rc = pe.main(["-f", "/no/such/compose.yml"])
        self.assertEqual(rc, 2)

    def test_safe_file_exit_0(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "docker-compose.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('services:\n  web:\n    ports:\n      - "127.0.0.1:8080:80"\n')
            rc = pe.main(["-f", path])
            self.assertEqual(rc, 0)

    def test_version(self):
        self.assertTrue(pe.__version__)
        self.assertRaises(SystemExit, pe.main, ["--version"])

    def test_report_lists_all_four_sample_services(self):
        findings = pe.audit_compose(SAMPLE, "s")
        report = pe.format_report(findings)
        for name in ("db", "redis", "web", "adminer"):
            self.assertIn(name, report)
        self.assertIn("CRITICAL", report)
        self.assertIn("SAFE", report)
        self.assertIn("HIGH", report)


class ClassifyTests(unittest.TestCase):
    def test_ips(self):
        self.assertEqual(pe.classify_ip(""), "wildcard")
        self.assertEqual(pe.classify_ip("0.0.0.0"), "wildcard")
        self.assertEqual(pe.classify_ip("::"), "wildcard")
        self.assertEqual(pe.classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(pe.classify_ip("::1"), "loopback")
        self.assertEqual(pe.classify_ip("10.0.0.5"), "private")
        self.assertEqual(pe.classify_ip("192.168.1.10"), "private")
        self.assertEqual(pe.classify_ip("172.16.0.2"), "private")
        self.assertEqual(pe.classify_ip("8.8.8.8"), "public")


if __name__ == "__main__":
    unittest.main()
