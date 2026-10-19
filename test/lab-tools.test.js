"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { getSystemSummary, resolveDomain, scanSingleHost } = require("../lab-tools");

test("system summary reports real local OS metadata", () => {
  const result = getSystemSummary();
  assert.equal(result.ok, true);
  assert.equal(result.source, "live-local-operating-system");
  assert.ok(result.platform);
  assert.ok(result.cpuCores >= 1);
  assert.ok(Array.isArray(result.networkInterfaces));
  assert.ok(result.memory.totalBytes > 0);
});

test("DNS lookup rejects URL paths and malformed names before lookup", async () => {
  await assert.rejects(resolveDomain("https://example.com/path"), /اسم نطاق فقط/);
  await assert.rejects(resolveDomain("localhost"), /اسم نطاق فقط/);
  await assert.rejects(resolveDomain(""), /اسم نطاق صحيح/);
});

test("Nmap scan requires explicit authorization", async () => {
  await assert.rejects(scanSingleHost("192.168.1.1", false), /أكد صراحةً/);
});

test("Nmap scan accepts only one valid IPv4 target", async () => {
  await assert.rejects(scanSingleHost("192.168.1.0/24", true), /عنوان IPv4 واحد/);
  await assert.rejects(scanSingleHost("example.com", true), /عنوان IPv4 واحد/);
  await assert.rejects(scanSingleHost("127.0.0.1", true), /عنوان IPv4 واحد/);
});
