const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const dir = path.join(__dirname, "..", "src", "lib", "i18n");
const manifest = require(path.join(dir, "locales.json"));
const dictionaries = Object.fromEntries(
  Object.keys(manifest).map((locale) => [locale, require(path.join(dir, locale + ".json"))]),
);
const en = dictionaries.en;

test("locale manifest registers every dictionary", () => {
  assert.ok(en, "English must be the primary locale");
  for (const locale of Object.keys(manifest)) {
    assert.ok(fs.existsSync(path.join(dir, locale + ".json")), locale + " dictionary exists");
  }
});

test("every locale has complete English key coverage", () => {
  for (const [locale, dictionary] of Object.entries(dictionaries)) {
    assert.deepEqual(Object.keys(dictionary).sort(), Object.keys(en).sort(), locale + " keys");
  }
});

test("all locale values are non-empty strings", () => {
  for (const [locale, dictionary] of Object.entries(dictionaries)) {
    for (const [key, value] of Object.entries(dictionary)) {
      assert.equal(typeof value, "string", locale + "." + key);
      assert.ok(value.trim().length, locale + "." + key);
    }
  }
});

test("English is the primary application language", () => {
  assert.equal(manifest.en, "English");
  assert.match(fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8"), /<html lang="en">/);
});
