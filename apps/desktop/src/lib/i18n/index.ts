import en from "./en.json";
import es from "./es.json";
import ca from "./ca.json";
import localeManifest from "./locales.json";

export const localeNames = localeManifest;
export type Locale = keyof typeof localeNames;
export const dictionaries = { en, es, ca } as const;
export type TranslationKey = keyof typeof en;

export function translate(locale: Locale, key: TranslationKey): string {
  return dictionaries[locale][key] ?? en[key];
}

export function isLocale(value: string): value is Locale {
  return Object.hasOwn(localeNames, value);
}
