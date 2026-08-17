window.NedI18n = (() => {
    const DEFAULT_LANGUAGE = 'en';
    const STORAGE_KEY = 'uiLanguage';
    const SUPPORTED_LANGUAGES = ['en', 'zh_CN'];

    let currentLanguage = DEFAULT_LANGUAGE;
    let initialized = false;
    const bundles = {};

    function normalizeLanguage(language) {
        if (typeof language !== 'string' || language.trim() === '') {
            return DEFAULT_LANGUAGE;
        }

        return language.toLowerCase().startsWith('zh') ? 'zh_CN' : 'en';
    }

    async function loadBundle(language) {
        if (bundles[language]) {
            return bundles[language];
        }

        const response = await fetch(chrome.runtime.getURL(`_locales/${language}/messages.json`));
        if (!response.ok) {
            throw new Error(`Unable to load locale bundle: ${language}`);
        }

        bundles[language] = await response.json();
        return bundles[language];
    }

    function getStoredLanguage() {
        return new Promise(resolve => {
            chrome.storage.local.get([STORAGE_KEY], result => {
                resolve(result[STORAGE_KEY]);
            });
        });
    }

    function setStoredLanguage(language) {
        return new Promise(resolve => {
            chrome.storage.local.set({ [STORAGE_KEY]: language }, resolve);
        });
    }

    function updateDocumentLanguage() {
        document.documentElement.lang = currentLanguage === 'zh_CN' ? 'zh-CN' : 'en';
    }

    function applySubstitutions(message, substitutions) {
        if (typeof message !== 'string') {
            return '';
        }

        const values = Array.isArray(substitutions)
            ? substitutions
            : substitutions === undefined
                ? []
                : [substitutions];

        return values.reduce((result, value, index) => {
            const token = `$${index + 1}`;
            return result.split(token).join(String(value));
        }, message);
    }

    function getMessageEntry(key) {
        return (bundles[currentLanguage] && bundles[currentLanguage][key]) ||
            (bundles[DEFAULT_LANGUAGE] && bundles[DEFAULT_LANGUAGE][key]) ||
            null;
    }

    function t(key, substitutions) {
        const entry = getMessageEntry(key);
        if (!entry || typeof entry.message !== 'string') {
            return key;
        }

        return applySubstitutions(entry.message, substitutions);
    }

    function translateDocument(root = document) {
        root.querySelectorAll('[data-i18n]').forEach(element => {
            element.textContent = t(element.dataset.i18n);
        });

        root.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
            element.placeholder = t(element.dataset.i18nPlaceholder);
        });

        root.querySelectorAll('[data-i18n-title]').forEach(element => {
            element.title = t(element.dataset.i18nTitle);
        });

        root.querySelectorAll('[data-i18n-aria-label]').forEach(element => {
            element.setAttribute('aria-label', t(element.dataset.i18nAriaLabel));
        });

        root.querySelectorAll('[data-i18n-alt]').forEach(element => {
            element.alt = t(element.dataset.i18nAlt);
        });
    }

    async function init() {
        if (!initialized) {
            const storedLanguage = await getStoredLanguage();
            const browserLanguage = typeof chrome.i18n?.getUILanguage === 'function'
                ? chrome.i18n.getUILanguage()
                : navigator.language;

            currentLanguage = normalizeLanguage(storedLanguage || browserLanguage);
            await Promise.all(SUPPORTED_LANGUAGES.map(loadBundle));
            updateDocumentLanguage();
            initialized = true;
        }

        return currentLanguage;
    }

    async function setLanguage(language) {
        const normalizedLanguage = normalizeLanguage(language);

        if (!bundles[normalizedLanguage]) {
            await loadBundle(normalizedLanguage);
        }

        currentLanguage = normalizedLanguage;
        updateDocumentLanguage();
        await setStoredLanguage(normalizedLanguage);
        translateDocument();

        document.dispatchEvent(new CustomEvent('ned:language-changed', {
            detail: { language: currentLanguage },
        }));

        return currentLanguage;
    }

    return {
        DEFAULT_LANGUAGE,
        SUPPORTED_LANGUAGES,
        init,
        normalizeLanguage,
        setLanguage,
        t,
        translateDocument,
        getCurrentLanguage: () => currentLanguage,
    };
})();
