(function () {
    'use strict';

    const root = document.documentElement;
    const locale = window.DMARQ_I18N_LOCALE || root.dataset.appLocale || root.lang || 'en';
    const catalog = window.DMARQ_I18N_CATALOG || {};

    const translate = (message, replacements = {}) => {
        let result = catalog[message] || message;
        Object.entries(replacements).forEach(([key, value]) => {
            result = result.replaceAll(`{${key}}`, String(value));
        });
        return result;
    };

    const translateTextNode = (node) => {
        if (!node || node.nodeType !== Node.TEXT_NODE || !node.parentElement) return;
        if (node.parentElement.closest('script, style, code, pre, [data-i18n-ignore]')) return;
        const source = node.nodeValue;
        const trimmed = source.trim();
        if (!trimmed || !catalog[trimmed]) return;
        node.nodeValue = source.replace(trimmed, catalog[trimmed]);
    };

    const translateAttributes = (element) => {
        if (!(element instanceof Element) || element.matches('[data-i18n-ignore]')) return;
        ['aria-label', 'placeholder', 'title'].forEach((attribute) => {
            const source = element.getAttribute(attribute);
            if (source && catalog[source]) element.setAttribute(attribute, catalog[source]);
        });
    };

    const translateTree = (node) => {
        if (node.nodeType === Node.TEXT_NODE) {
            translateTextNode(node);
            return;
        }
        if (!(node instanceof Element) && node !== document) return;
        if (node instanceof Element) translateAttributes(node);
        const walker = document.createTreeWalker(node, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
        let current = walker.nextNode();
        while (current) {
            if (current.nodeType === Node.TEXT_NODE) translateTextNode(current);
            else translateAttributes(current);
            current = walker.nextNode();
        }
    };

    const chooseLocale = (nextLocale) => {
        if (!['en', 'de'].includes(nextLocale)) return;
        document.cookie = `dmarq_locale=${nextLocale}; Path=/; Max-Age=31536000; SameSite=Lax`;
        const nextUrl = new URL(window.location.href);
        nextUrl.searchParams.delete('lang');
        window.location.replace(nextUrl.toString());
    };

    const syncLanguageSelectors = (rootNode = document) => {
        if (rootNode instanceof Element && rootNode.matches('[data-language-selector]')) {
            rootNode.value = locale;
        }
        if (typeof rootNode.querySelectorAll !== 'function') return;
        rootNode.querySelectorAll('[data-language-selector]').forEach((selector) => {
            selector.value = locale;
        });
    };

    window.dmarqLocale = locale;
    window.dmarqT = translate;
    window.dmarqFormatNumber = (value, options = {}) =>
        new Intl.NumberFormat(locale, options).format(value);
    window.dmarqFormatDate = (value, options = {}) => {
        const date = value instanceof Date ? value : new Date(value);
        if (Number.isNaN(date.getTime())) return String(value ?? '');
        return new Intl.DateTimeFormat(locale, options).format(date);
    };

    document.addEventListener('DOMContentLoaded', () => {
        translateTree(document.body);
        syncLanguageSelectors();
        document.addEventListener('change', (event) => {
            if (!(event.target instanceof Element)) return;
            const selector = event.target.closest('[data-language-selector]');
            if (selector) chooseLocale(selector.value);
        });

        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    translateTree(node);
                    syncLanguageSelectors(node);
                });
            });
        });
        // Alpine owns existing text nodes. Observing characterData here causes a
        // feedback loop when Alpine restores source text after it is translated.
        // Added nodes still cover asynchronously rendered menus and status copy.
        observer.observe(document.body, {childList: true, subtree: true});
    });
})();
