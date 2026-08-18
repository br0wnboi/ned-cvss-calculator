document.addEventListener('DOMContentLoaded', async () => {
    const i18n = window.NedI18n;

    await i18n.init();

    function syncPageLanguage() {
        document.title = i18n.t('privacyDocumentTitle');
        i18n.translateDocument();

        document.querySelectorAll('.lang-btn').forEach(button => {
            button.classList.toggle('active', button.dataset.lang === i18n.getCurrentLanguage());
        });
    }

    document.querySelectorAll('.lang-btn').forEach(button => {
        button.addEventListener('click', async () => {
            await i18n.setLanguage(button.dataset.lang);
        });
    });

    document.addEventListener('ned:language-changed', syncPageLanguage);
    syncPageLanguage();
});
