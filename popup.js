document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.tab-btn');
    const sections = document.querySelectorAll('.tab-content');
    const vectorDisplay = document.getElementById('vector-string');
    const scoreDisplay = document.getElementById('final-score');
    const severityDisplay = document.getElementById('final-severity');
    const emojiDisplay = document.getElementById('final-emoji');
    const resetBtn = document.getElementById('reset-btn');
    const appVersionDisplay = document.getElementById('app-version');

    if (appVersionDisplay) {
        const manifest = chrome.runtime.getManifest();
        appVersionDisplay.textContent = `v${manifest.version}`;
    }

    let currentTab = 'cvss3';

    // Default fresh states
    const defaultStates = {
        cvss3: {
            metrics: {
                'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U',
                'C': 'N', 'I': 'N', 'A': 'N'
            }
        },
        cvss4: {
            metrics: {
                'AV': 'N', 'AC': 'L', 'AT': 'N', 'PR': 'N', 'UI': 'N',
                'VC': 'N', 'VI': 'N', 'VA': 'N', 'SC': 'N', 'SI': 'N', 'SA': 'N'
            }
        }
    };

    // Current working state
    let state = JSON.parse(JSON.stringify(defaultStates));

    function saveState() {
        chrome.storage.local.set({ cvssState: state, activeTab: currentTab });
    }

    function loadState(callback) {
        chrome.storage.local.get(['cvssState', 'activeTab'], (result) => {
            if (result.cvssState) {
                state = result.cvssState;
            }
            if (result.activeTab) {
                currentTab = result.activeTab;
            }
            callback();
        });
    }

    function updateUISelections() {
        document.querySelectorAll('.metric-options').forEach(group => {
            const metricGroup = group.dataset.metric; // e.g. "3_AV"
            const [versionStr, metricName] = metricGroup.split('_');
            const version = "cvss" + versionStr;
            const currentVal = state[version].metrics[metricName];

            group.querySelectorAll('.opt-btn').forEach(b => b.classList.remove('selected'));
            if (currentVal) {
                const btn = group.querySelector(`[data-val="${currentVal}"]`);
                if (btn) btn.classList.add('selected');
            }
        });
    }

    // Setup tab switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
            currentTab = tab.dataset.tab;

            updateUISelections(); // ensure active tab shows correct selections if coming back
            updateCalculations();

            // Hide vector string on About tab
            if (currentTab === 'about') {
                document.querySelector('.vector-display-container').style.display = 'none';
            } else {
                document.querySelector('.vector-display-container').style.display = 'flex';
            }

            saveState();
        });
    });

    const vectorInput = document.getElementById('vector-input');
    const editVectorBtn = document.getElementById('edit-vector-btn');
    const copiedBadge = document.getElementById('copied-badge');
    const toast = document.getElementById('toast');

    function showToast(message) {
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }

    // Setup copy to clipboard vs edit (differentiate single and double clicks)
    let clickTimeout = null;
    vectorDisplay.addEventListener('click', () => {
        if (clickTimeout !== null) {
            clearTimeout(clickTimeout);
            clickTimeout = null;
            startEdit(); // Double click
        } else {
            clickTimeout = setTimeout(() => {
                clickTimeout = null;
                // Single click logic (copy)
                const text = vectorDisplay.dataset.rawVector || vectorDisplay.textContent.trim();

                if (text === 'Invalid metrics' || text.includes('Error') || text === '--') {
                    showToast('Cannot copy invalid vector string');
                    return;
                }

                navigator.clipboard.writeText(text).then(() => {
                    copiedBadge.classList.add('show');
                    setTimeout(() => {
                        copiedBadge.classList.remove('show');
                    }, 1500);
                });
            }, 250); // 250ms threshold
        }
    });

    // Setup Edit Mode
    const saveIconHTML = `<svg xmlns="http://www.3w.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-save"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"></path><polyline points="17 21 17 13 7 13 7 21"></polyline><polyline points="7 3 7 8 15 8"></polyline></svg>`;
    const editIconHTML = `✎`;

    function startEdit() {
        const text = vectorDisplay.dataset.rawVector || vectorDisplay.textContent.trim();
        if (text === 'Invalid metrics' || text.includes('Error') || text === '--') {
            showToast("Cannot edit an invalid vector string");
            return;
        }

        vectorDisplay.style.display = 'none';
        vectorInput.style.display = 'block';
        vectorInput.value = text;
        vectorInput.focus();
        editVectorBtn.innerHTML = saveIconHTML;
        editVectorBtn.title = "Save Vector String";
    }

    function stopEditAndSave() {
        vectorInput.style.display = 'none';
        vectorDisplay.style.display = 'block';
        editVectorBtn.innerHTML = editIconHTML;
        editVectorBtn.title = "Edit Vector String";

        const newVector = vectorInput.value.trim();
        if (!newVector) return;

        try {
            if (newVector.startsWith('CVSS:3.1/')) {
                if (currentTab !== 'cvss3') {
                    document.querySelector('.tab-btn[data-tab="cvss3"]').click();
                }
                const metricsStr = newVector.replace('CVSS:3.1/', '');
                const mArr = metricsStr.split('/');
                let hasInvalidValue = false;

                mArr.forEach(m => {
                    const [key, val] = m.split(':');
                    if (state.cvss3.metrics[key] !== undefined) {
                        const metricGroup = `3_${key}`;
                        const isValid = document.querySelector(`.metric-options[data-metric="${metricGroup}"] .opt-btn[data-val="${val}"]`);
                        if (isValid) {
                            state.cvss3.metrics[key] = val;
                        } else {
                            hasInvalidValue = true;
                        }
                    }
                });

                if (hasInvalidValue) {
                    showToast("Error parsing vector string. Ensure proper format.");
                    updateCalculations();
                    return;
                }

            } else if (newVector.startsWith('CVSS:4.0/')) {
                if (currentTab !== 'cvss4') {
                    document.querySelector('.tab-btn[data-tab="cvss4"]').click();
                }
                const metricsStr = newVector.replace('CVSS:4.0/', '');
                const mArr = metricsStr.split('/');
                let hasInvalidValue = false;

                mArr.forEach(m => {
                    const [key, val] = m.split(':');
                    if (state.cvss4.metrics[key] !== undefined) {
                        const metricGroup = `4_${key}`;
                        const isValid = document.querySelector(`.metric-options[data-metric="${metricGroup}"] .opt-btn[data-val="${val}"]`);
                        if (isValid) {
                            state.cvss4.metrics[key] = val;
                        } else {
                            hasInvalidValue = true;
                        }
                    }
                });

                if (hasInvalidValue) {
                    showToast("Error parsing vector string. Ensure proper format.");
                    updateCalculations(); // Allows UI to display cleanly based on whatever valid chunks were parsed
                    return;
                }

            } else {
                showToast("Invalid vector string prefix. Must start with CVSS:3.1/ or CVSS:4.0/");
                return;
            }
            updateUISelections();
            updateCalculations();
            saveState();
        } catch (e) {
            showToast("Error parsing vector string. Ensure proper format.");
        }
    }

    editVectorBtn.addEventListener('click', () => {
        if (vectorInput.style.display === 'block') {
            stopEditAndSave();
        } else {
            startEdit();
        }
    });

    vectorInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            stopEditAndSave();
        } else if (e.key === 'Escape') {
            // Cancel edit
            vectorInput.style.display = 'none';
            vectorDisplay.style.display = 'block';
            editVectorBtn.textContent = '✎';
        }
    });

    // Setup metric selection
    document.querySelectorAll('.opt-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const actualBtn = e.target.closest('.opt-btn');
            if (!actualBtn) return;

            const parent = actualBtn.parentElement;
            const metricGroup = parent.dataset.metric;
            if (!metricGroup) return;

            const [versionStr, metricName] = metricGroup.split('_');
            const version = "cvss" + versionStr;

            // Rescue corrupted state from bad manual vector string inputs before applying this valid choice
            if (scoreDisplay.textContent === 'Error' || vectorDisplay.textContent.trim() === 'Invalid metrics') {
                if (defaultStates[version]) {
                    state[version] = JSON.parse(JSON.stringify(defaultStates[version]));
                }
            }

            parent.querySelectorAll('.opt-btn').forEach(b => b.classList.remove('selected'));
            actualBtn.classList.add('selected');

            state[version].metrics[metricName] = actualBtn.dataset.val;
            updateCalculations();
            saveState();
        });
    });

    // Setup Reset Button
    resetBtn.addEventListener('click', () => {
        if (!defaultStates[currentTab]) return;

        state[currentTab] = JSON.parse(JSON.stringify(defaultStates[currentTab]));
        updateUISelections();
        updateCalculations();
        saveState();
    });

    function getSeverityClass(score) {
        if (score === 0) return 'sev-none';
        if (score < 4.0) return 'sev-low';
        if (score < 7.0) return 'sev-medium';
        if (score < 9.0) return 'sev-high';
        return 'sev-critical';
    }

    function getSeverityName(score) {
        if (score === 0) return 'None';
        if (score < 4.0) return 'Low';
        if (score < 7.0) return 'Medium';
        if (score < 9.0) return 'High';
        return 'Critical';
    }

    function getSeverityEmoji(score) {
        if (score === 0) return '😴';
        if (score < 4.0) return '🥱';
        if (score < 7.0) return '😬';
        if (score < 9.0) return '😎';
        return '🔥';
    }

    function updateCalculations() {
        if (currentTab === 'cvss3') {
            const m = state.cvss3.metrics;
            // Using FIRST.org cvsscalc31.js CVSS31 namespace
            if (typeof CVSS31 !== 'undefined') {
                const result = CVSS31.calculateCVSSFromMetrics(
                    m.AV, m.AC, m.PR, m.UI, m.S, m.C, m.I, m.A,
                    "X", "X", "X", // Temporal
                    "X", "X", "X", "X", "X", "X", "X", "X", "X", "X", "X" // Environmental
                );

                if (result.success) {
                    updateUI(result.baseMetricScore, result.baseSeverity, result.vectorString);
                } else {
                    updateUI('Error', 'N/A', 'Invalid metrics');
                }
            } else {
                updateUI('--', 'none', 'Error: CVSS3 library missing');
            }
        } else if (currentTab === 'cvss4') {
            const m = state.cvss4.metrics;
            // Using Red Hat cvss40.js CVSS40 class
            if (typeof CVSS40 !== 'undefined') {
                const vectorString = `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}/VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`;
                try {
                    const vuln = new CVSS40(vectorString);
                    updateUI(vuln.score.toFixed(1), getSeverityName(vuln.score), vuln.vector.raw);
                } catch (e) {
                    updateUI('Error', 'N/A', 'Invalid metrics');
                }
            } else {
                updateUI('--', 'none', 'Error: CVSS4 library missing');
            }
        } else {
            // About tab, do nothing
        }
    }

    function updateUI(score, severity, vector) {
        scoreDisplay.textContent = score;
        severityDisplay.textContent = severity;
        vectorDisplay.textContent = vector;
        vectorDisplay.dataset.rawVector = vector;

        // Update colors and emoji
        const numScore = parseFloat(score);
        if (!isNaN(numScore)) {
            scoreDisplay.className = 'score-value ' + getSeverityClass(numScore);
            severityDisplay.className = 'score-severity ' + getSeverityClass(numScore);

            if (numScore === 6.9) {
                emojiDisplay.innerHTML = '<img src="images/69.jpeg" class="easter-egg-img" alt="6.9">';
            } else if (numScore === 6.7) {
                emojiDisplay.innerHTML = '<img src="images/67.webp" class="easter-egg-img" alt="6.7">';
            } else {
                emojiDisplay.textContent = getSeverityEmoji(numScore);
            }
        } else {
            scoreDisplay.className = 'score-value';
            severityDisplay.className = 'score-severity';
            emojiDisplay.textContent = '❌';
        }
    }

    function applyHelpTextToButtons() {
        document.querySelectorAll('.metric').forEach(metricDiv => {
            const optionsContainer = metricDiv.querySelector('.metric-options');
            if (!optionsContainer) return;

            const metricGroup = optionsContainer.dataset.metric;
            if (!metricGroup) return;

            const [versionStr, metricName] = metricGroup.split('_');
            const helpObj = versionStr === "3" ? (typeof CVSS31_Help !== 'undefined' ? CVSS31_Help.helpText_en : null) :
                versionStr === "4" ? (typeof CVSS40_Help !== 'undefined' ? CVSS40_Help.helpText_en : null) : null;

            if (!helpObj) return;

            // Apply to the metric heading/label itself
            const label = metricDiv.querySelector('label');
            const headingKey = metricName + "_Heading";
            if (label && helpObj[headingKey]) {
                label.title = helpObj[headingKey];
                // Visual cue that it has a tooltip
                label.style.textDecoration = 'underline dotted rgba(255,255,255,0.3)';
                label.style.cursor = 'help';
            }

            // Apply to each option button
            optionsContainer.querySelectorAll('.opt-btn').forEach(btn => {
                const optVal = btn.dataset.val;

                // Extract original title (e.g. "Network") as the short display name
                // Some buttons might have already been processed if this function runs multiple times,
                // but since innerHTML is overwritten, we rely on the data-val for the Initial.
                // To be safe and idempotent, we check if it already has child elements
                if (btn.children.length === 0) {
                    const shortName = btn.title || optVal;
                    btn.innerHTML = `<span class="opt-val">${optVal}</span>
                                     <span class="opt-name">${shortName}</span>`;
                }

                // Add the official FIRST.org long help text to the browser native tooltip
                const labelKey = metricName + "_" + optVal + "_Label";
                if (helpObj[labelKey]) {
                    btn.title = helpObj[labelKey];
                }
            });
        });
    }

    function setupHoverHighlights() {
        document.querySelectorAll('.metric').forEach(metricDiv => {
            metricDiv.addEventListener('mouseenter', () => {
                const optionsContainer = metricDiv.querySelector('.metric-options');
                if (!optionsContainer) return;

                const metricGroup = optionsContainer.dataset.metric;
                if (!metricGroup) return;

                const [, metricAbbr] = metricGroup.split('_'); // 'AV' etc

                let rawText = vectorDisplay.dataset.rawVector;
                if (!rawText || rawText === 'Invalid metrics' || rawText.includes('Error') || rawText === '--') return;

                // Create a RegEx to find the exact metric attribute like "/AV:N/" or "/AV:N"
                // The regex captures three parts: the prefix (slash or start), the metric chunk (e.g. AV:N), and suffix
                const regex = new RegExp(`(^|/)(${metricAbbr}:[^/]+)`);
                if (regex.test(rawText)) {
                    // Wrap the match in our highlight span HTML
                    const highlightedHTML = rawText.replace(regex, `$1<span class="vector-highlight">$2</span>`);
                    vectorDisplay.innerHTML = highlightedHTML;
                }
            });

            metricDiv.addEventListener('mouseleave', () => {
                const rawText = vectorDisplay.dataset.rawVector;
                if (rawText && vectorDisplay.innerHTML.includes('vector-highlight')) {
                    // Restore unmodified raw vector
                    vectorDisplay.textContent = rawText;
                }
            });
        });
    }

    // Initialize application state
    loadState(() => {
        // Activate correct tab based on saved state
        tabs.forEach(t => t.classList.remove('active'));
        sections.forEach(s => s.classList.remove('active'));
        document.querySelector(`.tab-btn[data-tab="${currentTab}"]`).classList.add('active');
        document.getElementById(currentTab).classList.add('active');

        // Render UI
        updateUISelections();
        updateCalculations();
        applyHelpTextToButtons();
        setupHoverHighlights();

        if (currentTab === 'about') {
            document.querySelector('.vector-display-container').style.display = 'none';
        } else {
            document.querySelector('.vector-display-container').style.display = 'flex';
        }
    });
});
