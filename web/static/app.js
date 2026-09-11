// Theme toggle — disabled for now (light mode only, toggle hidden in
// index.html). Auto-detection via prefers-color-scheme and the
// saved-preference read are switched off; the toggle's click handler is
// left wired up in case the button is ever unhidden again.
(() => {
    const toggle = document.getElementById('theme-toggle');
    const html = document.documentElement;
    toggle.addEventListener('click', () => {
        const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('fikua-theme', next);
    });
})();

// Identification flow
(() => {
    // Same-origin now that this page is served by the identity provider
    // itself, rather than by the standalone fikua-lab-identify Worker
    // that used to call the issuer cross-origin.
    const IDENTIFY_API = '/identify';

    // Fields auto-filled by the issuer (not shown in forms)
    const BACKEND_FIELDS = ['issuing_authority', 'issuing_country'];

    const params = new URLSearchParams(window.location.search);
    const sessionToken = params.get('session');

    const phases = {
        identify: document.getElementById('phase-identify'),
        loading: document.getElementById('phase-loading'),
        form: document.getElementById('phase-form'),
        confirm: document.getElementById('phase-confirm'),
        submitting: document.getElementById('phase-submitting'),
        success: document.getElementById('phase-success'),
        error: document.getElementById('phase-error')
    };

    let certData = null;
    let claimsMetadata = null;

    function showPhase(name) {
        Object.entries(phases).forEach(function(entry) {
            entry[1].classList.toggle('hidden', entry[0] !== name);
        });
    }

    function showError(message) {
        document.getElementById('error-message').textContent = message;
        showPhase('error');
    }

    // Render dynamic form fields from claims metadata
    function renderFormFields(container, claims, prefill) {
        container.innerHTML = '';
        if (!claims) return;
        claims.forEach(function(claim) {
            var fieldName = claim.path[0];
            if (BACKEND_FIELDS.indexOf(fieldName) !== -1) return;

            var label = (claim.display && claim.display[0]) ? claim.display[0].name : fieldName;
            // Whether this field is a date comes from the credential's own
            // scheme (its DataType), not a fixed field-name list, so the
            // same form works for any credential type this AS ever asks for.
            var inputType = claim.is_date ? 'date' : 'text';
            var prefillValue = (prefill && prefill[fieldName]) ? prefill[fieldName] : '';
            // Whether this field is required comes from the credential's own
            // scheme (attestation-registry's presence declaration, passed
            // through by the issuer and this AS) — not a fixed list, so the
            // same form works for any credential type this AS ever asks for.
            var isRequired = !!claim.mandatory;

            var group = document.createElement('div');
            group.className = 'form-group';

            var labelEl = document.createElement('label');
            labelEl.className = 'form-label';
            labelEl.setAttribute('for', 'field-' + fieldName);
            labelEl.textContent = label + (isRequired ? '' : ' (optional)');

            var input = document.createElement('input');
            input.className = 'form-input';
            input.type = inputType;
            input.id = 'field-' + fieldName;
            input.name = fieldName;
            input.required = isRequired;
            input.value = prefillValue;
            if (prefillValue) {
                input.readOnly = true;
                input.classList.add('form-input--prefilled');
            }

            group.appendChild(labelEl);
            group.appendChild(input);
            container.appendChild(group);
        });
    }

    // Collect form data from a container — empty optional fields are
    // omitted rather than sent as blank strings.
    function collectFormData(container) {
        var data = {};
        var fields = container.querySelectorAll('input');
        fields.forEach(function(input) {
            if (input.value !== '') data[input.name] = input.value;
        });
        return data;
    }

    // Validate all required fields are filled
    function validateForm(container) {
        var allFilled = true;
        container.querySelectorAll('input[required]').forEach(function(input) {
            if (!input.value.trim()) {
                input.classList.add('form-input--error');
                allFilled = false;
            } else {
                input.classList.remove('form-input--error');
            }
        });
        return allFilled;
    }

    // Submit identification data
    function submitIdentification(credentialData, sourceType, sourceRef) {
        showPhase('submitting');
        var body = {
            session: sessionToken,
            credential_data: credentialData,
            source_type: sourceType,
            source_ref: sourceRef
        };

        fetch(IDENTIFY_API + '/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(res) {
            if (!res.ok) return res.json().then(function(err) { throw new Error(err.error_description || err.error || 'Server error'); });
            return res.json();
        })
        .then(function(data) {
            if (data.redirect) {
                showPhase('success');
                setTimeout(function() { window.location.href = data.redirect; }, 1500);
            } else {
                showError('No redirect URL received.');
            }
        })
        .catch(function(err) {
            showError('Identification failed: ' + err.message);
        });
    }

    // Deny the authorization request — redirects the client back with
    // error=access_denied instead of an authorization code (RFC 6749
    // §4.1.2.1). Reuses the "submitting" phase's spinner UI, with its
    // text swapped so it doesn't claim to be creating a credential.
    function denyAuthorization() {
        var heading = phases.submitting.querySelector('h1');
        var sub = phases.submitting.querySelector('.id-sub');
        heading.textContent = 'Denying Access';
        sub.textContent = 'Returning you to the wallet...';
        showPhase('submitting');
        fetch(IDENTIFY_API + '/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session: sessionToken })
        })
        .then(function(res) {
            if (!res.ok) return res.json().then(function(err) { throw new Error(err.error_description || err.error || 'Server error'); });
            return res.json();
        })
        .then(function(data) {
            if (data.redirect) {
                window.location.href = data.redirect;
            } else {
                showError('No redirect URL received.');
            }
        })
        .catch(function(err) {
            showError('Failed to deny access: ' + err.message);
        });
    }

    // --- Initialization ---

    if (!sessionToken) {
        showError('Missing session parameter. This page must be accessed from the authorization flow.');
        return;
    }

    // Fetch claims metadata from backend
    fetch(IDENTIFY_API + '/claims?session=' + encodeURIComponent(sessionToken))
        .then(function(res) {
            if (!res.ok) throw new Error('Failed to fetch claims');
            return res.json();
        })
        .then(function(data) {
            claimsMetadata = data.claims || [];
        })
        .catch(function(err) {
            console.warn('Could not fetch claims metadata, using fallback', err);
            // Only reached if /identify/claims itself is unreachable — a
            // generic minimal-identity fallback, not tied to any one
            // credential's schema, so it stays deliberately PID-shaped.
            claimsMetadata = [
                { path: ['given_name'], display: [{ name: 'Given Name', locale: 'en' }], mandatory: true },
                { path: ['family_name'], display: [{ name: 'Surname', locale: 'en' }], mandatory: true },
                { path: ['birth_date'], display: [{ name: 'Date of Birth', locale: 'en' }], mandatory: true, is_date: true }
            ];
        })
        .then(function() {
            // After claims loaded: check whether we came back from the
            // X.509 flow. Nothing sets this parameter yet — see the
            // method-cert handler below.
            var certParam = params.get('cert');
            if (certParam) {
                try {
                    certData = JSON.parse(atob(certParam));
                    var nameParts = (certData.subject || '').split(' ');
                    var givenName = nameParts[0] || certData.subject || '';
                    var familyName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';

                    document.getElementById('cert-summary-issuer').textContent = certData.issuer || '-';
                    document.getElementById('cert-summary-serial').textContent = certData.serial || '-';

                    renderFormFields(document.getElementById('confirm-form-fields'), claimsMetadata, {
                        given_name: givenName,
                        family_name: familyName
                    });
                    showPhase('confirm');
                } catch (e) {
                    showError('Failed to parse certificate data. Please try again.');
                }
            }
        });

    // --- Deny access ---
    document.getElementById('btn-deny').addEventListener('click', function() {
        denyAuthorization();
    });

    // --- Method: Digital Certificate ---
    //
    // TODO(x509): not ported yet. The old flow redirected to the separate
    // fikua-lab-cert origin, where Traefik terminated mTLS with
    // clientAuthType=RequestClientCert and its passTLSClientCert
    // middleware injected X-Forwarded-Tls-Client-Cert-Info; nginx echoed
    // that back from /cert-info and the page parsed the DN itself
    // (formats differ per CA — FNMT, ACCV, Camerfirma — which is why
    // parsing stayed in JS). Replicating that here needs its own
    // mTLS-terminating Traefik route for this service before any Go code
    // is worth writing, so it is deliberately IaC work first. When it
    // lands, a handler reading that same header should base64url a
    // {subject, issuer, serial} object into a `cert` query param and
    // redirect back here — the confirm phase above already consumes
    // exactly that.
    document.getElementById('method-cert').addEventListener('click', function() {
        showError('Certificate identification is not available yet. Please use the manual form.');
    });

    // --- Method: Manual Form ---
    document.getElementById('method-form').addEventListener('click', function() {
        if (!claimsMetadata) return;
        renderFormFields(document.getElementById('form-fields'), claimsMetadata, null);
        showPhase('form');
    });

    // Form submit
    document.getElementById('btn-form-submit').addEventListener('click', function() {
        var container = document.getElementById('form-fields');
        if (!validateForm(container)) return;
        var credentialData = collectFormData(container);
        submitIdentification(credentialData, 'manual_form', 'User manual input');
    });

    // Form cancel
    document.getElementById('btn-form-cancel').addEventListener('click', function() {
        showPhase('identify');
    });

    // --- Certificate confirm ---
    document.getElementById('btn-confirm').addEventListener('click', function() {
        if (!sessionToken) return;
        var container = document.getElementById('confirm-form-fields');
        if (!validateForm(container)) return;
        var credentialData = collectFormData(container);
        submitIdentification(credentialData, 'x509_cert',
            certData.subject + ' (serial: ' + certData.serial + ')');
    });

    // Cancel button — go back to identify phase
    document.getElementById('btn-cancel').addEventListener('click', function() {
        certData = null;
        var cleanUrl = window.location.origin + window.location.pathname + '?session=' + encodeURIComponent(sessionToken);
        window.history.replaceState({}, '', cleanUrl);
        showPhase('identify');
    });

    // Retry button
    document.getElementById('btn-retry').addEventListener('click', function() {
        if (sessionToken) {
            certData = null;
            var cleanUrl = window.location.origin + window.location.pathname + '?session=' + encodeURIComponent(sessionToken);
            window.history.replaceState({}, '', cleanUrl);
            showPhase('identify');
        }
    });
})();
