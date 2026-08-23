"use strict";

const API_BASE =
    "/api";

const PERMISSIONS = Object.freeze({
    READ: "credential.read",
    AUDIT: "audit.read",
    REVOKE: "credential.revoke",
    ADMIN: "admin.manage",
});

let sessionToken = null;
let sessionExpiresAt = 0;
let currentSerial = null;
let currentRole = null;

let countdownTimer = null;
let sessionValidationTimer = null;

const elements = {};


function getElements() {
    const ids = [
        "api-dot",
        "api-status",
        "auth-status",
        "admin-username",
        "admin-token",
        "unlock-button",
        "login-form",
        "authenticated-controls",
        "lock-button",
        "auth-message",
        "session-details",
        "session-identity",
        "session-username",
        "session-role",
        "session-countdown",
        "permission-strip",
        "perm-read",
        "perm-audit",
        "perm-revoke",
        "perm-admin",
        "protected-console",
        "lookup-capability",
        "serial-input",
        "lookup-button",
        "message",
        "credential-section",
        "credential-name",
        "credential-status-badge",
        "credential-organization",
        "credential-common-name",
        "credential-key-id",
        "credential-serial",
        "credential-issued",
        "credential-expires",
        "credential-revoked",
        "credential-reason",
        "audit-access-panel",
        "audit-state",
        "history-list",
        "active-action-panel",
        "revoke-denied-panel",
        "reason-input",
        "revoke-button",
        "revoked-state-panel",
        "revoked-state-date",
        "revoked-state-reason",
        "admin-audit-section",
        "admin-audit-state",
        "admin-audit-list",
    ];

    for (const id of ids) {
        elements[id] =
            document.getElementById(id);
    }
}


function assertElements() {
    for (
        const [name, element]
        of Object.entries(elements)
    ) {
        if (!element) {
            throw new Error(
                `Missing AEGIS admin element: ${name}`
            );
        }
    }
}


function authHeaders() {
    if (!sessionToken) {
        return {};
    }

    return {
        Authorization:
            `Bearer ${sessionToken}`,
    };
}


async function apiRequest(
    path,
    options = {}
) {
    const response =
        await fetch(
            `${API_BASE}${path}`,
            {
                ...options,

                headers: {
                    ...authHeaders(),
                    ...(options.headers || {}),
                },
            }
        );

    let data = null;

    try {
        data =
            await response.json();
    } catch {
        // Empty response.
    }

    if (!response.ok) {
        const error =
            new Error(
                data?.detail ||
                `AEGIS API request failed (${response.status}).`
            );

        error.status =
            response.status;

        throw error;
    }

    return data;
}


async function checkApi() {
    try {
        const response =
            await fetch(
                `${API_BASE}/health`
            );

        if (!response.ok) {
            throw new Error();
        }

        elements[
            "api-dot"
        ].className =
            "status-dot online";

        elements[
            "api-status"
        ].textContent =
            "API online";
    } catch {
        elements[
            "api-dot"
        ].className =
            "status-dot offline";

        elements[
            "api-status"
        ].textContent =
            "API offline";
    }
}


function setAuthMessage(
    message,
    error = false
) {
    elements[
        "auth-message"
    ].textContent =
        message;

    elements[
        "auth-message"
    ].className =
        error
            ? "auth-message error"
            : "auth-message";
}


function formatDuration(
    seconds
) {
    const total =
        Math.max(
            0,
            Math.ceil(
                Number(seconds) || 0
            )
        );

    const minutes =
        Math.floor(
            total / 60
        );

    const remaining =
        total % 60;

    return (
        String(minutes).padStart(
            2,
            "0"
        )
        +
        ":"
        +
        String(
            remaining
        ).padStart(
            2,
            "0"
        )
    );
}


function updateCountdown() {
    if (!sessionToken) {
        elements[
            "session-countdown"
        ].textContent =
            "ΓÇö";

        return;
    }

    const remaining =
        Math.max(
            0,
            Math.ceil(
                (
                    sessionExpiresAt -
                    Date.now()
                )
                / 1000
            )
        );

    elements[
        "session-countdown"
    ].textContent =
        formatDuration(
            remaining
        );

    elements[
        "session-countdown"
    ].style.color =
        remaining <= 60
            ? "var(--red)"
            : "var(--accent)";

    if (
        remaining <= 0
    ) {
        expireSession(
            "Authenticated session expired."
        );
    }
}


function startSessionTimers() {
    stopSessionTimers();

    updateCountdown();

    countdownTimer =
        window.setInterval(
            updateCountdown,
            1000
        );

    sessionValidationTimer =
        window.setInterval(
            validateServerSession,
            30000
        );
}


function stopSessionTimers() {
    if (countdownTimer) {
        window.clearInterval(
            countdownTimer
        );

        countdownTimer = null;
    }

    if (
        sessionValidationTimer
    ) {
        window.clearInterval(
            sessionValidationTimer
        );

        sessionValidationTimer = null;
    }
}


function rolePermissions(
    role
) {
    switch (
        String(
            role || ""
        ).toUpperCase()
    ) {
        case "ADMIN":
            return new Set([
                PERMISSIONS.READ,
                PERMISSIONS.AUDIT,
                PERMISSIONS.REVOKE,
                PERMISSIONS.ADMIN,
            ]);

        case "OPERATOR":
            return new Set([
                PERMISSIONS.READ,
                PERMISSIONS.AUDIT,
                PERMISSIONS.REVOKE,
            ]);

        case "AUDITOR":
            return new Set([
                PERMISSIONS.READ,
                PERMISSIONS.AUDIT,
            ]);

        case "VIEWER":
            return new Set([
                PERMISSIONS.READ,
            ]);

        default:
            return new Set();
    }
}


function hasPermission(
    permission
) {
    return rolePermissions(
        currentRole
    ).has(
        permission
    );
}


function getRoleLabel(
    role
) {
    const normalized =
        String(
            role || ""
        ).toUpperCase();

    if (!normalized) {
        return "Authenticated";
    }

    return (
        normalized.charAt(0) +
        normalized.slice(1).toLowerCase()
    );
}


function renderSessionActiveLabel(
    role
) {
    const sessionActive =
        elements[
            "authenticated-controls"
        ].querySelector(
            ".session-active span:last-child"
        );

    if (!sessionActive) {
        return;
    }

    sessionActive.textContent =
        `${getRoleLabel(role)} session active`;
}


function renderRoleBadge(
    role
) {
    const normalized =
        String(
            role || ""
        ).toUpperCase();

    elements[
        "session-role"
    ].textContent =
        normalized || "ΓÇö";

    elements[
        "session-role"
    ].className =
        normalized
            ? `role-badge ${normalized.toLowerCase()}`
            : "role-badge";
}


function renderPermissions() {
    const permissions =
        rolePermissions(
            currentRole
        );

    const states = [
        [
            "perm-read",
            PERMISSIONS.READ,
        ],
        [
            "perm-audit",
            PERMISSIONS.AUDIT,
        ],
        [
            "perm-revoke",
            PERMISSIONS.REVOKE,
        ],
        [
            "perm-admin",
            PERMISSIONS.ADMIN,
        ],
    ];

    for (
        const [id, permission]
        of states
    ) {
        const allowed =
            permissions.has(
                permission
            );

        elements[id].className =
            allowed
                ? "permission-dot allowed"
                : "permission-dot denied";
    }

    elements[
        "permission-strip"
    ].classList.remove(
        "hidden"
    );

    elements[
        "lookup-capability"
    ].textContent =
        hasPermission(
            PERMISSIONS.READ
        )
            ? "READ"
            : "DENIED";
}


function setAuthenticated(
    authenticated,
    session = null
) {
    const roleLabel =
        getRoleLabel(
            session?.role || currentRole
        );

    elements[
        "protected-console"
    ].classList.toggle(
        "hidden",
        !authenticated
    );

    elements[
        "session-details"
    ].classList.toggle(
        "hidden",
        !authenticated
    );

    elements[
        "permission-strip"
    ].classList.toggle(
        "hidden",
        !authenticated
    );

    elements[
        "login-form"
    ].classList.toggle(
        "hidden",
        authenticated
    );

    elements[
        "authenticated-controls"
    ].classList.toggle(
        "hidden",
        !authenticated
    );

    elements[
        "auth-status"
    ].textContent =
        authenticated
            ? "AUTHENTICATED"
            : "LOCKED";

    elements[
        "auth-status"
    ].className =
        authenticated
            ? "auth-status authenticated"
            : "auth-status locked";

    if (
        authenticated &&
        session
    ) {
        currentRole =
            String(
                session.role || ""
            ).toUpperCase();

        renderSessionActiveLabel(
            currentRole
        );

        elements[
            "session-identity"
        ].textContent =
            session.identity ||
            "AEGIS Administrator";

        elements[
            "session-username"
        ].textContent =
            session.username
                ? `@${session.username}`
                : "ΓÇö";

        renderRoleBadge(
            currentRole
        );

        renderPermissions();

        elements[
            "audit-access-panel"
        ].classList.toggle(
            "hidden",
            !hasPermission(
                PERMISSIONS.AUDIT
            )
        );

        elements[
            "admin-audit-section"
        ].classList.toggle(
            "hidden",
            !hasPermission(
                PERMISSIONS.AUDIT
            )
        );
    }

    if (!authenticated) {
        currentRole = null;

        renderSessionActiveLabel(
            ""
        );

        elements[
            "session-identity"
        ].textContent =
            "ΓÇö";

        elements[
            "session-username"
        ].textContent =
            "ΓÇö";

        elements[
            "session-countdown"
        ].textContent =
            "ΓÇö";

        renderRoleBadge("");

        elements[
            "permission-strip"
        ].classList.add(
            "hidden"
        );

        elements[
            "audit-access-panel"
        ].classList.add(
            "hidden"
        );

        elements[
            "admin-audit-section"
        ].classList.add(
            "hidden"
        );

        elements[
            "active-action-panel"
        ].classList.add(
            "hidden"
        );

        elements[
            "revoke-denied-panel"
        ].classList.add(
            "hidden"
        );
    }

    setAuthMessage(
        authenticated
            ? `${roleLabel} session active.`
            : "Operator console is locked."
    );
}


function clearMessage() {
    elements[
        "message"
    ].textContent =
        "";

    elements[
        "message"
    ].classList.add(
        "hidden"
    );
}


function showMessage(
    message
) {
    elements[
        "message"
    ].textContent =
        message;

    elements[
        "message"
    ].classList.remove(
        "hidden"
    );
}


function formatDate(
    value
) {
    if (!value) {
        return "ΓÇö";
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return value;
    }

    return date.toLocaleString();
}


function extractOrganization(
    subject
) {
    if (!subject) {
        return "Unknown";
    }

    const match =
        subject.match(
            /(?:^|,)O=([^,]+)/
        );

    return match
        ? match[1]
        : subject;
}


function renderCredential(
    record
) {
    elements[
        "credential-name"
    ].textContent =
        record.common_name ||
        "Unknown credential";

    elements[
        "credential-organization"
    ].textContent =
        extractOrganization(
            record.subject
        );

    elements[
        "credential-common-name"
    ].textContent =
        record.common_name ||
        "ΓÇö";

    elements[
        "credential-key-id"
    ].textContent =
        record.key_id ||
        "ΓÇö";

    elements[
        "credential-serial"
    ].textContent =
        record.certificate_serial_number ||
        "ΓÇö";

    elements[
        "credential-issued"
    ].textContent =
        formatDate(
            record.issued_at
        );

    elements[
        "credential-expires"
    ].textContent =
        formatDate(
            record.expires_at
        );

    elements[
        "credential-revoked"
    ].textContent =
        formatDate(
            record.revoked_at
        );

    elements[
        "credential-reason"
    ].textContent =
        record.revocation_reason ||
        "ΓÇö";

    const status =
        String(
            record.status ||
            "UNKNOWN"
        ).toUpperCase();

    elements[
        "credential-status-badge"
    ].textContent =
        status;

    elements[
        "credential-status-badge"
    ].className =
        `credential-status ${status.toLowerCase()}`;

    const revoked =
        status === "REVOKED";

    const canRevoke =
        hasPermission(
            PERMISSIONS.REVOKE
        );

    elements[
        "active-action-panel"
    ].classList.toggle(
        "hidden",
        revoked || !canRevoke
    );

    elements[
        "revoke-denied-panel"
    ].classList.toggle(
        "hidden",
        revoked || canRevoke
    );

    elements[
        "revoked-state-panel"
    ].classList.toggle(
        "hidden",
        !revoked
    );

    if (revoked) {
        elements[
            "revoked-state-date"
        ].textContent =
            formatDate(
                record.revoked_at
            );

        elements[
            "revoked-state-reason"
        ].textContent =
            record.revocation_reason ||
            "No reason recorded.";
    }
}


function renderHistory(
    payload
) {
    elements[
        "history-list"
    ].innerHTML =
        "";

    const valid =
        payload.audit_chain_valid === true;

    elements[
        "audit-state"
    ].textContent =
        valid
            ? "AUDIT CHAIN VALID"
            : "AUDIT CHAIN INVALID";

    elements[
        "audit-state"
    ].className =
        `audit-badge ${
            valid
                ? "valid"
                : "invalid"
        }`;

    const events =
        Array.isArray(
            payload.events
        )
            ? payload.events
            : [];

    if (!events.length) {
        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "history-item";

        empty.textContent =
            "No audit events were found.";

        elements[
            "history-list"
        ].appendChild(
            empty
        );

        return;
    }

    for (
        const event of events
    ) {
        const item =
            document.createElement(
                "div"
            );

        item.className =
            "history-item";

        const top =
            document.createElement(
                "div"
            );

        top.className =
            "history-top";

        const name =
            document.createElement(
                "span"
            );

        name.className =
            "history-event";

        name.textContent =
            event.event_type ||
            "UNKNOWN";

        const time =
            document.createElement(
                "span"
            );

        time.className =
            "history-time";

        time.textContent =
            formatDate(
                event.event_time
            );

        top.appendChild(name);
        top.appendChild(time);

        const detail =
            document.createElement(
                "div"
            );

        detail.className =
            "history-detail";

        let text =
            event.payload_json ||
            "";

        try {
            const parsed =
                JSON.parse(
                    text
                );

            if (
                parsed.revocation_reason
            ) {
                text =
                    `Reason: ${parsed.revocation_reason}`;
            } else if (
                parsed.common_name
            ) {
                text =
                    `Credential: ${parsed.common_name}`;
            }
        } catch {
            // Preserve raw payload.
        }

        detail.textContent =
            text;

        item.appendChild(top);
        item.appendChild(detail);

        elements[
            "history-list"
        ].appendChild(
            item
        );
    }
}


function renderAdminAudit(
    payload
) {
    elements[
        "admin-audit-list"
    ].innerHTML =
        "";

    const valid =
        payload.audit_chain_valid === true;

    elements[
        "admin-audit-state"
    ].textContent =
        valid
            ? "AUDIT CHAIN VALID"
            : "AUDIT CHAIN INVALID";

    elements[
        "admin-audit-state"
    ].className =
        `audit-badge ${
            valid
                ? "valid"
                : "invalid"
        }`;

    const events =
        Array.isArray(
            payload.events
        )
            ? payload.events
            : [];

    if (!events.length) {
        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "history-item";

        empty.textContent =
            "No administrator actions recorded.";

        elements[
            "admin-audit-list"
        ].appendChild(
            empty
        );

        return;
    }

    for (
        const event of events
    ) {
        const item =
            document.createElement(
                "div"
            );

        item.className =
            "history-item";

        const top =
            document.createElement(
                "div"
            );

        top.className =
            "history-top";

        const name =
            document.createElement(
                "span"
            );

        name.className =
            "history-event";

        name.textContent =
            event.event_type ||
            "UNKNOWN";

        const time =
            document.createElement(
                "span"
            );

        time.className =
            "history-time";

        time.textContent =
            formatDate(
                event.event_time
            );

        top.appendChild(name);
        top.appendChild(time);

        const detail =
            document.createElement(
                "div"
            );

        detail.className =
            "history-detail";

        let text =
            `${event.identity || "Unknown operator"} ┬╖ ` +
            `${event.role || "UNKNOWN"}`;

        if (event.username) {
            text +=
                ` ┬╖ @${event.username}`;
        }

        if (
            event.certificate_serial_number
        ) {
            text +=
                ` ┬╖ Certificate ${event.certificate_serial_number}`;
        }

        if (event.reason) {
            text +=
                ` ┬╖ Reason: ${event.reason}`;
        }

        detail.textContent =
            text;

        item.appendChild(top);
        item.appendChild(detail);

        elements[
            "admin-audit-list"
        ].appendChild(
            item
        );
    }
}


async function authenticate() {
    const username =
        elements[
            "admin-username"
        ].value.trim();

    const password =
        elements[
            "admin-token"
        ].value;

    if (!username) {
        setAuthMessage(
            "Enter the administrator username.",
            true
        );

        elements[
            "admin-username"
        ].focus();

        return;
    }

    if (!password) {
        setAuthMessage(
            "Enter the administrator password.",
            true
        );

        elements[
            "admin-token"
        ].focus();

        return;
    }

    elements[
        "unlock-button"
    ].disabled =
        true;

    setAuthMessage(
        "Authenticating..."
    );

    try {
        const response =
            await fetch(
                `${API_BASE}/admin/login`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body: JSON.stringify({
                        username,
                        password,
                    }),
                }
            );

        let data = null;

        try {
            data =
                await response.json();
        } catch {
            // Empty response.
        }

        if (!response.ok) {
            const error =
                new Error(
                    data?.detail ||
                    "Administrator authentication failed."
                );

            error.status =
                response.status;

            throw error;
        }

        if (
            !data.authenticated ||
            !data.session_token
        ) {
            throw new Error(
                "AEGIS did not return a valid administrator session."
            );
        }

        sessionToken =
            data.session_token;

        sessionExpiresAt =
            Date.now()
            +
            (
                Number(
                    data.expires_in
                )
                * 1000
            );

        elements[
            "admin-username"
        ].value =
            "";

        elements[
            "admin-token"
        ].value =
            "";

        setAuthenticated(
            true,
            data
        );

        startSessionTimers();

        const serial =
            new URLSearchParams(
                window.location.search
            ).get(
                "serial"
            );

        if (serial) {
            elements[
                "serial-input"
            ].value =
                serial;

            await loadCredential(
                serial
            );
        }

        if (
            hasPermission(
                PERMISSIONS.AUDIT
            )
        ) {
            await loadAdminAudit();
        }
    } catch (error) {
        sessionToken = null;
        sessionExpiresAt = 0;

        stopSessionTimers();

        setAuthenticated(
            false
        );

        setAuthMessage(
            error instanceof Error
                ? error.message
                : "Administrator authentication failed.",
            true
        );
    } finally {
        elements[
            "unlock-button"
        ].disabled =
            false;
    }
}


async function validateServerSession() {
    if (!sessionToken) {
        return;
    }

    try {
        const data =
            await apiRequest(
                "/admin/session/validate",
                {
                    method: "POST",
                }
            );

        sessionExpiresAt =
            Date.now()
            +
            (
                Number(
                    data.expires_in
                )
                * 1000
            );

        currentRole =
            String(
                data.role || ""
            ).toUpperCase();

        renderSessionActiveLabel(
            currentRole
        );

        elements[
            "session-identity"
        ].textContent =
            data.identity ||
            "AEGIS Administrator";

        elements[
            "session-username"
        ].textContent =
            data.username
                ? `@${data.username}`
                : "ΓÇö";

        renderRoleBadge(
            currentRole
        );

        renderPermissions();

        elements[
            "audit-access-panel"
        ].classList.toggle(
            "hidden",
            !hasPermission(
                PERMISSIONS.AUDIT
            )
        );

        elements[
            "admin-audit-section"
        ].classList.toggle(
            "hidden",
            !hasPermission(
                PERMISSIONS.AUDIT
            )
        );

        updateCountdown();
    } catch (error) {
        if (
            error.status === 401
        ) {
            expireSession(
                "Authenticated session expired."
            );
        }
    }
}


function expireSession(
    message
) {
    sessionToken = null;
    sessionExpiresAt = 0;
    currentSerial = null;
    currentRole = null;

    stopSessionTimers();

    elements[
        "admin-username"
    ].value =
        "";

    elements[
        "admin-token"
    ].value =
        "";

    elements[
        "serial-input"
    ].value =
        "";

    elements[
        "credential-section"
    ].classList.add(
        "hidden"
    );

    elements[
        "login-form"
    ].classList.remove(
        "hidden"
    );

    elements[
        "authenticated-controls"
    ].classList.add(
        "hidden"
    );

    clearMessage();

    setAuthenticated(
        false
    );

    setAuthMessage(
        message,
        true
    );
}


async function lockSession() {
    if (sessionToken) {
        try {
            await apiRequest(
                "/admin/session/revoke",
                {
                    method: "POST",
                }
            );
        } catch {
            // Continue local lock.
        }
    }

    expireSession(
        "Authenticated session locked."
    );
}


async function loadCredential(
    serial
) {
    const normalized =
        String(
            serial || ""
        ).trim();

    if (!normalized) {
        showMessage(
            "Enter a certificate serial number."
        );

        return;
    }

    if (!sessionToken) {
        setAuthMessage(
            "Authenticate before inspecting credentials.",
            true
        );

        return;
    }

    if (
        !hasPermission(
            PERMISSIONS.READ
        )
    ) {
        showMessage(
            "Your administrator role does not permit credential inspection."
        );

        return;
    }

    clearMessage();

    try {
        const credentialResponse =
            await apiRequest(
                `/credentials/${encodeURIComponent(
                    normalized
                )}`
            );

        currentSerial =
            normalized;

        renderCredential(
            credentialResponse.credential
        );

        elements[
            "credential-section"
        ].classList.remove(
            "hidden"
        );

        if (
            hasPermission(
                PERMISSIONS.AUDIT
            )
        ) {
            const historyResponse =
                await apiRequest(
                    `/credentials/${encodeURIComponent(
                        normalized
                    )}/history`
                );

            renderHistory(
                historyResponse
            );

            elements[
                "audit-access-panel"
            ].classList.remove(
                "hidden"
            );
        } else {
            elements[
                "audit-access-panel"
            ].classList.add(
                "hidden"
            );
        }
    } catch (error) {
        if (
            error.status === 401
        ) {
            expireSession(
                "Authenticated session expired."
            );

            return;
        }

        if (
            error.status === 403
        ) {
            showMessage(
                "Your administrator role does not permit credential inspection."
            );

            return;
        }

        showMessage(
            error instanceof Error
                ? error.message
                : "Unable to load credential."
        );
    }
}


async function loadAdminAudit() {
    if (
        !sessionToken ||
        !hasPermission(
            PERMISSIONS.AUDIT
        )
    ) {
        return;
    }

    try {
        const payload =
            await apiRequest(
                "/admin/audit"
            );

        renderAdminAudit(
            payload
        );
    } catch (error) {
        if (
            error.status === 401
        ) {
            expireSession(
                "Authenticated session expired."
            );

            return;
        }

        if (
            error.status === 403
        ) {
            elements[
                "admin-audit-section"
            ].classList.add(
                "hidden"
            );
        }
    }
}


async function revokeCurrentCredential() {
    if (!currentSerial) {
        showMessage(
            "Load a credential before attempting revocation."
        );

        return;
    }

    if (
        !hasPermission(
            PERMISSIONS.REVOKE
        )
    ) {
        showMessage(
            "Your administrator role does not permit credential revocation."
        );

        return;
    }

    const reason =
        elements[
            "reason-input"
        ].value.trim();

    if (!reason) {
        showMessage(
            "A revocation reason is required."
        );

        elements[
            "reason-input"
        ].focus();

        return;
    }

    const confirmed =
        window.confirm(
            "Revoke this credential now?\n\n" +
            "New AEGIS verification attempts will return " +
            "REVOKED_CREDENTIAL."
        );

    if (!confirmed) {
        return;
    }

    elements[
        "revoke-button"
    ].disabled =
        true;

    try {
        await apiRequest(
            `/credentials/${encodeURIComponent(
                currentSerial
            )}/revoke`,
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json",
                },

                body: JSON.stringify({
                    reason,
                }),
            }
        );

        elements[
            "reason-input"
        ].value =
            "";

        await loadCredential(
            currentSerial
        );

        await loadAdminAudit();
    } catch (error) {
        if (
            error.status === 401
        ) {
            expireSession(
                "Authenticated session expired."
            );

            return;
        }

        if (
            error.status === 403
        ) {
            showMessage(
                "Your administrator role does not permit credential revocation."
            );

            return;
        }

        if (
            error.status === 409
        ) {
            showMessage(
                "Credential is already revoked."
            );

            await loadCredential(
                currentSerial
            );

            return;
        }

        showMessage(
            error instanceof Error
                ? error.message
                : "Unable to revoke credential."
        );
    } finally {
        elements[
            "revoke-button"
        ].disabled =
            false;
    }
}


function initialize() {
    getElements();
    assertElements();

    elements[
        "unlock-button"
    ].addEventListener(
        "click",
        authenticate
    );

    elements[
        "admin-username"
    ].addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Enter"
            ) {
                event.preventDefault();

                elements[
                    "admin-token"
                ].focus();
            }
        }
    );

    elements[
        "admin-token"
    ].addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Enter"
            ) {
                event.preventDefault();

                authenticate();
            }
        }
    );

    elements[
        "lock-button"
    ].addEventListener(
        "click",
        lockSession
    );

    elements[
        "lookup-button"
    ].addEventListener(
        "click",
        () => {
            loadCredential(
                elements[
                    "serial-input"
                ].value
            );
        }
    );

    elements[
        "serial-input"
    ].addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Enter"
            ) {
                event.preventDefault();

                loadCredential(
                    elements[
                        "serial-input"
                    ].value
                );
            }
        }
    );

    elements[
        "revoke-button"
    ].addEventListener(
        "click",
        revokeCurrentCredential
    );

    setAuthenticated(
        false
    );

    checkApi();
}


window.addEventListener(
    "DOMContentLoaded",
    () => {
        try {
            initialize();
        } catch (error) {
            console.error(
                "AEGIS admin initialization failed:",
                error
            );

            window.alert(
                error instanceof Error
                    ? error.message
                    : "AEGIS admin initialization failed."
            );
        }
    }
);
