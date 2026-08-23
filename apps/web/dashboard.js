"use strict";

const API_BASE =
    "http://127.0.0.1:8000";

const PERMISSIONS = Object.freeze({
    READ: "credential.read",
    AUDIT: "audit.read",
    REVOKE: "credential.revoke",
    ADMIN: "admin.manage",
});

const elements = {
    apiDot:
        document.getElementById("api-dot"),

    apiStatus:
        document.getElementById("api-status"),

    loginPanel:
        document.getElementById("login-panel"),

    loginStatus:
        document.getElementById("login-status"),

    usernameInput:
        document.getElementById(
            "username-input"
        ),

    passwordInput:
        document.getElementById(
            "password-input"
        ),

    loginButton:
        document.getElementById(
            "login-button"
        ),

    loginMessage:
        document.getElementById(
            "login-message"
        ),

    dashboardContent:
        document.getElementById(
            "dashboard-content"
        ),

    operatorIdentity:
        document.getElementById(
            "operator-identity"
        ),

    operatorUsername:
        document.getElementById(
            "operator-username"
        ),

    operatorRole:
        document.getElementById(
            "operator-role"
        ),

    sessionCountdown:
        document.getElementById(
            "session-countdown"
        ),

    logoutButton:
        document.getElementById(
            "logout-button"
        ),

    metricApi:
        document.getElementById(
            "metric-api"
        ),

    metricAudit:
        document.getElementById(
            "metric-audit"
        ),

    metricEvents:
        document.getElementById(
            "metric-events"
        ),

    metricRole:
        document.getElementById(
            "metric-role"
        ),

    capabilityGrid:
        document.getElementById(
            "capability-grid"
        ),

    auditState:
        document.getElementById(
            "audit-state"
        ),

    auditList:
        document.getElementById(
            "audit-list"
        ),

    refreshAuditButton:
        document.getElementById(
            "refresh-audit-button"
        ),
};


let sessionToken = null;
let sessionExpiresAt = 0;
let currentRole = null;

let countdownTimer = null;
let validationTimer = null;


function validateElements() {
    for (
        const [
            name,
            element,
        ]
        of Object.entries(elements)
    ) {
        if (!element) {
            throw new Error(
                `Missing dashboard element: ${name}`
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
                `${API_BASE}/health`,
                {
                    cache: "no-store",
                }
            );

        if (!response.ok) {
            throw new Error();
        }

        elements.apiDot.className =
            "status-dot online";

        elements.apiStatus.textContent =
            "API online";

        elements.metricApi.textContent =
            "ONLINE";

        elements.metricApi.className =
            "metric-value good";
    } catch {
        elements.apiDot.className =
            "status-dot offline";

        elements.apiStatus.textContent =
            "API offline";

        elements.metricApi.textContent =
            "OFFLINE";

        elements.metricApi.className =
            "metric-value";
    }
}


function setLoginMessage(
    message,
    error = false
) {
    elements.loginMessage.textContent =
        message;

    elements.loginMessage.className =
        error
            ? "login-message error"
            : "login-message";
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
        elements.sessionCountdown.textContent =
            "—";

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

    elements.sessionCountdown.textContent =
        formatDuration(
            remaining
        );

    elements.sessionCountdown.style.color =
        remaining <= 60
            ? "var(--red)"
            : "var(--accent)";

    if (
        remaining <= 0
    ) {
        lockSession(
            "Command Center session expired."
        );
    }
}


function startTimers() {
    stopTimers();

    updateCountdown();

    countdownTimer =
        window.setInterval(
            updateCountdown,
            1000
        );

    validationTimer =
        window.setInterval(
            validateSession,
            30000
        );
}


function stopTimers() {
    if (countdownTimer) {
        window.clearInterval(
            countdownTimer
        );

        countdownTimer = null;
    }

    if (validationTimer) {
        window.clearInterval(
            validationTimer
        );

        validationTimer = null;
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


function renderRole(
    role
) {
    const normalized =
        String(
            role || ""
        ).toUpperCase();

    elements.operatorRole.textContent =
        normalized || "—";

    elements.operatorRole.className =
        normalized
            ? `role-badge ${normalized.toLowerCase()}`
            : "role-badge";

    elements.metricRole.textContent =
        normalized || "—";
}


function renderCapabilities() {
    const items = [
        {
            permission:
                PERMISSIONS.READ,

            label:
                "Credential read",
        },

        {
            permission:
                PERMISSIONS.AUDIT,

            label:
                "Audit read",
        },

        {
            permission:
                PERMISSIONS.REVOKE,

            label:
                "Credential revoke",
        },

        {
            permission:
                PERMISSIONS.ADMIN,

            label:
                "Admin management",
        },
    ];

    elements.capabilityGrid.innerHTML =
        "";

    const permissions =
        rolePermissions(
            currentRole
        );

    for (
        const item
        of items
    ) {
        const allowed =
            permissions.has(
                item.permission
            );

        const card =
            document.createElement(
                "div"
            );

        card.className =
            `capability-item ${
                allowed
                    ? "allowed"
                    : "denied"
            }`;

        const top =
            document.createElement(
                "div"
            );

        top.className =
            "capability-top";

        const dot =
            document.createElement(
                "span"
            );

        dot.className =
            `capability-dot ${
                allowed
                    ? "allowed"
                    : "denied"
            }`;

        const name =
            document.createElement(
                "span"
            );

        name.className =
            "capability-name";

        name.textContent =
            item.label;

        top.appendChild(dot);
        top.appendChild(name);

        const state =
            document.createElement(
                "div"
            );

        state.className =
            "capability-state";

        state.textContent =
            allowed
                ? "PERMITTED"
                : "NOT PERMITTED";

        card.appendChild(top);
        card.appendChild(state);

        elements.capabilityGrid.appendChild(
            card
        );
    }
}


function formatDate(
    value
) {
    if (!value) {
        return "—";
    }

    const date =
        new Date(
            value
        );

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return value;
    }

    return date.toLocaleString();
}


function renderAudit(
    payload
) {
    const valid =
        payload.audit_chain_valid === true;

    elements.metricAudit.textContent =
        valid
            ? "VALID"
            : "INVALID";

    elements.metricAudit.className =
        valid
            ? "metric-value good"
            : "metric-value";

    elements.auditState.textContent =
        valid
            ? "AUDIT CHAIN VALID"
            : "AUDIT CHAIN INVALID";

    const events =
        Array.isArray(
            payload.events
        )
            ? payload.events
            : [];

    elements.metricEvents.textContent =
        String(
            events.length
        );

    elements.auditList.innerHTML =
        "";

    if (!events.length) {
        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "audit-item";

        empty.textContent =
            "No administrator audit events were recorded.";

        elements.auditList.appendChild(
            empty
        );

        return;
    }

    const recentEvents =
        [...events]
            .reverse()
            .slice(
                0,
                20
            );

    for (
        const event
        of recentEvents
    ) {
        const item =
            document.createElement(
                "div"
            );

        item.className =
            "audit-item";

        const top =
            document.createElement(
                "div"
            );

        top.className =
            "audit-top";

        const type =
            document.createElement(
                "span"
            );

        type.className =
            "audit-event";

        type.textContent =
            event.event_type ||
            "UNKNOWN";

        const time =
            document.createElement(
                "span"
            );

        time.className =
            "audit-time";

        time.textContent =
            formatDate(
                event.event_time
            );

        top.appendChild(type);
        top.appendChild(time);

        const detail =
            document.createElement(
                "div"
            );

        detail.className =
            "audit-detail";

        let text =
            `${event.identity || "Unknown operator"} · ` +
            `${event.role || "UNKNOWN"}`;

        if (event.username) {
            text +=
                ` · @${event.username}`;
        }

        if (
            event.certificate_serial_number
        ) {
            text +=
                ` · Certificate ${event.certificate_serial_number}`;
        }

        if (event.reason) {
            text +=
                ` · Reason: ${event.reason}`;
        }

        detail.textContent =
            text;

        item.appendChild(top);
        item.appendChild(detail);

        elements.auditList.appendChild(
            item
        );
    }
}


async function loadAudit() {
    if (!sessionToken) {
        return;
    }

    if (
        !hasPermission(
            PERMISSIONS.AUDIT
        )
    ) {
        elements.metricAudit.textContent =
            "RESTRICTED";

        elements.metricAudit.className =
            "metric-value";

        elements.auditState.textContent =
            "AUDIT ACCESS RESTRICTED";

        elements.auditList.innerHTML =
            "";

        const restricted =
            document.createElement(
                "div"
            );

        restricted.className =
            "audit-item";

        restricted.textContent =
            `The ${currentRole} role does not permit audit.read.`;

        elements.auditList.appendChild(
            restricted
        );

        return;
    }

    try {
        const payload =
            await apiRequest(
                "/admin/audit"
            );

        renderAudit(
            payload
        );
    } catch (error) {
        if (
            error.status === 401
        ) {
            lockSession(
                "Command Center session expired."
            );

            return;
        }

        elements.auditState.textContent =
            "AUDIT UNAVAILABLE";

        elements.metricAudit.textContent =
            "ERROR";

        elements.metricEvents.textContent =
            "—";
    }
}


function showDashboard(
    session
) {
    elements.loginPanel.classList.add(
        "hidden"
    );

    elements.dashboardContent.classList.remove(
        "hidden"
    );

    elements.loginStatus.textContent =
        "AUTHENTICATED";

    elements.loginStatus.className =
        "state-badge authenticated";

    elements.operatorIdentity.textContent =
        session.identity ||
        "AEGIS Administrator";

    elements.operatorUsername.textContent =
        session.username
            ? `@${session.username}`
            : "—";

    currentRole =
        String(
            session.role || ""
        ).toUpperCase();

    renderRole(
        currentRole
    );

    renderCapabilities();

    setLoginMessage(
        "Command Center session active."
    );
}


function showLogin() {
    elements.loginPanel.classList.remove(
        "hidden"
    );

    elements.dashboardContent.classList.add(
        "hidden"
    );

    elements.loginStatus.textContent =
        "LOCKED";

    elements.loginStatus.className =
        "state-badge locked";

    currentRole = null;

    elements.operatorIdentity.textContent =
        "—";

    elements.operatorUsername.textContent =
        "—";

    elements.operatorRole.textContent =
        "—";

    elements.operatorRole.className =
        "role-badge";

    elements.metricRole.textContent =
        "—";

    elements.sessionCountdown.textContent =
        "15:00";

    elements.capabilityGrid.innerHTML =
        "";

    setLoginMessage(
        "Command Center is locked."
    );
}


async function authenticate() {
    const username =
        elements.usernameInput.value.trim();

    const password =
        elements.passwordInput.value;

    if (!username) {
        setLoginMessage(
            "Enter the administrator username.",
            true
        );

        elements.usernameInput.focus();

        return;
    }

    if (!password) {
        setLoginMessage(
            "Enter the administrator password.",
            true
        );

        elements.passwordInput.focus();

        return;
    }

    elements.loginButton.disabled =
        true;

    setLoginMessage(
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

        elements.usernameInput.value =
            "";

        elements.passwordInput.value =
            "";

        showDashboard(
            data
        );

        startTimers();

        await loadAudit();
    } catch (error) {
        setLoginMessage(
            error instanceof Error
                ? error.message
                : "Administrator authentication failed.",
            true
        );
    } finally {
        elements.loginButton.disabled =
            false;
    }
}


async function validateSession() {
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

        elements.operatorIdentity.textContent =
            data.identity ||
            "AEGIS Administrator";

        elements.operatorUsername.textContent =
            data.username
                ? `@${data.username}`
                : "—";

        renderRole(
            currentRole
        );

        renderCapabilities();

        updateCountdown();
    } catch (error) {
        if (
            error.status === 401
        ) {
            lockSession(
                "Command Center session expired."
            );
        }
    }
}


async function lockSession(
    message =
        "Command Center session locked."
) {
    if (sessionToken) {
        try {
            await apiRequest(
                "/admin/session/revoke",
                {
                    method: "POST",
                }
            );
        } catch {
            // Local lock still applies.
        }
    }

    sessionToken = null;
    sessionExpiresAt = 0;
    currentRole = null;

    stopTimers();

    showLogin();

    setLoginMessage(
        message,
        true
    );
}


function initialize() {
    validateElements();

    elements.loginButton.addEventListener(
        "click",
        authenticate
    );

    elements.usernameInput.addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Enter"
            ) {
                event.preventDefault();

                elements.passwordInput.focus();
            }
        }
    );

    elements.passwordInput.addEventListener(
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

    elements.logoutButton.addEventListener(
        "click",
        () => {
            lockSession();
        }
    );

    elements.refreshAuditButton.addEventListener(
        "click",
        () => {
            loadAudit();
        }
    );

    showLogin();

    checkApi();

    window.setInterval(
        checkApi,
        15000
    );
}


try {
    initialize();
} catch (error) {
    console.error(
        "AEGIS Command Center initialization failed:",
        error
    );

    window.alert(
        error instanceof Error
            ? error.message
            : "AEGIS Command Center initialization failed."
    );
}