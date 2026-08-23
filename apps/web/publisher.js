"use strict";

const API_BASE =
    window.location.hostname === "127.0.0.1" &&
    window.location.port === "3000"
        ? "http://127.0.0.1:8000"
        : "/api";
const state = {
    token: sessionStorage.getItem(
        "aegis_publisher_token"
    ),

    publisher: null,

    notices: [],

    selectedNoticeId: null,
};


const elements = {};


function getElements() {
    elements.loginView =
        document.getElementById(
            "login-view"
        );

    elements.consoleView =
        document.getElementById(
            "console-view"
        );

    elements.loginForm =
        document.getElementById(
            "login-form"
        );

    elements.loginUsername =
        document.getElementById(
            "login-username"
        );

    elements.loginPassword =
        document.getElementById(
            "login-password"
        );

    elements.loginButton =
        document.getElementById(
            "login-button"
        );

    elements.loginMessage =
        document.getElementById(
            "login-message"
        );

    elements.apiDot =
        document.getElementById(
            "api-dot"
        );

    elements.apiStatus =
        document.getElementById(
            "api-status"
        );

    elements.roleBadge =
        document.getElementById(
            "role-badge"
        );

    elements.identityName =
        document.getElementById(
            "identity-name"
        );

    elements.identityDetails =
        document.getElementById(
            "identity-details"
        );

    elements.logoutButton =
        document.getElementById(
            "logout-button"
        );

    elements.globalMessage =
        document.getElementById(
            "global-message"
        );

    elements.noticeForm =
        document.getElementById(
            "notice-form"
        );

    elements.noticeId =
        document.getElementById(
            "notice-id"
        );

    elements.editorTitle =
        document.getElementById(
            "editor-title"
        );

    elements.newNoticeButton =
        document.getElementById(
            "new-notice-button"
        );

    elements.noticeTitle =
        document.getElementById(
            "notice-title"
        );

    elements.noticeType =
        document.getElementById(
            "notice-type"
        );

    elements.noticeAudience =
        document.getElementById(
            "notice-audience"
        );

    elements.noticeSummary =
        document.getElementById(
            "notice-summary"
        );

    elements.noticeContent =
        document.getElementById(
            "notice-content"
        );

    elements.noticeExpiry =
        document.getElementById(
            "notice-expiry"
        );

    elements.noticeFile =
        document.getElementById(
            "notice-file"
        );

    elements.policyValue =
        document.getElementById(
            "policy-value"
        );

    elements.policyDescription =
        document.getElementById(
            "policy-description"
        );

    elements.saveButton =
        document.getElementById(
            "save-button"
        );

    elements.submitButton =
        document.getElementById(
            "submit-button"
        );

    elements.publishButton =
        document.getElementById(
            "publish-button"
        );

    elements.approveButton =
        document.getElementById(
            "approve-button"
        );

    elements.editorMessage =
        document.getElementById(
            "editor-message"
        );

    elements.refreshButton =
        document.getElementById(
            "refresh-button"
        );

    elements.noticeList =
        document.getElementById(
            "notice-list"
        );
}


function showMessage(
    element,
    message,
    type = "info"
) {
    element.textContent =
        message;

    element.classList.remove(
        "hidden",
        "error",
        "success",
        "info"
    );

    if (type) {
        element.classList.add(
            type
        );
    }
}


function hideMessage(
    element
) {
    element.textContent = "";

    element.classList.add(
        "hidden"
    );

    element.classList.remove(
        "error",
        "success",
        "info"
    );
}


function setApiStatus(
    online
) {
    elements.apiDot.classList.toggle(
        "online",
        online
    );

    elements.apiDot.classList.toggle(
        "offline",
        !online
    );

    elements.apiStatus.textContent =
        online
            ? "API online"
            : "API offline";
}


async function request(
    path,
    options = {}
) {
    const headers = new Headers(
        options.headers || {}
    );

    if (
        state.token
    ) {
        headers.set(
            "Authorization",
            `Bearer ${state.token}`
        );
    }

    const response =
        await fetch(
            `${API_BASE}${path}`,
            {
                ...options,
                headers,
                cache: "no-store",
            }
        );

    let data = null;

    const contentType =
        response.headers.get(
            "content-type"
        ) || "";

    if (
        contentType.includes(
            "application/json"
        )
    ) {
        try {
            data =
                await response.json();
        } catch {
            data = null;
        }
    }

    if (
        response.status === 401
    ) {
        clearSession();

        throw new Error(
            "Publisher session expired. Please sign in again."
        );
    }

    if (
        !response.ok
    ) {
        const detail =
            data &&
            data.detail;

        if (
            typeof detail === "string"
        ) {
            throw new Error(
                detail
            );
        }

        throw new Error(
            "AEGIS API request failed."
        );
    }

    setApiStatus(
        true
    );

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

        setApiStatus(
            response.ok
        );
    } catch {
        setApiStatus(
            false
        );
    }
}


function clearSession() {
    sessionStorage.removeItem(
        "aegis_publisher_token"
    );

    state.token = null;
    state.publisher = null;

    showLogin();
}


function showLogin() {
    elements.loginView.classList.remove(
        "hidden"
    );

    elements.consoleView.classList.add(
        "hidden"
    );

    elements.loginPassword.value = "";

    hideMessage(
        elements.loginMessage
    );
}


function showConsole() {
    elements.loginView.classList.add(
        "hidden"
    );

    elements.consoleView.classList.remove(
        "hidden"
    );

    if (
        state.publisher
    ) {
        elements.identityName.textContent =
            state.publisher.identity;

        elements.identityDetails.textContent =
            `${state.publisher.organization} · ${state.publisher.role}`;

        elements.roleBadge.textContent =
            state.publisher.role;
    }

    updateEditorPolicy();
}


async function login(
    event
) {
    event.preventDefault();

    const username =
        elements.loginUsername.value.trim();

    const password =
        elements.loginPassword.value;

    hideMessage(
        elements.loginMessage
    );

    if (
        !username ||
        !password
    ) {
        showMessage(
            elements.loginMessage,
            "Username and password are required.",
            "error"
        );

        return;
    }

    elements.loginButton.disabled =
        true;

    elements.loginButton.textContent =
        "Signing in...";

    try {
        const data =
            await request(
                "/publisher/login",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                    },
                    body: JSON.stringify(
                        {
                            username,
                            password,
                        }
                    ),
                }
            );

        state.token =
            data.session_token;

        state.publisher = {
            publisher_id:
                data.publisher_id,

            username:
                data.username,

            identity:
                data.identity,

            organization:
                data.organization,

            role:
                data.role,

            expires_in:
                data.expires_in,
        };

        sessionStorage.setItem(
            "aegis_publisher_token",
            state.token
        );

        showConsole();

        await loadNotices();

    } catch (error) {
        showMessage(
            elements.loginMessage,
            error instanceof Error
                ? error.message
                : "Unable to sign in.",
            "error"
        );

    } finally {
        elements.loginButton.disabled =
            false;

        elements.loginButton.textContent =
            "Sign in";
    }
}


async function validateSession() {
    if (
        !state.token
    ) {
        return false;
    }

    try {
        const data =
            await request(
                "/publisher/session/validate",
                {
                    method: "POST",
                }
            );

        state.publisher = {
            publisher_id:
                data.publisher_id,

            username:
                data.username,

            identity:
                data.identity,

            organization:
                data.organization,

            role:
                data.role,

            expires_in:
                data.expires_in,
        };

        return true;

    } catch {
        return false;
    }
}


async function logout() {
    try {
        if (
            state.token
        ) {
            await request(
                "/publisher/session/revoke",
                {
                    method: "POST",
                }
            );
        }
    } catch {
        // Session is cleared locally regardless.
    }

    clearSession();
}


function normalizeNoticeType(
    value
) {
    return String(
        value || ""
    )
        .trim()
        .toLowerCase();
}


function getPublicationPolicy(
    noticeType
) {
    const normalized =
        normalizeNoticeType(
            noticeType
        );

    if (
        [
            "emergency",
            "safety",
            "general",
            "general announcement",
        ].includes(
            normalized
        )
    ) {
        return "DIRECT";
    }

    return "APPROVAL_REQUIRED";
}


function updateEditorPolicy(
    notice = null
) {
    const noticeType =
        notice
            ? notice.notice_type
            : elements.noticeType.value;

    const policy =
        notice
            ? notice.publication_policy
            : getPublicationPolicy(
                noticeType
            );

    elements.policyValue.textContent =
        policy;

    if (
        policy === "DIRECT"
    ) {
        elements.policyValue.style.color =
            "var(--accent)";

        elements.policyDescription.textContent =
            "This communication may be signed and published directly by an authorized publisher.";

    } else {
        elements.policyValue.style.color =
            "var(--amber)";

        elements.policyDescription.textContent =
            "This communication must be approved by an authorized approver before it can be signed and published.";
    }

    updateActionButtons(
        notice
    );
}


function updateActionButtons(
    notice = null
) {
    const role =
        state.publisher
            ? state.publisher.role
            : null;

    const exists =
        Boolean(
            notice &&
            notice.notice_id
        );

    const status =
        notice
            ? notice.status
            : "DRAFT";

    const policy =
        notice
            ? notice.publication_policy
            : getPublicationPolicy(
                elements.noticeType.value
            );

    const publisher =
        role === "PUBLISHER";

    const approver =
        role === "APPROVER" ||
        role === "NOTICE_ADMIN";

    const admin =
        role === "NOTICE_ADMIN";

    const canEdit =
        !exists ||
        (
            publisher &&
            status === "DRAFT" &&
            notice.author_id ===
                state.publisher.publisher_id
        );

    elements.saveButton.classList.toggle(
        "hidden",
        !canEdit
    );

    elements.saveButton.disabled =
        !canEdit;

    const canSubmit =
        publisher &&
        exists &&
        notice.author_id ===
            state.publisher.publisher_id &&
        status === "DRAFT" &&
        policy === "APPROVAL_REQUIRED";

    elements.submitButton.classList.toggle(
        "hidden",
        !canSubmit
    );

    const canPublish =
        (
            publisher ||
            admin
        ) &&
        exists &&
        (
            (
                policy === "DIRECT" &&
                status === "DRAFT"
            )
            ||
            (
                policy === "APPROVAL_REQUIRED" &&
                status === "APPROVED"
            )
        );

    elements.publishButton.classList.toggle(
        "hidden",
        !canPublish
    );

    const canApprove =
        approver &&
        exists &&
        policy === "APPROVAL_REQUIRED" &&
        status === "READY_FOR_APPROVAL";

    elements.approveButton.classList.toggle(
        "hidden",
        !canApprove
    );
}


function resetEditor() {
    state.selectedNoticeId =
        null;

    elements.noticeId.value =
        "";

    elements.editorTitle.textContent =
        "New notice";

    elements.noticeTitle.value =
        "";

    elements.noticeType.value =
        "Emergency";

    elements.noticeAudience.value =
        "ALL";

    elements.noticeSummary.value =
        "";

    elements.noticeContent.value =
        "";

    elements.noticeExpiry.value =
        "";

    elements.noticeFile.value =
        "";

    hideMessage(
        elements.editorMessage
    );

    updateEditorPolicy(
        null
    );
}


function toDateTimeLocal(
    value
) {
    if (
        !value
    ) {
        return "";
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
        return "";
    }

    const pad =
        (number) =>
            String(number)
                .padStart(
                    2,
                    "0"
                );

    return [
        date.getFullYear(),
        "-",
        pad(
            date.getMonth() + 1
        ),
        "-",
        pad(
            date.getDate()
        ),
        "T",
        pad(
            date.getHours()
        ),
        ":",
        pad(
            date.getMinutes()
        ),
    ].join("");
}


function toIsoDateTime(
    value
) {
    if (
        !value
    ) {
        return null;
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
        return null;
    }

    return date.toISOString();
}


function loadNoticeIntoEditor(
    notice
) {
    state.selectedNoticeId =
        notice.notice_id;

    elements.noticeId.value =
        notice.notice_id;

    elements.editorTitle.textContent =
        "Edit notice";

    elements.noticeTitle.value =
        notice.title || "";

    elements.noticeType.value =
        notice.notice_type || "General";

    elements.noticeAudience.value =
        notice.audience || "ALL";

    elements.noticeSummary.value =
        notice.summary || "";

    elements.noticeContent.value =
        notice.content || "";

    elements.noticeExpiry.value =
        toDateTimeLocal(
            notice.expires_at
        );

    elements.noticeFile.value =
        "";

    hideMessage(
        elements.editorMessage
    );

    updateEditorPolicy(
        notice
    );

    renderNoticeList();
}


async function loadNotice(
    noticeId
) {
    const data =
        await request(
            `/notices/${encodeURIComponent(
                noticeId
            )}`
        );

    loadNoticeIntoEditor(
        data.notice
    );
}


async function loadNotices() {
    try {
        elements.noticeList.innerHTML =
            `<div class="empty-state">
                Loading notices...
            </div>`;

        const data =
            await request(
                "/notices"
            );

        state.notices =
            Array.isArray(
                data.notices
            )
                ? data.notices
                : [];

        renderNoticeList();

    } catch (error) {
        showMessage(
            elements.globalMessage,
            error instanceof Error
                ? error.message
                : "Unable to load notices.",
            "error"
        );

        elements.noticeList.innerHTML =
            `<div class="empty-state">
                Unable to load notices.
            </div>`;
    }
}


function statusClass(
    status
) {
    switch (
        status
    ) {
        case "PUBLISHED":
            return "published";

        case "APPROVED":
            return "approved";

        case "READY_FOR_APPROVAL":
            return "pending";

        case "REVOKED":
            return "revoked";

        case "DRAFT":
        default:
            return "draft";
    }
}


function policyClass(
    policy
) {
    return policy ===
        "DIRECT"
        ? "direct"
        : "approval";
}


function escapeHtml(
    value
) {
    return String(
        value ?? ""
    )
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}


function formatDate(
    value
) {
    if (
        !value
    ) {
        return "";
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
        return "";
    }

    return date.toLocaleString();
}


function renderNoticeList() {
    if (
        !state.notices.length
    ) {
        elements.noticeList.innerHTML =
            `<div class="empty-state">
                No communications found.
            </div>`;

        return;
    }

    elements.noticeList.innerHTML =
        state.notices
            .map(
                (notice) => {
                    const active =
                        notice.notice_id ===
                        state.selectedNoticeId
                            ? " active"
                            : "";

                    const policy =
                        policyClass(
                            notice.publication_policy
                        );

                    const status =
                        statusClass(
                            notice.status
                        );

                    const summary =
                        notice.summary ||
                        notice.content.slice(
                            0,
                            180
                        );

                    const publishedUrl =
                        notice.signed_asset_url &&
                        notice.status ===
                            "PUBLISHED"
                            ? notice.signed_asset_url
                            : "";

                    return `
                        <article
                            class="notice-card${active}"
                            data-notice-id="${escapeHtml(
                                notice.notice_id
                            )}"
                        >
                            <div class="notice-title">
                                ${escapeHtml(
                                    notice.title
                                )}
                            </div>

                            <div class="notice-meta">
                                <span class="badge ${policy}">
                                    ${escapeHtml(
                                        notice.publication_policy
                                    )}
                                </span>

                                <span class="badge ${status}">
                                    ${escapeHtml(
                                        notice.status
                                    )}
                                </span>

                                <span class="badge">
                                    ${escapeHtml(
                                        notice.notice_type
                                    )}
                                </span>
                            </div>

                            <div class="notice-summary">
                                ${escapeHtml(
                                    summary
                                )}
                            </div>

                            <div class="notice-date">
                                Updated:
                                ${escapeHtml(
                                    formatDate(
                                        notice.updated_at
                                    )
                                )}
                            </div>

                            ${
                                publishedUrl
                                    ? `
                                        <a
                                            class="published-link"
                                            href="${escapeHtml(
                                                publishedUrl
                                            )}"
                                            target="_blank"
                                            rel="noopener"
                                            onclick="event.stopPropagation()"
                                        >
                                            Open published asset
                                        </a>
                                    `
                                    : ""
                            }
                        </article>
                    `;
                }
            )
            .join("");

    elements.noticeList
        .querySelectorAll(
            ".notice-card"
        )
        .forEach(
            (card) => {
                card.addEventListener(
                    "click",
                    () => {
                        const id =
                            card.dataset.noticeId;

                        if (
                            id
                        ) {
                            loadNotice(
                                id
                            ).catch(
                                (error) => {
                                    showMessage(
                                        elements.globalMessage,
                                        error instanceof Error
                                            ? error.message
                                            : "Unable to load notice.",
                                        "error"
                                    );
                                }
                            );
                        }
                    }
                );
            }
        );
}


function noticePayload() {
    return {
        title:
            elements.noticeTitle.value.trim(),

        notice_type:
            elements.noticeType.value.trim(),

        summary:
            elements.noticeSummary.value.trim(),

        content:
            elements.noticeContent.value.trim(),

        audience:
            elements.noticeAudience.value.trim(),

        expires_at:
            toIsoDateTime(
                elements.noticeExpiry.value
            ),
    };
}


async function saveNotice(
    event
) {
    event.preventDefault();

    const noticeId =
        elements.noticeId.value.trim();

    const payload =
        noticePayload();

    hideMessage(
        elements.editorMessage
    );

    elements.saveButton.disabled =
        true;

    try {
        let data;

        if (
            noticeId
        ) {
            data =
                await request(
                    `/notices/${encodeURIComponent(
                        noticeId
                    )}`,
                    {
                        method: "PUT",
                        headers: {
                            "Content-Type":
                                "application/json",
                        },
                        body:
                            JSON.stringify(
                                payload
                            ),
                    }
                );

            showMessage(
                elements.editorMessage,
                "Draft saved successfully.",
                "success"
            );

        } else {
            data =
                await request(
                    "/notices",
                    {
                        method: "POST",
                        headers: {
                            "Content-Type":
                                "application/json",
                        },
                        body:
                            JSON.stringify(
                                payload
                            ),
                    }
                );

            showMessage(
                elements.editorMessage,
                "Draft created successfully.",
                "success"
            );
        }

        loadNoticeIntoEditor(
            data.notice
        );

        await loadNotices();

    } catch (error) {
        showMessage(
            elements.editorMessage,
            error instanceof Error
                ? error.message
                : "Unable to save notice.",
            "error"
        );

    } finally {
        elements.saveButton.disabled =
            false;

        updateActionButtons(
            state.notices.find(
                (notice) =>
                    notice.notice_id ===
                    elements.noticeId.value
            ) || null
        );
    }
}


async function submitNotice() {
    const noticeId =
        elements.noticeId.value.trim();

    if (
        !noticeId
    ) {
        showMessage(
            elements.editorMessage,
            "Save the notice before submitting it.",
            "error"
        );

        return;
    }

    if (
        !window.confirm(
            "Submit this notice for approval?"
        )
    ) {
        return;
    }

    elements.submitButton.disabled =
        true;

    try {
        const data =
            await request(
                `/notices/${encodeURIComponent(
                    noticeId
                )}/submit`,
                {
                    method: "POST",
                }
            );

        loadNoticeIntoEditor(
            data.notice
        );

        showMessage(
            elements.editorMessage,
            "Notice submitted for approval.",
            "success"
        );

        await loadNotices();

    } catch (error) {
        showMessage(
            elements.editorMessage,
            error instanceof Error
                ? error.message
                : "Unable to submit notice.",
            "error"
        );

    } finally {
        elements.submitButton.disabled =
            false;
    }
}


async function approveNotice() {
    const noticeId =
        elements.noticeId.value.trim();

    if (
        !noticeId
    ) {
        return;
    }

    if (
        !window.confirm(
            "Approve this official communication?"
        )
    ) {
        return;
    }

    elements.approveButton.disabled =
        true;

    try {
        const data =
            await request(
                `/notices/${encodeURIComponent(
                    noticeId
                )}/approve`,
                {
                    method: "POST",
                }
            );

        loadNoticeIntoEditor(
            data.notice
        );

        showMessage(
            elements.editorMessage,
            "Notice approved.",
            "success"
        );

        await loadNotices();

    } catch (error) {
        showMessage(
            elements.editorMessage,
            error instanceof Error
                ? error.message
                : "Unable to approve notice.",
            "error"
        );

    } finally {
        elements.approveButton.disabled =
            false;
    }
}


async function signAndPublish() {
    const noticeId =
        elements.noticeId.value.trim();

    if (!noticeId) {
        showMessage(
            elements.editorMessage,
            "Save the notice before publishing.",
            "error"
        );
        return;
    }

    const file =
        elements.noticeFile.files &&
        elements.noticeFile.files[0];

    if (!file) {
        showMessage(
            elements.editorMessage,
            "Select the final PNG, JPEG, or PDF asset before signing.",
            "error"
        );
        return;
    }

    const allowedTypes = new Set([
        "image/png",
        "image/jpeg",
        "application/pdf",
    ]);

    if (!allowedTypes.has(file.type)) {
        showMessage(
            elements.editorMessage,
            "Only PNG, JPEG, and PDF files are supported.",
            "error"
        );
        return;
    }

    const maxBytes =
        25 * 1024 * 1024;

    if (file.size > maxBytes) {
        showMessage(
            elements.editorMessage,
            "The selected asset is larger than 25 MB.",
            "error"
        );
        return;
    }

    if (
        !window.confirm(
            "Upload the final asset, sign it with the AEGIS issuer, verify it, and publish the notice?"
        )
    ) {
        return;
    }

    elements.publishButton.disabled =
        true;

    elements.publishButton.textContent =
        "Preparing upload...";

    try {
        // ---------------------------------------------------------
        // 1. Ask AEGIS for a short-lived B2 upload URL.
        // ---------------------------------------------------------
        const uploadPlan =
            await request(
                `/notices/${encodeURIComponent(
                    noticeId
                )}/asset-upload-url`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                    },
                    body: JSON.stringify({
                        filename:
                            file.name,

                        content_type:
                            file.type,

                        size_bytes:
                            file.size,
                    }),
                }
            );

        // ---------------------------------------------------------
        // 2. Upload the asset directly to Backblaze B2.
        // ---------------------------------------------------------
        elements.publishButton.textContent =
            "Uploading...";

        const uploadResponse =
            await fetch(
                uploadPlan.upload_url,
                {
                    method: "PUT",
                    headers: {
                        "Content-Type":
                            file.type,
                    },
                    body: file,
                }
            );

        if (
            !uploadResponse.ok
        ) {
            throw new Error(
                "The notice asset could not be uploaded to secure storage."
            );
        }

        // ---------------------------------------------------------
        // 3. Ask AEGIS to invoke the isolated signing service.
        // ---------------------------------------------------------
        elements.publishButton.textContent =
            "Signing...";

        const publishData =
            await request(
                `/notices/${encodeURIComponent(
                    noticeId
                )}/sign-publish`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                    },
                    body: JSON.stringify({
                        source_key:
                            uploadPlan.object_key,

                        filename:
                            file.name,

                        content_type:
                            file.type,
                    }),
                }
            );

        // ---------------------------------------------------------
        // 4. Update the editor with the newly published notice.
        // ---------------------------------------------------------
        loadNoticeIntoEditor(
            publishData.notice
        );

        elements.noticeFile.value =
            "";

        showMessage(
            elements.editorMessage,
            "Published and cryptographically verified.",
            "success"
        );

        await loadNotices();

    } catch (error) {
        showMessage(
            elements.editorMessage,
            error instanceof Error
                ? error.message
                : "Unable to sign and publish notice.",
            "error"
        );

    } finally {
        elements.publishButton.disabled =
            false;

        elements.publishButton.textContent =
            "Sign & Publish";
    }
}

function findSelectedNotice() {
    const noticeId =
        elements.noticeId.value.trim();

    if (
        !noticeId
    ) {
        return null;
    }

    return (
        state.notices.find(
            (notice) =>
                notice.notice_id ===
                noticeId
        ) || null
    );
}


function bindEvents() {
    elements.loginForm.addEventListener(
        "submit",
        login
    );

    elements.logoutButton.addEventListener(
        "click",
        logout
    );

    elements.noticeForm.addEventListener(
        "submit",
        saveNotice
    );

    elements.newNoticeButton.addEventListener(
        "click",
        resetEditor
    );

    elements.refreshButton.addEventListener(
        "click",
        loadNotices
    );

    elements.noticeType.addEventListener(
        "change",
        () => {
            const selected =
                findSelectedNotice();

            updateEditorPolicy(
                selected
            );
        }
    );

    elements.submitButton.addEventListener(
        "click",
        submitNotice
    );

    elements.approveButton.addEventListener(
        "click",
        approveNotice
    );

    elements.publishButton.addEventListener(
        "click",
        signAndPublish
    );

    window.setInterval(
        checkApi,
        15000
    );
}


async function initialize() {
    getElements();

    bindEvents();

    checkApi();

    const valid =
        await validateSession();

    if (
        valid
    ) {
        showConsole();

        await loadNotices();

    } else {
        showLogin();
    }

    resetEditor();
}


window.addEventListener(
    "DOMContentLoaded",
    () => {
        initialize().catch(
            (error) => {
                console.error(
                    "AEGIS publisher UI initialization failed:",
                    error
                );

                showMessage(
                    elements.loginMessage,
                    error instanceof Error
                        ? error.message
                        : "Unable to initialize communications console.",
                    "error"
                );
            }
        );
    }
);