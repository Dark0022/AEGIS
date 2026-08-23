"use strict";

const API_BASE = "/api";

const elements = {
    dropZone:
        document.getElementById("drop-zone"),

    fileInput:
        document.getElementById("file-input"),

    loading:
        document.getElementById("loading"),

    resultSection:
        document.getElementById("result-section"),

    hero:
        document.getElementById("hero"),

    apiDot:
        document.getElementById("api-dot"),

    apiStatus:
        document.getElementById("api-status"),

    resultFilename:
        document.getElementById("result-filename"),

    verifyAnother:
        document.getElementById("verify-another"),

    verdictCard:
        document.getElementById("verdict-card"),

    verdictIcon:
        document.getElementById("verdict-icon"),

    verdictStatus:
        document.getElementById("verdict-status"),

    verdictMessage:
        document.getElementById("verdict-message"),

    decisionExplanation:
        document.getElementById(
            "decision-explanation"
        ),

    decisionFactors:
        document.getElementById(
            "decision-factors"
        ),

    issuer:
        document.getElementById(
            "signal-issuer"
        ),

    issuerState:
        document.getElementById(
            "signal-issuer-state"
        ),

    signature:
        document.getElementById(
            "signal-signature"
        ),

    integrity:
        document.getElementById(
            "signal-integrity"
        ),

    credential:
        document.getElementById(
            "signal-credential"
        ),

    credentialState:
        document.getElementById(
            "signal-credential-state"
        ),

    issuerCard:
        document.getElementById(
            "signal-card-issuer"
        ),

    signatureCard:
        document.getElementById(
            "signal-card-signature"
        ),

    integrityCard:
        document.getElementById(
            "signal-card-integrity"
        ),

    credentialCard:
        document.getElementById(
            "signal-card-credential"
        ),

    warningPanel:
        document.getElementById(
            "warning-panel"
        ),

    warningTitle:
        document.getElementById(
            "warning-title"
        ),

    warningMessage:
        document.getElementById(
            "warning-message"
        ),

    identityTrustBadge:
        document.getElementById(
            "identity-trust-badge"
        ),

    identityIssuer:
        document.getElementById(
            "identity-issuer"
        ),

    identityCommonName:
        document.getElementById(
            "identity-common-name"
        ),

    identitySerial:
        document.getElementById(
            "identity-serial"
        ),

    identityAlgorithm:
        document.getElementById(
            "identity-algorithm"
        ),

    identityAnchor:
        document.getElementById(
            "identity-anchor"
        ),

    identityCredentialState:
        document.getElementById(
            "identity-credential-state"
        ),

    evidenceCount:
        document.getElementById(
            "evidence-count"
        ),

    evidenceList:
        document.getElementById(
            "evidence-list"
        ),
};


const STATUS_META = {
    TRUSTED: {
        icon: "✓",
        className: "trusted",
        label: "TRUSTED OFFICIAL CONTENT",
        message:
            "The issuer is trusted, the cryptographic signature is valid, the content binding is intact, and the issuing credential is currently active.",
    },

    INTEGRITY_FAILURE: {
        icon: "!",
        className: "danger",
        label: "CONTENT INTEGRITY FAILURE",
        message:
            "The issuer is trusted and the signature remains valid, but the received content no longer matches the content authenticated by the signature.",
    },

    REVOKED_CREDENTIAL: {
        icon: "×",
        className: "danger",
        label: "REVOKED CREDENTIAL",
        message:
            "The content and signature may still be cryptographically valid, but the issuing credential is no longer trusted by AEGIS.",
    },

    EXPIRED_CREDENTIAL: {
        icon: "!",
        className: "warning",
        label: "EXPIRED CREDENTIAL",
        message:
            "The cryptographic evidence is present, but the issuing credential is outside its active validity period.",
    },

    UNTRUSTED_ISSUER: {
        icon: "?",
        className: "warning",
        label: "UNTRUSTED ISSUER",
        message:
            "The cryptographic evidence could not establish a currently trusted institutional signing identity.",
    },

    INVALID_SIGNATURE: {
        icon: "×",
        className: "danger",
        label: "INVALID SIGNATURE",
        message:
            "The content's cryptographic signature could not be validated.",
    },

    MALFORMED_PROVENANCE: {
        icon: "!",
        className: "warning",
        label: "MALFORMED PROVENANCE",
        message:
            "The asset contains provenance information, but the provenance structure failed validation.",
    },

    UNVERIFIED: {
        icon: "?",
        className: "neutral",
        label: "UNVERIFIED",
        message:
            "AEGIS could not establish enough evidence to make a trusted authenticity decision.",
    },
};


function requireElement(
    name,
    element
) {
    if (!element) {
        throw new Error(
            `AEGIS UI element is missing: ${name}`
        );
    }

    return element;
}


function validateElements() {
    for (
        const [name, element]
        of Object.entries(elements)
    ) {
        requireElement(
            name,
            element
        );
    }
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
            throw new Error(
                "API health check failed"
            );
        }

        elements.apiDot.className =
            "status-dot online";

        elements.apiStatus.textContent =
            "API online";
    } catch {
        elements.apiDot.className =
            "status-dot offline";

        elements.apiStatus.textContent =
            "API offline";
    }
}


function setLoading(
    isLoading
) {
    if (isLoading) {
        elements.loading.classList.remove(
            "hidden"
        );

        elements.dropZone.classList.add(
            "hidden"
        );

        return;
    }

    elements.loading.classList.add(
        "hidden"
    );

    elements.dropZone.classList.remove(
        "hidden"
    );
}


function showResult() {
    elements.hero.classList.add(
        "hidden"
    );

    elements.resultSection.classList.remove(
        "hidden"
    );

    window.scrollTo({
        top: 0,
        behavior: "smooth",
    });
}


function resetView() {
    elements.resultSection.classList.add(
        "hidden"
    );

    elements.hero.classList.remove(
        "hidden"
    );

    elements.fileInput.value = "";

    setLoading(false);

    window.scrollTo({
        top: 0,
        behavior: "smooth",
    });
}


function findEvidence(
    evidence,
    code
) {
    return (
        evidence.find(
            (item) =>
                item.code === code
        ) || null
    );
}


function findEvidenceAny(
    evidence,
    codes
) {
    for (
        const code
        of codes
    ) {
        const match =
            findEvidence(
                evidence,
                code
            );

        if (match) {
            return match;
        }
    }

    return null;
}


function setSignalState(
    card,
    element,
    value
) {
    card.classList.remove(
        "good",
        "bad",
        "warning"
    );

    if (value === true) {
        element.textContent =
            "VERIFIED";

        element.style.color =
            "var(--green)";

        card.classList.add(
            "good"
        );

        return "good";
    }

    if (value === false) {
        element.textContent =
            "FAILED";

        element.style.color =
            "var(--red)";

        card.classList.add(
            "bad"
        );

        return "bad";
    }

    element.textContent =
        "UNKNOWN";

    element.style.color =
        "var(--muted-strong)";

    return "neutral";
}


function renderCredentialStatus(
    verification
) {
    const status =
        verification.credential_status;

    elements.credentialCard.classList.remove(
        "good",
        "bad",
        "warning"
    );

    if (status === "ACTIVE") {
        elements.credential.textContent =
            "ACTIVE";

        elements.credential.style.color =
            "var(--green)";

        elements.credentialState.textContent =
            verification.credential_active === true
                ? "Current credential is active"
                : "Registry reports ACTIVE";

        elements.credentialCard.classList.add(
            "good"
        );

        return "good";
    }

    if (status === "REVOKED") {
        elements.credential.textContent =
            "REVOKED";

        elements.credential.style.color =
            "var(--red)";

        elements.credentialState.textContent =
            "Credential is no longer trusted";

        elements.credentialCard.classList.add(
            "bad"
        );

        return "bad";
    }

    if (status === "EXPIRED") {
        elements.credential.textContent =
            "EXPIRED";

        elements.credential.style.color =
            "var(--amber)";

        elements.credentialState.textContent =
            "Credential is outside its active lifecycle";

        elements.credentialCard.classList.add(
            "warning"
        );

        return "warning";
    }

    elements.credential.textContent =
        "UNKNOWN";

    elements.credential.style.color =
        "var(--muted-strong)";

    elements.credentialState.textContent =
        verification.credential_active === false
            ? "Credential is not active"
            : "Credential lifecycle unavailable";

    return "neutral";
}


function makeDecisionExplanation(
    verification
) {
    switch (
        verification.status
    ) {
        case "TRUSTED":
            return (
                "AEGIS established a trusted institutional identity, "
                + "validated the claim signature, verified the content binding, "
                + "confirmed valid provenance, and confirmed that the signing "
                + "credential is currently active."
            );

        case "INTEGRITY_FAILURE":
            return (
                "The issuer is trusted and its signature remains valid, "
                + "but the received content no longer matches the content "
                + "authenticated by that signature. Credential lifecycle "
                + "state is reported independently."
            );

        case "REVOKED_CREDENTIAL":
            return (
                "The signature and content remain cryptographically valid, "
                + "but AEGIS has revoked the credential that issued this content. "
                + "The historical cryptographic evidence does not restore trust."
            );

        case "EXPIRED_CREDENTIAL":
            return (
                "The cryptographic evidence is present, but the issuer "
                + "credential is outside its allowed active validity period."
            );

        case "UNTRUSTED_ISSUER":
            return (
                "AEGIS could not establish that the signing certificate "
                + "belongs to a currently trusted institutional credential."
            );

        case "INVALID_SIGNATURE":
            return (
                "The signing claim could not be cryptographically validated, "
                + "so AEGIS cannot establish an authentic signature."
            );

        case "MALFORMED_PROVENANCE":
            return (
                "The asset contains provenance information, but its "
                + "structure does not satisfy the required C2PA validation rules."
            );

        default:
            return (
                "AEGIS could not establish enough evidence to make a trusted decision."
            );
    }
}


function createDecisionFactor(
    label,
    state,
    className
) {
    const container =
        document.createElement(
            "div"
        );

    container.className =
        "decision-factor";

    const labelElement =
        document.createElement(
            "div"
        );

    labelElement.className =
        "decision-factor-label";

    labelElement.textContent =
        label;

    const stateElement =
        document.createElement(
            "div"
        );

    stateElement.className =
        `decision-factor-state ${className}`;

    stateElement.textContent =
        state;

    container.appendChild(
        labelElement
    );

    container.appendChild(
        stateElement
    );

    return container;
}


function renderDecisionFactors(
    verification
) {
    elements.decisionFactors.innerHTML =
        "";

    const factors = [
        {
            label: "ISSUER",
            state:
                verification.issuer_trusted === true
                    ? "TRUSTED"
                    : verification.issuer_trusted === false
                        ? "UNTRUSTED"
                        : "UNKNOWN",
            className:
                verification.issuer_trusted === true
                    ? "good"
                    : verification.issuer_trusted === false
                        ? "bad"
                        : "neutral",
        },
        {
            label: "SIGNATURE",
            state:
                verification.signature_valid === true
                    ? "VALID"
                    : verification.signature_valid === false
                        ? "INVALID"
                        : "UNKNOWN",
            className:
                verification.signature_valid === true
                    ? "good"
                    : verification.signature_valid === false
                        ? "bad"
                        : "neutral",
        },
        {
            label: "INTEGRITY",
            state:
                verification.content_integrity === true
                    ? "INTACT"
                    : verification.content_integrity === false
                        ? "FAILED"
                        : "UNKNOWN",
            className:
                verification.content_integrity === true
                    ? "good"
                    : verification.content_integrity === false
                        ? "bad"
                        : "neutral",
        },
        {
            label: "CREDENTIAL",
            state:
                verification.credential_status ||
                "UNKNOWN",
            className:
                verification.credential_status === "ACTIVE"
                    ? "good"
                    : verification.credential_status === "REVOKED"
                        ? "bad"
                        : verification.credential_status === "EXPIRED"
                            ? "warning"
                            : "neutral",
        },
    ];

    for (
        const factor
        of factors
    ) {
        elements.decisionFactors.appendChild(
            createDecisionFactor(
                factor.label,
                factor.state,
                factor.className
            )
        );
    }
}


function renderWarning(
    verification
) {
    const status =
        verification.status;

    const needsWarning =
        status !== "TRUSTED";

    if (!needsWarning) {
        elements.warningPanel.classList.add(
            "hidden"
        );

        return;
    }

    let title =
        "Verification warning";

    let message =
        "AEGIS did not reach a trusted authenticity decision.";

    switch (status) {
        case "INTEGRITY_FAILURE":
            title =
                "Do not trust the received bytes";

            message =
                "The signing credential is trusted, but the received asset does not match the signed content.";
            break;

        case "REVOKED_CREDENTIAL":
            title =
                "Do not trust newly verified content from this credential";

            message =
                "The credential has been revoked by AEGIS even though the cryptographic evidence may remain valid.";
            break;

        case "EXPIRED_CREDENTIAL":
            title =
                "Credential lifecycle is no longer active";

            message =
                "The credential used to issue this content has expired.";
            break;

        case "INVALID_SIGNATURE":
            title =
                "Signature validation failed";

            message =
                "AEGIS could not validate the signing claim.";
            break;

        case "UNTRUSTED_ISSUER":
            title =
                "Issuer is not trusted";

            message =
                "The signer could not be established as a trusted institutional credential.";
            break;

        case "MALFORMED_PROVENANCE":
            title =
                "Provenance validation failed";

            message =
                "The asset contains provenance information that does not satisfy the required validation rules.";
            break;

        default:
            break;
    }

    elements.warningTitle.textContent =
        title;

    elements.warningMessage.textContent =
        message;

    elements.warningPanel.classList.remove(
        "hidden"
    );
}


function renderEvidence(
    evidence
) {
    elements.evidenceList.innerHTML =
        "";

    elements.evidenceCount.textContent =
        String(
            evidence.length
        );

    if (
        evidence.length === 0
    ) {
        const empty =
            document.createElement(
                "div"
            );

        empty.className =
            "evidence-item";

        empty.textContent =
            "No verification evidence was returned.";

        elements.evidenceList.appendChild(
            empty
        );

        return;
    }

    for (
        const item
        of evidence
    ) {
        const card =
            document.createElement(
                "div"
            );

        card.className =
            "evidence-item";

        const isFailure =
            String(
                item.code || ""
            ).includes(
                "mismatch"
            )
            ||
            String(
                item.code || ""
            ).includes(
                "malformed"
            )
            ||
            String(
                item.code || ""
            ).startsWith(
                "claimSignature."
            ) &&
            item.source === "C2PA" &&
            /fail|invalid|error/i.test(
                item.message || ""
            );

        const isLifecycleBad =
            item.code === "credential.status"
            &&
            /REVOKED|EXPIRED/i.test(
                item.message || ""
            );

        if (
            isFailure ||
            isLifecycleBad
        ) {
            card.classList.add(
                "bad"
            );
        } else if (
            item.code === "credential.status"
            ||
            item.code === "signingCredential.trusted"
            ||
            item.code === "claimSignature.validated"
            ||
            item.code === "assertion.dataHash.match"
        ) {
            card.classList.add(
                "good"
            );
        }

        const top =
            document.createElement(
                "div"
            );

        top.className =
            "evidence-top";

        const code =
            document.createElement(
                "span"
            );

        code.className =
            "evidence-code";

        code.textContent =
            item.code ||
            "unknown";

        const source =
            document.createElement(
                "span"
            );

        source.className =
            "evidence-source";

        source.textContent =
            item.source ||
            "UNKNOWN";

        const message =
            document.createElement(
                "div"
            );

        message.className =
            "evidence-message";

        message.textContent =
            item.message ||
            "";

        top.appendChild(
            code
        );

        top.appendChild(
            source
        );

        card.appendChild(
            top
        );

        card.appendChild(
            message
        );

        elements.evidenceList.appendChild(
            card
        );
    }
}


function renderResult(
    payload
) {
    if (
        !payload ||
        !payload.verification
    ) {
        throw new Error(
            "AEGIS API returned an invalid verification response."
        );
    }

    const verification =
        payload.verification;

    const metadata =
        STATUS_META[
            verification.status
        ] ||
        STATUS_META.UNVERIFIED;

    const evidence =
        Array.isArray(
            verification.evidence
        )
            ? verification.evidence
            : [];

    const issuerEvidence =
        findEvidence(
            evidence,
            "credential.identity"
        );

    const serialEvidence =
        findEvidence(
            evidence,
            "credential.serial"
        );

    const algorithmEvidence =
        findEvidenceAny(
            evidence,
            [
                "signature.algorithm",
                "claimSignature.algorithm",
            ]
        );

    const certificateEvidence =
        findEvidence(
            evidence,
            "signingCredential.trusted"
        );

    elements.resultFilename.textContent =
        payload.filename ||
        "Unknown file";

    elements.verdictCard.className =
        `verdict-card ${metadata.className}`;

    elements.verdictIcon.textContent =
        metadata.icon;

    elements.verdictStatus.textContent =
        metadata.label;

    elements.verdictMessage.textContent =
        metadata.message;

    elements.decisionExplanation.textContent =
        makeDecisionExplanation(
            verification
        );

    renderDecisionFactors(
        verification
    );

    elements.issuer.textContent =
        issuerEvidence
            ? issuerEvidence.message
            : "Unknown";

    elements.issuerState.textContent =
        verification.issuer_trusted === true
            ? "Trusted institutional credential"
            : verification.issuer_trusted === false
                ? "Issuer not trusted"
                : "Issuer state unavailable";

    elements.issuerState.style.color =
        verification.issuer_trusted === true
            ? "var(--green)"
            : verification.issuer_trusted === false
                ? "var(--red)"
                : "var(--muted-strong)";

    setSignalState(
        elements.issuerCard,
        elements.issuer,
        verification.issuer_trusted
    );

    setSignalState(
        elements.signatureCard,
        elements.signature,
        verification.signature_valid
    );

    setSignalState(
        elements.integrityCard,
        elements.integrity,
        verification.content_integrity
    );

    renderCredentialStatus(
        verification
    );

    elements.identityIssuer.textContent =
        issuerEvidence
            ? inferOrganizationFromEvidence(
                issuerEvidence.message,
                verification
            )
            : "Unknown";

    elements.identityCommonName.textContent =
        issuerEvidence
            ? issuerEvidence.message
            : "Unknown";

    elements.identitySerial.textContent =
        serialEvidence
            ? serialEvidence.message
            : "Unknown";

    elements.identityAlgorithm.textContent =
        algorithmEvidence
            ? algorithmEvidence.message
            : inferAlgorithmFromEvidence(
                certificateEvidence,
                evidence
            );

    elements.identityAnchor.textContent =
        certificateEvidence &&
        verification.issuer_trusted
            ? "AEGIS Root CA"
            : "Not established";

    elements.identityCredentialState.textContent =
        verification.credential_status ||
        (
            verification.credential_active === true
                ? "ACTIVE"
                : "UNKNOWN"
        );

    elements.identityTrustBadge.textContent =
        verification.issuer_trusted === true
            ? "TRUSTED SIGNER"
            : verification.issuer_trusted === false
                ? "UNTRUSTED SIGNER"
                : "SIGNER UNKNOWN";

    elements.identityTrustBadge.className =
        `identity-trust-badge ${
            verification.issuer_trusted === true
                ? "trusted"
                : verification.issuer_trusted === false
                    ? "untrusted"
                    : "unknown"
        }`;

    renderWarning(
        verification
    );

    renderEvidence(
        evidence
    );
}


function inferOrganizationFromEvidence(
    commonName,
    verification
) {
    if (
        verification.issuer_trusted === true
        &&
        /Emergency Communications Issuer/i.test(
            commonName || ""
        )
    ) {
        return "SOA University";
    }

    const identity =
        findEvidence(
            Array.isArray(
                verification.evidence
            )
                ? verification.evidence
                : [],
            "credential.identity"
        );

    return identity
        ? "Institutional issuer"
        : "Unknown";
}


function inferAlgorithmFromEvidence(
    certificateEvidence,
    evidence
) {
    const algorithmItem =
        findEvidenceAny(
            evidence,
            [
                "signature.algorithm",
                "claimSignature.algorithm",
            ]
        );

    if (algorithmItem) {
        return algorithmItem.message;
    }

    if (
        certificateEvidence &&
        /trusted/i.test(
            certificateEvidence.message || ""
        )
    ) {
        return "Ed25519";
    }

    return "Unknown";
}


async function verifyFile(
    file
) {
    if (!file) {
        return;
    }

    setLoading(true);

    try {
        const formData =
            new FormData();

        formData.append(
            "file",
            file
        );

        const response =
            await fetch(
                `${API_BASE}/verify`,
                {
                    method: "POST",
                    body: formData,
                    cache: "no-store",
                }
            );

        let data;

        try {
            data =
                await response.json();
        } catch {
            throw new Error(
                "AEGIS API returned an invalid response."
            );
        }

        if (!response.ok) {
            throw new Error(
                data.detail ||
                "Verification failed."
            );
        }

        renderResult(
            data
        );

        showResult();
    } catch (error) {
        console.error(
            "AEGIS verification error:",
            error
        );

        window.alert(
            error instanceof Error
                ? error.message
                : "Unable to verify file."
        );
    } finally {
        setLoading(false);
    }
}


function initialize() {
    validateElements();

    elements.fileInput.addEventListener(
        "change",
        (event) => {
            const file =
                event.target.files &&
                event.target.files[0];

            verifyFile(
                file
            );
        }
    );

    elements.dropZone.addEventListener(
        "dragenter",
        (event) => {
            event.preventDefault();

            elements.dropZone.classList.add(
                "drag-over"
            );
        }
    );

    elements.dropZone.addEventListener(
        "dragover",
        (event) => {
            event.preventDefault();

            elements.dropZone.classList.add(
                "drag-over"
            );
        }
    );

    elements.dropZone.addEventListener(
        "dragleave",
        (event) => {
            if (
                event.target ===
                elements.dropZone
            ) {
                elements.dropZone.classList.remove(
                    "drag-over"
                );
            }
        }
    );

    elements.dropZone.addEventListener(
        "drop",
        (event) => {
            event.preventDefault();

            elements.dropZone.classList.remove(
                "drag-over"
            );

            const file =
                event.dataTransfer.files &&
                event.dataTransfer.files[0];

            verifyFile(
                file
            );
        }
    );

    elements.verifyAnother.addEventListener(
        "click",
        resetView
    );

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
        "AEGIS UI initialization failed:",
        error
    );

    window.alert(
        error instanceof Error
            ? error.message
            : "AEGIS UI initialization failed."
    );
}