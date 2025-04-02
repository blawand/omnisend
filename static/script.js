let quill;
let csvHeaders = [];
let csvFirstRow = null;
let csvFileHandle = null;
let currentMode = "csv"; // 'csv' or 'manual'
let infoStatusTimeout = null; // To manage the timeout for info messages

// Use limits passed from backend, provide defaults if missing
const appLimits = window.appLimits || {
  MAX_TOTAL_ATTACHMENT_SIZE_MB: 15,
  MAX_ATTACHMENTS_PER_EMAIL: 5,
  MAX_MANUAL_RECIPIENTS: 100,
  MAX_CSV_RECIPIENTS: 1000,
  MAX_BODY_LENGTH: 5000,
};
const MAX_TOTAL_ATTACHMENT_SIZE_BYTES =
  appLimits.MAX_TOTAL_ATTACHMENT_SIZE_MB * 1024 * 1024;

const toolbarOptions = [
  [{ header: [1, 2, 3, false] }, { font: [] }],
  ["bold", "italic", "underline", "strike", { color: [] }, { background: [] }],
  [{ list: "ordered" }, { list: "bullet" }, { indent: "-1" }, { indent: "+1" }],
  [{ script: "sub" }, { script: "super" }, { align: [] }],
  ["link", "image", "blockquote", "code-block"],
  ["clean"],
  ["insertPlaceholder"],
];

function initializeQuill() {
  quill = new Quill("#editor-container", {
    theme: "snow",
    modules: {
      toolbar: {
        container: toolbarOptions,
        handlers: {
          insertPlaceholder: insertPlaceholderHandler,
        },
      },
    },
    placeholder: "Compose your email template here...",
  });

  const placeholderButton = document.querySelector(".ql-insertPlaceholder");
  if (placeholderButton) {
    placeholderButton.innerHTML = '<i class="bi bi-braces"></i>'; // Use braces icon consistent with buttons
    placeholderButton.title = "Insert CSV Placeholder {Header}";
    // Set initial state correctly
    placeholderButton.disabled = !(
      currentMode === "csv" && csvHeaders.length > 0
    );
    placeholderButton.style.cursor = placeholderButton.disabled
      ? "not-allowed"
      : "pointer";
    placeholderButton.style.opacity = placeholderButton.disabled ? "0.5" : "1";
  }
}

function insertPlaceholderHandler() {
  if (currentMode !== "csv" || csvHeaders.length === 0) {
    displayStatus(
      "Placeholders only available in CSV mode with loaded headers.",
      "info"
    );
    return;
  }

  const header = prompt(
    `Enter the CSV header name you want to insert (case-sensitive):\nAvailable: ${csvHeaders.join(
      ", "
    )}`
  );
  if (header && csvHeaders.includes(header.trim())) {
    const range = quill.getSelection(true);
    quill.insertText(range.index, `{${header.trim()}}`, "user");
    quill.setSelection(range.index + header.trim().length + 2);
  } else if (header) {
    displayStatus(
      `Header "${header.trim()}" not found. Check spelling/case.`,
      "warning"
    );
  }
}

function handleModeChange(event) {
  const newMode = event.target.getAttribute("data-mode");
  if (newMode && newMode !== currentMode) {
    currentMode = newMode;
    document.getElementById("current-mode").value = currentMode;
    console.log("Switched to mode:", currentMode);

    updatePlaceholderInsertersState();
    resetPreview();
    checkFormValidityAndButtonStates(); // Update buttons based on new mode
  }
}

function updatePlaceholderInsertersState() {
  const enabled = currentMode === "csv" && csvHeaders.length > 0;
  const inserterBtns = document.querySelectorAll(".placeholder-inserter-btn");
  inserterBtns.forEach((btn) => (btn.disabled = !enabled));

  const quillToolbarButton = document.querySelector(".ql-insertPlaceholder");
  if (quillToolbarButton) {
    quillToolbarButton.disabled = !enabled;
    quillToolbarButton.style.cursor = enabled ? "pointer" : "not-allowed";
    quillToolbarButton.style.opacity = enabled ? "1" : "0.5";
  }
}

function handleCsvFileSelect(event) {
  const file = event.target.files[0];
  const headersSection = document.getElementById("csv-headers-section");
  const headersContainer = document.getElementById("headers-container");

  resetCsvState(); // Reset previous state first

  if (!file) {
    // No file selected or selection cancelled
    if (headersContainer)
      headersContainer.innerHTML =
        '<span class="text-muted small">Upload a valid CSV to see available placeholders.</span>';
    if (headersSection) headersSection.classList.add("d-none"); // Hide section if no file selected
    checkFormValidityAndButtonStates();
    return;
  }

  if (currentMode !== "csv") {
    displayStatus("Switched to CSV mode as a file was uploaded.", "info");
    const csvTab = document.getElementById("csv-mode-tab");
    if (csvTab) {
      const tab = new bootstrap.Tab(csvTab);
      tab.show();
      // handleModeChange will update state via event
    } else {
      // Fallback if tab system fails
      currentMode = "csv";
      document.getElementById("current-mode").value = currentMode;
      updatePlaceholderInsertersState(); // Manually update if no tab event
    }
  }

  // Basic client-side size check
  if (file.size > 50 * 1024 * 1024) {
    // 50MB Warning
    displayStatus(
      `Warning: CSV file is large (${(file.size / (1024 * 1024)).toFixed(
        1
      )} MB). Processing might be slow or fail. Max ${
        appLimits.MAX_CSV_RECIPIENTS
      } rows processed.`,
      "warning"
    );
  }

  csvFileHandle = file;
  if (headersContainer)
    headersContainer.innerHTML =
      '<span class="text-muted small">Parsing CSV... <div class="spinner-border spinner-border-sm ms-1" role="status"><span class="visually-hidden">Loading...</span></div></span>';
  // Keep headers section hidden until parsing is successful

  Papa.parse(file, {
    header: true,
    skipEmptyLines: "greedy",
    preview: 2,
    encoding: "UTF-8",
    transformHeader: (header) => header.trim(),
    complete: function (results) {
      if (results.errors.length > 0) {
        console.error("CSV Parsing Errors:", results.errors);
        const errorMsg = results.errors
          .map((e) => `Row ${e.row}: ${e.message}`)
          .join("<br>");
        displayStatus(
          `<strong>Error parsing CSV:</strong><br>${errorMsg}.<br>Check format, UTF-8 encoding, and headers.`,
          "danger"
        );
        if (headersContainer)
          headersContainer.innerHTML =
            '<span class="text-danger small">Error parsing CSV.</span>';
        if (headersSection) headersSection.classList.remove("d-none"); // Show section to display error text
        csvFileHandle = null;
        resetCsvState(); // Reset headers/buttons
        return;
      }

      if (!results.meta.fields || results.meta.fields.length === 0) {
        displayStatus(
          "CSV file seems empty or lacks valid headers in the first row.",
          "warning"
        );
        if (headersContainer)
          headersContainer.innerHTML =
            '<span class="text-warning small">No headers found.</span>';
        if (headersSection) headersSection.classList.remove("d-none"); // Show section to display warning
        csvFileHandle = null;
        resetCsvState();
        return;
      }

      csvHeaders = results.meta.fields.filter((h) => h && h.trim() !== "");
      csvFirstRow = results.data.length > 0 ? results.data[0] || {} : null;

      if (headersContainer) headersContainer.innerHTML = ""; // Clear parsing message
      if (csvHeaders.length > 0) {
        csvHeaders.forEach((header) => {
          const badge = document.createElement("span");
          badge.className =
            "badge bg-secondary me-1 mb-1 fw-normal csv-header-badge";
          badge.textContent = header;
          badge.title = `Click to copy placeholder {${header}}`;
          badge.style.cursor = "pointer";
          badge.onclick = () => copyPlaceholder(badge, header);
          if (headersContainer) headersContainer.appendChild(badge);
        });
        if (headersSection) headersSection.classList.remove("d-none"); // Show section only if headers found
      } else {
        if (headersContainer)
          headersContainer.innerHTML =
            '<span class="text-warning small">No valid headers detected.</span>';
        if (headersSection) headersSection.classList.remove("d-none"); // Show section to display warning
      }

      updatePlaceholderInsertersState();
      checkFormValidityAndButtonStates();
      displayStatus(
        `CSV loaded: ${csvHeaders.length} headers detected. ${
          csvFirstRow ? "Preview available." : "No data rows found for preview."
        }`,
        "info"
      );
    },
    error: function (error, file) {
      console.error("CSV Parsing Failed:", error);
      displayStatus(
        `<strong>Failed to parse CSV:</strong> ${error}. Check file encoding (UTF-8 recommended) and format.`,
        "danger"
      );
      if (headersContainer)
        headersContainer.innerHTML =
          '<span class="text-danger small">Failed to parse CSV.</span>';
      if (headersSection) headersSection.classList.remove("d-none"); // Show section to display error
      csvFileHandle = null;
      resetCsvState();
    },
  });
}

function copyPlaceholder(badgeElement, headerText) {
  navigator.clipboard
    .writeText(`{${headerText}}`)
    .then(() => {
      const originalText = badgeElement.textContent;
      badgeElement.textContent = "Copied!";
      badgeElement.classList.add("bg-success");
      setTimeout(() => {
        badgeElement.textContent = originalText;
        badgeElement.classList.remove("bg-success");
      }, 1000);
    })
    .catch((err) => console.error("Copy failed: ", err));
}

function resetCsvState() {
  csvHeaders = [];
  csvFirstRow = null;
  // csvFileHandle is only reset on error or new selection

  const headersSection = document.getElementById("csv-headers-section");
  const headersContainer = document.getElementById("headers-container");

  if (headersSection) headersSection.classList.add("d-none"); // Hide headers section on reset
  if (headersContainer)
    headersContainer.innerHTML =
      '<span class="text-muted small">Upload a valid CSV to see available placeholders.</span>';

  updatePlaceholderInsertersState();
  checkFormValidityAndButtonStates();
  resetPreview();
}

function resetPreview() {
  const previewArea = document.getElementById("preview-area");
  if (previewArea) previewArea.classList.add("d-none");
  const previewTo = document.getElementById("preview-to");
  const previewSubject = document.getElementById("preview-subject");
  const previewBody = document.getElementById("preview-body");
  const previewContext = document.getElementById("preview-context");
  const previewAttachments = document.getElementById("preview-attachments");

  if (previewTo) previewTo.textContent = "";
  if (previewSubject) previewSubject.textContent = "";
  if (previewBody) previewBody.innerHTML = "";
  if (previewContext) previewContext.textContent = "";
  if (previewAttachments) previewAttachments.innerHTML = "";
}

function checkFormValidityAndButtonStates() {
  const previewButton = document.getElementById("preview-button");
  const sendButton = document.getElementById("send-button");
  if (!previewButton || !sendButton) return;

  let isPreviewValid = false;
  let isSendValid = false;

  const subjectFilled =
    document.getElementById("subject-template").value.trim() !== "";
  const bodyFilled = quill && quill.getLength() > 1;
  const attachmentsValid = validateAttachments(false);

  if (currentMode === "csv") {
    const csvFileSelected = !!csvFileHandle;
    const recipientTemplateFilled =
      document.getElementById("recipient-template").value.trim() !== "";
    isPreviewValid =
      csvFileSelected &&
      csvFirstRow && // Need first row data for preview
      recipientTemplateFilled &&
      subjectFilled &&
      bodyFilled &&
      attachmentsValid;
    isSendValid =
      csvFileSelected && // Only need file handle for sending
      recipientTemplateFilled &&
      subjectFilled &&
      bodyFilled &&
      attachmentsValid;
  } else {
    // manual mode
    const manualRecipientsValue = document
      .getElementById("manual-recipients")
      .value.trim();
    const manualRecipientsFilled = manualRecipientsValue !== "";
    const recipientCount = countManualRecipients(manualRecipientsValue);
    const recipientCountValid =
      recipientCount > 0 && recipientCount <= appLimits.MAX_MANUAL_RECIPIENTS;

    isPreviewValid =
      manualRecipientsFilled &&
      recipientCountValid &&
      subjectFilled &&
      bodyFilled &&
      attachmentsValid;
    isSendValid =
      manualRecipientsFilled &&
      recipientCountValid &&
      subjectFilled &&
      bodyFilled &&
      attachmentsValid;
    updateManualRecipientCounter();
  }

  previewButton.disabled = !isPreviewValid;
  sendButton.disabled = !isSendValid;
}

function generatePreview() {
  const previewArea = document.getElementById("preview-area");
  const previewContext = document.getElementById("preview-context");
  resetPreview();

  if (!validateAttachments(true)) {
    displayStatus("Please fix attachment issues before previewing.", "warning");
    return;
  }

  const subjectTemplate = document.getElementById("subject-template").value;
  const bodyTemplateHtml = quill.root.innerHTML;

  if (!subjectTemplate || quill.getLength() <= 1) {
    displayStatus(
      "Please fill in Subject and Body before previewing.",
      "warning"
    );
    return;
  }

  let previewTo = "(Not Applicable)";
  let previewSubject = subjectTemplate;
  let previewBody = bodyTemplateHtml;
  let contextText = "";
  let unresolvedPlaceholders = new Set();
  const placeholderRegex = /\{(.+?)\}/g;

  if (currentMode === "csv") {
    const recipientTemplate =
      document.getElementById("recipient-template").value;
    if (!csvFirstRow || csvHeaders.length === 0) {
      displayStatus("Load a valid CSV with data for preview.", "warning");
      return;
    }
    if (!recipientTemplate) {
      displayStatus("Fill in Recipient Email Template.", "warning");
      return;
    }
    const recipientPlaceholderMatch = recipientTemplate.match(/^\{(.+?)\}$/);
    if (!recipientPlaceholderMatch) {
      displayStatus(
        "Recipient Template must be like {EmailColumn}.",
        "warning"
      );
      return;
    }
    const recipientHeader = recipientPlaceholderMatch[1];
    if (!csvHeaders.includes(recipientHeader)) {
      displayStatus(
        `Recipient header '{${recipientHeader}}' not found in CSV.`,
        "warning"
      );
      return;
    }

    previewTo = recipientTemplate;
    contextText = "(Preview based on first CSV data row)";

    [recipientTemplate, subjectTemplate, bodyTemplateHtml].forEach(
      (template) => {
        let match;
        while ((match = placeholderRegex.exec(template)) !== null) {
          if (!csvHeaders.includes(match[1])) {
            unresolvedPlaceholders.add(match[0]);
          }
        }
        placeholderRegex.lastIndex = 0;
      }
    );

    csvHeaders.forEach((header) => {
      const placeholder = new RegExp(`\\{${escapeRegExp(header)}\\}`, "g");
      const value =
        csvFirstRow[header] !== undefined && csvFirstRow[header] !== null
          ? String(csvFirstRow[header])
          : "";
      previewTo = previewTo.replace(placeholder, value);
      previewSubject = previewSubject.replace(placeholder, value);
      previewBody = previewBody.replace(placeholder, value);
    });
  } else {
    // manual mode
    const manualRecipientsRaw =
      document.getElementById("manual-recipients").value;
    const recipients = parseManualRecipients(manualRecipientsRaw);

    if (recipients.length === 0) {
      displayStatus("Enter valid recipient emails.", "warning");
      return;
    }
    if (recipients.length > appLimits.MAX_MANUAL_RECIPIENTS) {
      displayStatus(
        `Too many recipients (${recipients.length}). Max ${appLimits.MAX_MANUAL_RECIPIENTS}.`,
        "warning"
      );
      return;
    }

    previewTo =
      recipients[0] +
      (recipients.length > 1 ? ` (and ${recipients.length - 1} others)` : "");
    contextText = "(Manual mode preview - Placeholders NOT replaced)";

    [subjectTemplate, bodyTemplateHtml].forEach((template) => {
      let match;
      while ((match = placeholderRegex.exec(template)) !== null) {
        unresolvedPlaceholders.add(match[0]);
      }
      placeholderRegex.lastIndex = 0;
    });
  }

  document.getElementById("preview-to").textContent =
    previewTo.trim() || "(empty)";
  document.getElementById("preview-subject").textContent =
    previewSubject || "(empty)";
  document.getElementById("preview-body").innerHTML =
    previewBody || "<p>(empty)</p>";
  previewContext.textContent = contextText;

  const attachmentFiles = document.getElementById("attachments").files;
  const attachmentListDiv = document.getElementById("preview-attachments");
  if (attachmentFiles.length > 0) {
    let fileNames = Array.from(attachmentFiles)
      .map((f) => escapeHtml(f.name))
      .join(", ");
    attachmentListDiv.innerHTML = `<hr class="my-2"><i class="bi bi-paperclip"></i> Attachments: ${fileNames}`;
  } else {
    attachmentListDiv.innerHTML = "";
  }

  previewArea.classList.remove("d-none");

  if (currentMode === "csv" && unresolvedPlaceholders.size > 0) {
    displayStatus(
      `Preview Generated. <strong class="text-danger">Warning:</strong> Unresolved placeholders: ${[
        ...unresolvedPlaceholders,
      ].join(", ")}. Check spelling/case.`,
      "warning"
    );
  } else if (currentMode === "manual" && unresolvedPlaceholders.size > 0) {
    displayStatus(
      `Preview Generated. <strong class="text-warning">Note:</strong> Placeholders (${[
        ...unresolvedPlaceholders,
      ].join(", ")}) will be sent literally.`,
      "warning"
    );
  } else {
    displayStatus("Preview generated successfully.", "info");
  }
}

function handleFormSubmit(event) {
  event.preventDefault();
  const sendButton = document.getElementById("send-button");
  const spinner = sendButton.querySelector(".spinner-border");
  const sendButtonIcon = sendButton.querySelector("i");

  // --- Client-side validation before sending ---
  if (!document.getElementById("subject-template").value.trim()) {
    displayStatus("Please enter a Subject.", "warning");
    return;
  }
  if (!quill || quill.getLength() <= 1) {
    if (
      !confirm("The email body appears empty. Are you sure you want to send?")
    ) {
      return;
    }
  }

  if (!validateAttachments(true)) {
    displayStatus("Please fix attachment issues before sending.", "warning");
    return;
  }

  if (currentMode === "csv") {
    if (!csvFileHandle) {
      displayStatus("Please upload a CSV file for CSV mode.", "warning");
      return;
    }
    const recipientTemplate = document
      .getElementById("recipient-template")
      .value.trim();
    if (!recipientTemplate) {
      displayStatus(
        "Please enter the Recipient Email Template for CSV mode.",
        "warning"
      );
      return;
    }
    const recipientPlaceholderMatch = recipientTemplate.match(/^\{(.+?)\}$/);
    if (!recipientPlaceholderMatch) {
      displayStatus(
        "Recipient Email Template must contain exactly one placeholder like {EmailColumn}.",
        "warning"
      );
      return;
    }
    const recipientHeader = recipientPlaceholderMatch[1];
    if (csvHeaders.length > 0 && !csvHeaders.includes(recipientHeader)) {
      displayStatus(
        `Recipient header '{${recipientHeader}}' specified in template not found in loaded CSV headers. Check spelling/case.`,
        "warning"
      );
      return;
    }
  } else {
    // manual mode
    const manualRecipientsValue = document
      .getElementById("manual-recipients")
      .value.trim();
    if (!manualRecipientsValue) {
      displayStatus(
        "Please enter at least one recipient email for Manual mode.",
        "warning"
      );
      return;
    }
    const recipientCount = countManualRecipients(manualRecipientsValue);
    if (recipientCount > appLimits.MAX_MANUAL_RECIPIENTS) {
      displayStatus(
        `Too many recipients (${recipientCount}). Maximum allowed is ${appLimits.MAX_MANUAL_RECIPIENTS}.`,
        "warning"
      );
      return;
    }
    const validRecipients = parseManualRecipients(manualRecipientsValue);
    if (validRecipients.length === 0) {
      displayStatus(
        "No valid email addresses found in the recipient list.",
        "warning"
      );
      return;
    }
  }
  // --- End Client-side validation ---

  document.getElementById("body-template").value = quill.root.innerHTML;
  const formData = new FormData(event.target);
  formData.set("mode", currentMode);

  if (
    currentMode === "csv" &&
    csvFileHandle &&
    (!formData.has("csv_file") ||
      formData.get("csv_file")?.size !== csvFileHandle.size)
  ) {
    formData.set("csv_file", csvFileHandle, csvFileHandle.name);
  } else if (currentMode === "manual" && formData.has("csv_file")) {
    formData.delete("csv_file");
  }

  sendButton.disabled = true;
  spinner.style.display = "inline-block";
  if (sendButtonIcon) sendButtonIcon.style.display = "none";
  displayStatus(
    "Sending emails... Please wait.",
    "info",
    true // isLoading = true
  );

  fetch("/send-emails", {
    method: "POST",
    body: formData,
  })
    .then((response) => {
      if (!response.ok) {
        return response
          .json()
          .catch(() => ({
            error: `Server error: ${response.status} ${response.statusText}. Check server logs.`,
            statusCode: response.status,
          }))
          .then((errData) => {
            if (!errData.statusCode) errData.statusCode = response.status;
            throw errData;
          });
      }
      return response.json();
    })
    .then((body) => {
      if (body.success) {
        let message = `<h5>Process Complete</h5><p class="lead">${escapeHtml(
          body.message || "Emails processed successfully."
        )}</p>`;
        if (body.results && body.results.length > 0) {
          message += renderResultsTable(body.results);
        }
        displayStatus(message, "success"); // Success status will have its icon added by displayStatus
      } else {
        console.error("Send Error Response:", body);
        let errorMessage =
          body.error || "An unknown error occurred during sending.";
        let alertType = "danger";
        const statusCode = body.statusCode || 0;

        if (statusCode === 401) {
          errorMessage = `Authentication Error (${statusCode}): ${escapeHtml(
            errorMessage
          )}. Reload page & sign in again.`;
        } else if (statusCode === 400) {
          errorMessage = `Invalid Request (${statusCode}): ${escapeHtml(
            errorMessage
          )}. Check inputs.`;
          alertType = "warning";
        } else if (statusCode === 413) {
          errorMessage = `Request Too Large (${statusCode}): ${escapeHtml(
            errorMessage
          )}. Reduce attachment size/number.`;
          alertType = "warning";
        } else if (statusCode === 429) {
          errorMessage = `Rate Limit Exceeded (${statusCode}): ${escapeHtml(
            errorMessage
          )}. Wait before trying again.`;
          alertType = "warning";
        } else if (statusCode >= 500) {
          errorMessage = `Server Error (${statusCode}): ${escapeHtml(
            errorMessage
          )}. Try again later or contact support.`;
        } else if (statusCode) {
          errorMessage = `Error ${statusCode}: ${escapeHtml(errorMessage)}`;
          alertType = "warning";
        } else {
          errorMessage = escapeHtml(errorMessage);
        }

        let detailedMessage = `<h5>Send Failed</h5><p class="lead">${errorMessage}</p>`;

        if (body.results && body.results.length > 0) {
          detailedMessage +=
            '<p class="mt-2 mb-1">Partial results (processing may have stopped):</p>';
          detailedMessage += renderResultsTable(body.results);
        }
        displayStatus(detailedMessage, alertType); // Error status will have icon added
      }
    })
    .catch((error) => {
      console.error("Fetch/Processing Error:", error);
      let message = "An unexpected client-side error occurred.";
      let alertType = "danger";

      if (error instanceof TypeError) {
        message = `Network error: ${error.message}. Could not reach server. Check connection.`;
      } else if (error.error) {
        const statusCode = error.statusCode || 0;
        message = error.error;
        if (statusCode === 401) {
          message = `Auth Error (${statusCode}): ${escapeHtml(
            message
          )}. Reload & re-auth.`;
        } else if (statusCode === 429) {
          message = `Rate Limit (${statusCode}): ${escapeHtml(
            message
          )}. Wait before retrying.`;
          alertType = "warning";
        } else if (statusCode >= 500) {
          message = `Server Error (${statusCode}): ${escapeHtml(
            message
          )}. Try again later.`;
        } else if (statusCode) {
          message = `Error ${statusCode}: ${escapeHtml(message)}`;
          alertType = "warning";
        } else {
          message = escapeHtml(message);
        }
      } else if (error.message) {
        message = `Client processing error: ${error.message}`;
      }

      displayStatus(`<h5>Error Occurred</h5> <p>${message}</p>`, alertType); // Error status will have icon
    })
    .finally(() => {
      sendButton.disabled = false;
      spinner.style.display = "none";
      if (sendButtonIcon) sendButtonIcon.style.display = "inline-block";
      checkFormValidityAndButtonStates();
    });
}

function renderResultsTable(results) {
  if (!results || results.length === 0) return "";

  // Group results by status for summary
  const summary = results.reduce((acc, r) => {
    acc[r.status] = (acc[r.status] || 0) + 1;
    return acc;
  }, {});

  let summaryHtml = '<p class="mb-2"><strong>Summary:</strong> ';
  summaryHtml += Object.entries(summary)
    .map(([status, count]) => {
      let badgeClass = "bg-secondary";
      if (status === "sent") badgeClass = "bg-success";
      else if (status === "skipped") badgeClass = "bg-warning text-dark";
      else if (status === "failed") badgeClass = "bg-danger";
      else if (status === "warning") badgeClass = "bg-info text-dark";
      return `<span class="badge ${badgeClass} me-2">${escapeHtml(
        status
      )}: ${count}</span>`;
    })
    .join("");
  summaryHtml += "</p>";

  let tableHtml = `
        ${summaryHtml}
        <div class="table-responsive mt-1" style="max-height: 400px; overflow-y: auto;">
          <table class="table table-sm table-striped table-hover small">
            <thead class="table-light sticky-top">
              <tr>
                <th scope="col">#</th>
                <th scope="col">Recipient/Target</th>
                <th scope="col">Status</th>
                <th scope="col">Details</th>
              </tr>
            </thead>
            <tbody>
    `;

  results.forEach((r, index) => {
    let statusClass = "";
    let iconClass = "";
    let statusText = escapeHtml(r.status || "unknown");
    switch (r.status) {
      case "sent":
        statusClass = "text-success";
        iconClass = "bi-check-circle"; // Use outline icon for less emphasis in rows
        break;
      case "skipped":
        statusClass = "text-warning";
        iconClass = "bi-skip-forward";
        break;
      case "failed":
        statusClass = "text-danger";
        iconClass = "bi-x-octagon";
        break;
      case "warning":
        statusClass = "text-info";
        iconClass = "bi-exclamation-circle";
        statusText = "Processed (Warning)";
        break;
      default:
        statusClass = "text-muted";
        iconClass = "bi-question-circle";
    }

    const fullReason = escapeHtml(r.reason || "");
    const displayReason =
      fullReason.length > 150
        ? fullReason.substring(0, 147) + "..."
        : fullReason;
    const reasonHtml = fullReason
      ? `<span title="${fullReason}">${displayReason}</span>`
      : '<span class="text-muted">-</span>';
    const recipientHtml = escapeHtml(r.recipient || "N/A");
    const rowNum = r.row
      ? escapeHtml(String(r.row))
      : currentMode === "csv"
      ? index + 2
      : index + 1;

    tableHtml += `
            <tr>
              <td class="text-muted">${rowNum}</td>
              <td>${recipientHtml}</td>
              <td class="${statusClass}"><i class="bi ${iconClass} me-1"></i>${statusText}</td>
              <td>${reasonHtml}</td>
            </tr>
        `;
  });

  tableHtml += `
            </tbody>
          </table>
        </div>
    `;
  return tableHtml;
}

function displayStatus(message, type = "info", isLoading = false) {
  const statusMessageDiv = document.getElementById("status-message");
  if (!statusMessageDiv) return;

  if (infoStatusTimeout) {
    clearTimeout(infoStatusTimeout);
    infoStatusTimeout = null;
  }

  let alertClass = `alert-${type}`;
  let shouldScroll = false;
  let autoDismiss = false;
  let iconClass = "";

  if (isLoading) {
    alertClass = "alert-info";
    iconClass = "spinner-border spinner-border-sm"; // Use spinner class directly
    shouldScroll = true;
  } else {
    switch (type) {
      case "success":
        alertClass = "alert-success";
        iconClass = "bi bi-check-circle-fill"; // Use filled icon for main status
        shouldScroll = true;
        break;
      case "warning":
        alertClass = "alert-warning";
        iconClass = "bi bi-exclamation-triangle-fill";
        break;
      case "danger":
        alertClass = "alert-danger";
        iconClass = "bi bi-x-octagon-fill";
        shouldScroll = true;
        break;
      case "info":
      default:
        alertClass = "alert-secondary"; // Use secondary for less emphasis
        iconClass = "bi bi-info-circle-fill";
        autoDismiss = true;
        break;
    }
  }

  const alertDiv = document.createElement("div");
  alertDiv.className = `alert ${alertClass} alert-dismissible d-flex align-items-start fade show`;
  alertDiv.setAttribute("role", "alert");

  // Construct inner HTML carefully
  let iconHtml = "";
  if (isLoading) {
    iconHtml = `<div class="${iconClass} flex-shrink-0 me-3" role="status" style="margin-top: 0.15rem;"><span class="visually-hidden">Loading...</span></div>`;
  } else if (iconClass) {
    // Only add i tag if iconClass is set and not loading
    iconHtml = `<i class="${iconClass} flex-shrink-0 me-2" style="font-size: 1.2rem;"></i>`;
  }

  // Check if message already contains <h5> for title - avoids nested <h5>
  const containsTitle = /<h5\b/i.test(message);
  const messageContent = containsTitle
    ? message
    : `<p class="mb-0">${message}</p>`; // Wrap simple messages in <p>

  alertDiv.innerHTML = `
        ${iconHtml}
        <div class="flex-grow-1">${messageContent}</div>
        <button type="button" class="btn-close ms-2" data-bs-dismiss="alert" aria-label="Close" style="margin-top: -0.1rem;"></button>
    `;

  statusMessageDiv.innerHTML = "";
  statusMessageDiv.appendChild(alertDiv);

  if (shouldScroll) {
    statusMessageDiv.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  if (autoDismiss && !isLoading) {
    infoStatusTimeout = setTimeout(() => {
      const currentAlert = statusMessageDiv.querySelector(".alert");
      if (
        currentAlert &&
        (currentAlert.classList.contains("alert-secondary") ||
          currentAlert.classList.contains("alert-info")) &&
        !isLoading
      ) {
        const bsAlert = bootstrap.Alert.getOrCreateInstance(currentAlert);
        if (bsAlert) bsAlert.close();
        else currentAlert.remove();
      }
      infoStatusTimeout = null;
    }, 7000);
  }
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== "string") {
    if (unsafe === null || typeof unsafe === "undefined") return "";
    try {
      unsafe = String(unsafe);
    } catch (e) {
      console.warn("Could not convert value:", unsafe);
      return "Invalid";
    }
  }
  const div = document.createElement("div");
  div.textContent = unsafe;
  return div.innerHTML;
}

function insertPlaceholderIntoInput(targetId) {
  if (currentMode !== "csv" || csvHeaders.length === 0) {
    displayStatus("Placeholders only available in CSV mode.", "info");
    return;
  }
  const header = prompt(
    `Enter CSV header name:\nAvailable: ${csvHeaders.join(", ")}`
  );
  const targetInput = document.getElementById(targetId);
  if (header && csvHeaders.includes(header.trim()) && targetInput) {
    const placeholderText = `{${header.trim()}}`;
    const start = targetInput.selectionStart;
    const end = targetInput.selectionEnd;
    targetInput.value =
      targetInput.value.substring(0, start) +
      placeholderText +
      targetInput.value.substring(end);
    targetInput.focus();
    targetInput.setSelectionRange(
      start + placeholderText.length,
      start + placeholderText.length
    );
    checkFormValidityAndButtonStates();
    targetInput.dispatchEvent(new Event("input"));
  } else if (header) {
    if (!targetInput)
      displayStatus(`Target '#${targetId}' not found.`, "danger");
    else
      displayStatus(
        `Header "${header.trim()}" not found. Check spelling/case.`,
        "warning"
      );
  }
}

function validateAttachments(showErrorMessages = true) {
  const attachmentInput = document.getElementById("attachments");
  const errorDiv = document.getElementById("attachment-error");
  if (!attachmentInput) return true;
  const files = attachmentInput.files;
  if (errorDiv) errorDiv.textContent = "";

  if (files.length > appLimits.MAX_ATTACHMENTS_PER_EMAIL) {
    const errorMsg = `Too many files (${files.length}). Max ${appLimits.MAX_ATTACHMENTS_PER_EMAIL}.`;
    if (showErrorMessages) {
      if (errorDiv) errorDiv.textContent = errorMsg;
      displayStatus(`Attachment Error: ${errorMsg}`, "warning");
    }
    return false;
  }

  let totalSize = 0;
  for (let i = 0; i < files.length; i++) {
    totalSize += files[i].size;
  }

  if (totalSize > MAX_TOTAL_ATTACHMENT_SIZE_BYTES) {
    const errorMsg = `Total size exceeds limit (${appLimits.MAX_TOTAL_ATTACHMENT_SIZE_MB} MB).`;
    if (showErrorMessages) {
      if (errorDiv) errorDiv.textContent = errorMsg;
      displayStatus(`Attachment Error: ${errorMsg}`, "warning");
    }
    return false;
  }

  return true;
}

function updateAttachmentList() {
  const attachmentInput = document.getElementById("attachments");
  const listDiv = document.getElementById("attachment-list");
  if (!attachmentInput || !listDiv) return;

  listDiv.innerHTML = "";

  if (!attachmentInput.files || attachmentInput.files.length === 0) return;

  const files = Array.from(attachmentInput.files);
  const list = document.createElement("ul");
  list.className = "list-unstyled mb-0 small";
  let totalSize = 0;

  files.forEach((file) => {
    const li = document.createElement("li");
    li.className =
      "text-muted d-flex justify-content-between align-items-center border-bottom py-1";
    const fileSizeKB = (file.size / 1024).toFixed(1);
    totalSize += file.size;
    li.innerHTML = `
            <span><i class="bi bi-file-earmark me-1"></i> ${escapeHtml(
              file.name
            )}</span>
            <span class="ms-2 text-nowrap">${fileSizeKB} KB</span>
        `;
    list.appendChild(li);
  });

  const summary = document.createElement("li");
  summary.className = "mt-1 pt-1 fw-medium";
  const totalSizeMB = (totalSize / (1024 * 1024)).toFixed(1);
  summary.textContent = `Total: ${files.length} file(s), ${totalSizeMB} MB / ${appLimits.MAX_TOTAL_ATTACHMENT_SIZE_MB} MB`;

  if (
    totalSize > MAX_TOTAL_ATTACHMENT_SIZE_BYTES ||
    files.length > appLimits.MAX_ATTACHMENTS_PER_EMAIL
  ) {
    summary.classList.add("text-danger");
  }

  list.appendChild(summary);
  listDiv.appendChild(list);
}

function handleAttachmentChange(event) {
  updateAttachmentList();
  validateAttachments(true); // Validate and show errors immediately
  checkFormValidityAndButtonStates();
}

function parseManualRecipients(rawValue) {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return rawValue
    .split(/[\s,;\n]+/)
    .map((email) => email.trim())
    .filter((email) => email !== "" && emailRegex.test(email));
}

function countManualRecipients(rawValue) {
  return rawValue.split(/[\s,;\n]+/).filter((e) => e.trim() !== "").length;
}

function updateManualRecipientCounter() {
  const textarea = document.getElementById("manual-recipients");
  const counterDiv = document.getElementById("manual-recipient-count");
  if (!textarea || !counterDiv) return;

  const count = countManualRecipients(textarea.value);
  counterDiv.textContent = `Recipients: ${count} / ${appLimits.MAX_MANUAL_RECIPIENTS}`;

  if (count > appLimits.MAX_MANUAL_RECIPIENTS) {
    textarea.classList.add("is-invalid");
    counterDiv.classList.add("text-danger");
    counterDiv.classList.remove("text-muted");
  } else {
    textarea.classList.remove("is-invalid");
    counterDiv.classList.remove("text-danger");
    counterDiv.classList.add("text-muted");
  }
}

// Event Listeners Setup
document.addEventListener("DOMContentLoaded", function () {
  const emailForm = document.getElementById("email-form");

  if (emailForm) {
    initializeQuill();

    const csvFileInput = document.getElementById("csv-file");
    const previewButton = document.getElementById("preview-button");
    const modeTabs = document.querySelectorAll(
      '#modeTabs button[data-bs-toggle="tab"]'
    );
    const attachmentInput = document.getElementById("attachments");
    const manualRecipientsTextarea =
      document.getElementById("manual-recipients");

    emailForm.addEventListener("submit", handleFormSubmit);
    modeTabs.forEach((tab) =>
      tab.addEventListener("shown.bs.tab", handleModeChange)
    );
    if (csvFileInput)
      csvFileInput.addEventListener("change", handleCsvFileSelect);
    if (previewButton) previewButton.addEventListener("click", generatePreview);
    if (attachmentInput)
      attachmentInput.addEventListener("change", handleAttachmentChange);
    if (manualRecipientsTextarea) {
      manualRecipientsTextarea.addEventListener(
        "input",
        updateManualRecipientCounter
      );
      manualRecipientsTextarea.addEventListener(
        "input",
        checkFormValidityAndButtonStates
      );
    }

    document.querySelectorAll(".placeholder-inserter-btn").forEach((button) => {
      button.addEventListener("click", () => {
        const targetId = button.getAttribute("data-target");
        if (targetId) insertPlaceholderIntoInput(targetId);
      });
    });

    ["recipient-template", "subject-template"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", checkFormValidityAndButtonStates);
    });

    if (quill) {
      // Function to update the character counter display
      const updateBodyCounter = () => {
        const counterElement = document.getElementById("body-char-count");
        if (!counterElement) return;

        const length = quill.getLength() - 1; // Exclude trailing newline
        counterElement.textContent = `${length} / ${MAX_BODY_LENGTH}`;

        if (length >= MAX_BODY_LENGTH) {
          counterElement.classList.add("text-danger");
        } else {
          counterElement.classList.remove("text-danger");
        }
      };

      quill.on("text-change", (delta, oldDelta, source) => {
        // Update hidden input for form submission
        const bodyTemplateInput = document.getElementById("body-template");
        if (bodyTemplateInput) {
          bodyTemplateInput.value = quill.root.innerHTML;
        }

        // Enforce character limit
        const currentLength = quill.getLength() - 1;
        if (currentLength > MAX_BODY_LENGTH) {
          // Use 'silent' source to prevent infinite loop if deleteText triggers text-change
          quill.deleteText(
            MAX_BODY_LENGTH,
            currentLength - MAX_BODY_LENGTH,
            "silent"
          );
          // Re-calculate length after deletion for accurate counter
          updateBodyCounter();
        } else {
          // Update counter normally
          updateBodyCounter();
        }

        // Only check form validity if the change came from the user
        if (source === "user") {
          checkFormValidityAndButtonStates();
        }
      });
    }

    // Initial setup
    resetCsvState();
    currentMode =
      document
        .querySelector("#modeTabs .nav-link.active")
        ?.getAttribute("data-mode") || "csv";
    const currentModeInput = document.getElementById("current-mode");
    if (currentModeInput) currentModeInput.value = currentMode;
    updatePlaceholderInsertersState();
    updateManualRecipientCounter();
    // Initial call to set the body counter after quill is ready
    if (quill) {
      const updateBodyCounterInitial = () => {
        const counterElement = document.getElementById("body-char-count");
        if (!counterElement) return;
        const length = quill.getLength() - 1;
        counterElement.textContent = `${length} / ${MAX_BODY_LENGTH}`;
        if (length >= MAX_BODY_LENGTH) {
          counterElement.classList.add("text-danger");
        } else {
          counterElement.classList.remove("text-danger");
        }
      };
      updateBodyCounterInitial();
    }
    checkFormValidityAndButtonStates(); // Checks button states including initial body content
  }
});
