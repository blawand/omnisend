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
  MAX_CSV_RECIPIENTS: 1000, // Primarily backend, used for warnings
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
    placeholderButton.innerHTML = '<i class="bi bi-paperclip"></i>';
    placeholderButton.title = "Insert CSV Placeholder";
  }
  updatePlaceholderInsertersState();
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

  resetCsvState();

  if (!file) {
    headersContainer.innerHTML =
      '<span class="text-muted small">No file selected.</span>';
    headersSection.classList.add("d-none");
    checkFormValidityAndButtonStates();
    return;
  }

  if (currentMode !== "csv") {
    displayStatus("Switched to CSV mode as a file was uploaded.", "info");
    const csvTab = document.getElementById("csv-mode-tab");
    if (csvTab) {
      const tab = new bootstrap.Tab(csvTab);
      tab.show();
      // handleModeChange will be triggered by the tab switch event
    } else {
      currentMode = "csv"; // Fallback if tab doesn't exist
      document.getElementById("current-mode").value = currentMode;
    }
  }

  // Basic check for potentially huge files client-side
  if (file.size > 50 * 1024 * 1024) {
    // Warn for files > 50MB
    displayStatus(
      `Warning: CSV file is very large (${(file.size / (1024 * 1024)).toFixed(
        1
      )} MB). Processing may be slow or fail due to server limits. The server will process max ${
        appLimits.MAX_CSV_RECIPIENTS
      } rows.`,
      "warning"
    );
  }

  csvFileHandle = file;
  headersContainer.innerHTML =
    '<span class="text-muted small">Parsing CSV... <div class="spinner-border spinner-border-sm ms-1" role="status"><span class="visually-hidden">Loading...</span></div></span>';
  headersSection.classList.remove("d-none");

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
          `<strong>Error parsing CSV:</strong><br>${errorMsg}.<br>Please check file format, UTF-8 encoding, and ensure headers are in the first row.`,
          "danger"
        );
        headersContainer.innerHTML =
          '<span class="text-danger small">Error parsing CSV.</span>';
        csvFileHandle = null;
        headersSection.classList.add("d-none");
        resetCsvState(); // Resets headers and buttons
        return;
      }

      if (!results.meta.fields || results.meta.fields.length === 0) {
        displayStatus(
          "CSV file seems to be empty or does not contain valid headers in the first row.",
          "warning"
        );
        headersContainer.innerHTML =
          '<span class="text-warning small">No headers found.</span>';
        csvFileHandle = null;
        headersSection.classList.add("d-none");
        resetCsvState();
        return;
      }

      csvHeaders = results.meta.fields.filter((h) => h && h.trim() !== "");
      csvFirstRow = results.data.length > 0 ? results.data[0] : null;

      headersContainer.innerHTML = "";
      if (csvHeaders.length > 0) {
        csvHeaders.forEach((header) => {
          const badge = document.createElement("span");
          badge.className =
            "badge bg-secondary me-1 mb-1 fw-normal csv-header-badge";
          badge.textContent = header;
          badge.title = `Click to copy placeholder {${header}}`;
          badge.style.cursor = "pointer";
          badge.onclick = () => {
            navigator.clipboard
              .writeText(`{${header}}`)
              .then(() => {
                const originalText = badge.textContent;
                badge.textContent = "Copied!";
                badge.classList.add("bg-success");
                setTimeout(() => {
                  badge.textContent = originalText;
                  badge.classList.remove("bg-success");
                }, 1000);
              })
              .catch((err) => console.error("Copy failed: ", err));
          };
          headersContainer.appendChild(badge);
        });
      } else {
        headersContainer.innerHTML =
          '<span class="text-warning small">No valid headers detected.</span>';
        headersSection.classList.add("d-none");
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
        `<strong>Failed to parse CSV file:</strong> ${error}. Check file encoding (UTF-8 recommended) and format.`,
        "danger"
      );
      headersContainer.innerHTML =
        '<span class="text-danger small">Failed to parse CSV.</span>';
      csvFileHandle = null;
      headersSection.classList.add("d-none");
      resetCsvState();
    },
  });
}

function resetCsvState() {
  csvHeaders = [];
  csvFirstRow = null;
  // Don't reset csvFileHandle here, only on new selection or error

  const headersSection = document.getElementById("csv-headers-section");
  const headersContainer = document.getElementById("headers-container");
  if (headersSection) headersSection.classList.add("d-none");
  if (headersContainer)
    headersContainer.innerHTML =
      '<span class="text-muted small">Upload a CSV to see headers.</span>';

  updatePlaceholderInsertersState();
  checkFormValidityAndButtonStates();
  resetPreview();
}

function resetPreview() {
  const previewArea = document.getElementById("preview-area");
  if (previewArea) previewArea.classList.add("d-none");
  document.getElementById("preview-to").textContent = "";
  document.getElementById("preview-subject").textContent = "";
  document.getElementById("preview-body").innerHTML = "";
  document.getElementById("preview-context").textContent = "";
  document.getElementById("preview-attachments").innerHTML = "";
}

function checkFormValidityAndButtonStates() {
  const previewButton = document.getElementById("preview-button");
  const sendButton = document.getElementById("send-button");
  if (!previewButton || !sendButton) return;

  let isPreviewValid = false;
  let isSendValid = false;

  const subjectFilled =
    document.getElementById("subject-template").value.trim() !== "";
  const bodyFilled = quill && quill.getLength() > 1; // quill.getLength() is 1 for an empty editor
  const attachmentsValid = validateAttachments(false); // Check validity without showing errors yet

  if (currentMode === "csv") {
    const csvFileSelected = !!csvFileHandle;
    const recipientTemplateFilled =
      document.getElementById("recipient-template").value.trim() !== "";
    isPreviewValid =
      csvFileSelected &&
      csvFirstRow &&
      recipientTemplateFilled &&
      subjectFilled &&
      bodyFilled &&
      attachmentsValid;
    isSendValid =
      csvFileSelected &&
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
      recipientCount <= appLimits.MAX_MANUAL_RECIPIENTS;

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
    updateManualRecipientCounter(); // Update counter display
  }

  previewButton.disabled = !isPreviewValid;
  sendButton.disabled = !isSendValid;
}

function generatePreview() {
  const previewArea = document.getElementById("preview-area");
  const previewContext = document.getElementById("preview-context");
  resetPreview();

  if (!validateAttachments(true)) {
    // Show errors if attachments are invalid
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
      displayStatus(
        "Cannot generate CSV preview. Load a valid CSV with headers and at least one data row.",
        "warning"
      );
      return;
    }
    if (!recipientTemplate) {
      displayStatus(
        "Please fill in the Recipient Email Template for CSV preview.",
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
        // Reset regex lastIndex since we reuse it
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
      displayStatus(
        "Please enter at least one valid recipient email for Manual mode preview.",
        "warning"
      );
      return;
    }
    if (recipients.length > appLimits.MAX_MANUAL_RECIPIENTS) {
      displayStatus(
        `Too many recipients entered (${recipients.length}). Maximum allowed is ${appLimits.MAX_MANUAL_RECIPIENTS}.`,
        "warning"
      );
      return; // Prevent preview if too many recipients
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
      placeholderRegex.lastIndex = 0; // Reset regex lastIndex
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
      `Preview Generated. <strong class="text-danger">Warning:</strong> Unresolved placeholders found: ${[
        ...unresolvedPlaceholders,
      ].join(", ")}. Check spelling/case against CSV headers.`,
      "warning"
    );
  } else if (currentMode === "manual" && unresolvedPlaceholders.size > 0) {
    displayStatus(
      `Preview Generated. <strong class="text-warning">Note:</strong> Placeholders (${[
        ...unresolvedPlaceholders,
      ].join(", ")}) found. In Manual mode, these are sent literally.`,
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
    // Show errors if attachments invalid
    displayStatus("Please fix attachment issues before sending.", "warning");
    return;
  }

  if (currentMode === "csv") {
    if (!csvFileHandle) {
      displayStatus("Please upload a CSV file for CSV mode.", "warning");
      return;
    }
    if (!document.getElementById("recipient-template").value.trim()) {
      displayStatus(
        "Please enter the Recipient Email Template for CSV mode.",
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
    if (recipientCount === 0) {
      displayStatus(
        "Please enter at least one valid recipient email for Manual mode.",
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
    (!formData.has("csv_file") || !formData.get("csv_file").size)
  ) {
    formData.set("csv_file", csvFileHandle, csvFileHandle.name);
  } else if (currentMode === "manual" && formData.has("csv_file")) {
    // Ensure CSV is not sent in manual mode if user switched after selecting file
    formData.delete("csv_file");
  }

  sendButton.disabled = true;
  spinner.style.display = "inline-block";
  if (sendButtonIcon) sendButtonIcon.style.display = "none";
  displayStatus(
    "Sending emails... Please wait. You might be prompted to authenticate with Google (check for pop-ups or new tabs). This can take time depending on the number of emails and attachments.",
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
          .catch(() => {
            // Handle cases where response is not valid JSON (e.g., server error page)
            return {
              error: `Server responded with status: ${response.status} ${response.statusText}. Check server logs for details.`,
              statusCode: response.status,
            };
          })
          .then((errData) => {
            if (!errData.statusCode) errData.statusCode = response.status;
            throw errData; // Re-throw the processed error object
          });
      }
      return response.json();
    })
    .then((body) => {
      if (body.success) {
        let message = `<h5><i class="bi bi-check-circle-fill text-success me-2"></i>Process Complete</h5><p class="lead">${escapeHtml(
          body.message || "Emails processed successfully."
        )}</p>`;
        if (body.results && body.results.length > 0) {
          message += renderResultsTable(body.results);
        }
        displayStatus(message, "success");
      } else {
        // Handle specific known error codes gracefully
        console.error("Send Error Response:", body);
        let errorMessage =
          body.error || "An unknown error occurred during sending.";
        let alertType = "danger";

        if (body.statusCode === 401) {
          errorMessage = `Authentication Error (${
            body.statusCode
          }): ${escapeHtml(
            errorMessage
          )}. Please reload the page and sign in again.`;
        } else if (body.statusCode === 400) {
          errorMessage = `Invalid Request (${body.statusCode}): ${escapeHtml(
            errorMessage
          )}. Please check your inputs (CSV, recipients, templates, attachments).`;
          alertType = "warning"; // More like a user input issue
        } else if (body.statusCode === 413) {
          errorMessage = `Request Too Large (${body.statusCode}): ${escapeHtml(
            errorMessage
          )}. Reduce the size or number of attachments.`;
          alertType = "warning";
        } else if (body.statusCode === 429) {
          errorMessage = `Rate Limit Exceeded (${
            body.statusCode
          }): ${escapeHtml(
            errorMessage
          )}. Please wait a while before trying again.`;
          alertType = "warning";
        } else if (body.statusCode === 500) {
          errorMessage = `Server Error (${body.statusCode}): ${escapeHtml(
            errorMessage
          )}. Please try again later or contact support. Check server logs.`;
        } else if (body.statusCode) {
          // Generic handling for other HTTP errors
          errorMessage = `Error ${body.statusCode}: ${escapeHtml(
            errorMessage
          )}`;
        } else {
          errorMessage = escapeHtml(errorMessage); // Non-HTTP errors
        }

        let detailedMessage = `<h5><i class="bi bi-exclamation-triangle-fill text-${
          alertType === "danger" ? "danger" : "warning"
        } me-2"></i>Send Failed</h5><p class="lead">${errorMessage}</p>`;

        if (body.results && body.results.length > 0) {
          detailedMessage +=
            '<p class="mt-2 mb-1">Partial results (processing may have stopped):</p>';
          detailedMessage += renderResultsTable(body.results);
        }
        displayStatus(detailedMessage, alertType);
      }
    })
    .catch((error) => {
      // Handle fetch errors (network issues) or errors thrown from response processing
      console.error("Fetch/Processing Error:", error);
      let message = "An unexpected client-side error occurred.";
      let alertType = "danger";

      if (error instanceof TypeError) {
        // Likely a network error
        message = `Network error: ${error.message}. Could not reach the server. Please check your connection.`;
      } else if (error.error) {
        // Errors thrown from response processing
        message = error.error; // Use the error message from the thrown object
        if (error.statusCode === 401) {
          message = `Authentication Error (${error.statusCode}): ${escapeHtml(
            message
          )}. Reload and re-authenticate.`;
        } else if (error.statusCode === 429) {
          message = `Rate Limit Exceeded (${error.statusCode}): ${escapeHtml(
            message
          )}. Please wait before trying again.`;
          alertType = "warning";
        } else if (error.statusCode) {
          message = `Error ${error.statusCode}: ${escapeHtml(message)}`;
        } else {
          message = escapeHtml(message);
        }
      } else if (error.message) {
        // Generic JS errors
        message = error.message;
      }

      displayStatus(
        `<h5><i class="bi bi-wifi-off text-danger me-2"></i>Error Occurred</h5> <p>${message}</p>`,
        alertType
      );
    })
    .finally(() => {
      sendButton.disabled = false; // Re-enable button, validity check will run again on next input
      spinner.style.display = "none";
      if (sendButtonIcon) sendButtonIcon.style.display = "inline-block";
      checkFormValidityAndButtonStates(); // Re-evaluate button states after send attempt
    });
}

function renderResultsTable(results) {
  if (!results || results.length === 0) return "";

  let tableHtml = `
        <div class="table-responsive mt-3" style="max-height: 400px; overflow-y: auto;">
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
        iconClass = "bi-check-circle-fill";
        break;
      case "skipped":
        statusClass = "text-warning";
        iconClass = "bi-skip-forward-fill";
        break;
      case "failed":
        statusClass = "text-danger";
        iconClass = "bi-x-octagon-fill";
        break;
      case "aborted":
        statusClass = "text-danger fw-bold";
        iconClass = "bi-stop-circle-fill";
        break;
      case "warning":
        statusClass = "text-info";
        iconClass = "bi-exclamation-circle-fill";
        statusText = "Processed with Warning"; // More descriptive
        break;
      default:
        statusClass = "text-muted";
        iconClass = "bi-question-circle";
    }

    const reasonHtml = r.reason
      ? `<span title="${escapeHtml(r.reason)}">${escapeHtml(
          r.reason.substring(0, 150) // Keep truncation
        )}${r.reason.length > 150 ? "..." : ""}</span>`
      : '<span class="text-muted">N/A</span>';
    const recipientHtml = escapeHtml(r.recipient || "N/A");
    const rowNum = r.row || index + 1; // Use index as fallback for row number

    tableHtml += `
            <tr>
              <td>${rowNum}</td>
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

  // Clear any existing timeout for auto-dismiss messages
  if (infoStatusTimeout) {
    clearTimeout(infoStatusTimeout);
    infoStatusTimeout = null;
  }

  // Determine the style and behavior
  let alertClass = `alert-${type}`;
  let shouldScroll = false;
  let autoDismiss = false;
  let iconHtml = "";

  if (isLoading) {
    alertClass = "alert-info";
    iconHtml =
      '<div class="spinner-border spinner-border-sm flex-shrink-0 me-3" role="status" style="margin-top: 0.15rem;"><span class="visually-hidden">Loading...</span></div>';
    shouldScroll = true;
  } else {
    // Define icons for different types
    switch (type) {
      case "success":
        iconHtml = '<i class="bi bi-check-circle-fill flex-shrink-0 me-2"></i>';
        shouldScroll = true;
        break;
      case "warning":
        alertClass = "alert-warning"; // Ensure correct class for warning
        iconHtml =
          '<i class="bi bi-exclamation-triangle-fill flex-shrink-0 me-2"></i>';
        // shouldScroll = true; // Optionally scroll for warnings
        break;
      case "danger":
        iconHtml = '<i class="bi bi-x-octagon-fill flex-shrink-0 me-2"></i>';
        shouldScroll = true;
        break;
      case "info":
      default: // Default to info style
        alertClass = "alert-secondary"; // Use secondary for less intrusive info
        iconHtml = '<i class="bi bi-info-circle-fill flex-shrink-0 me-2"></i>'; // Use filled icon
        autoDismiss = true; // Auto-dismiss simple info messages
        break;
    }
  }

  const alertDiv = document.createElement("div");
  alertDiv.className = `alert ${alertClass} d-flex align-items-start fade show`;
  alertDiv.setAttribute("role", "alert");
  alertDiv.innerHTML = `
        ${iconHtml}
        <div class="flex-grow-1">${message}</div>
        <button type="button" class="btn-close ms-2" data-bs-dismiss="alert" aria-label="Close" style="margin-top: -0.2rem;"></button>
    `;

  statusMessageDiv.innerHTML = ""; // Clear previous messages
  statusMessageDiv.appendChild(alertDiv);

  if (shouldScroll) {
    statusMessageDiv.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  if (autoDismiss) {
    infoStatusTimeout = setTimeout(() => {
      const currentAlert = statusMessageDiv.querySelector(".alert");
      // Only dismiss if it's still the same auto-dismiss alert
      if (
        currentAlert &&
        (currentAlert.classList.contains("alert-secondary") ||
          currentAlert.classList.contains("alert-info")) &&
        !isLoading
      ) {
        const bsAlert = bootstrap.Alert.getOrCreateInstance(currentAlert);
        if (bsAlert) {
          bsAlert.close();
        } else {
          currentAlert.remove();
        }
      }
      infoStatusTimeout = null;
    }, 5000); // Dismiss after 5 seconds
  }
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== "string") {
    try {
      // Convert non-strings carefully
      if (unsafe === null || typeof unsafe === "undefined") return "";
      unsafe = String(unsafe);
    } catch (e) {
      console.warn("Could not convert value to string for escaping:", unsafe);
      return "Invalid Value";
    }
  }
  // Basic HTML escaping
  return unsafe
    .replace(/&/g, "&") // Must be first
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "'");
}

function insertPlaceholderIntoInput(targetId) {
  if (currentMode !== "csv" || csvHeaders.length === 0) {
    displayStatus(
      "Placeholders only available in CSV mode with loaded headers.",
      "info"
    );
    return;
  }
  const header = prompt(
    `Enter the CSV header name to insert (case-sensitive):\nAvailable: ${csvHeaders.join(
      ", "
    )}`
  );
  const targetInput = document.getElementById(targetId);
  if (header && csvHeaders.includes(header.trim()) && targetInput) {
    const placeholderText = `{${header.trim()}}`;
    const start = targetInput.selectionStart;
    const end = targetInput.selectionEnd;
    const text = targetInput.value;
    targetInput.value =
      text.substring(0, start) + placeholderText + text.substring(end);
    targetInput.focus();
    targetInput.setSelectionRange(
      start + placeholderText.length,
      start + placeholderText.length
    );
    checkFormValidityAndButtonStates(); // Update buttons after insertion
  } else if (header) {
    displayStatus(
      `Header "${header.trim()}" not found or target input missing.`,
      "warning"
    );
  }
}

function validateAttachments(showErrorMessages = true) {
  const attachmentInput = document.getElementById("attachments");
  const errorDiv = document.getElementById("attachment-error");
  const files = attachmentInput.files;
  errorDiv.textContent = ""; // Clear previous errors

  if (files.length > appLimits.MAX_ATTACHMENTS_PER_EMAIL) {
    if (showErrorMessages) {
      errorDiv.textContent = `Too many files selected. Maximum is ${appLimits.MAX_ATTACHMENTS_PER_EMAIL}.`;
      displayStatus(
        `Attachment Error: Too many files. Max ${appLimits.MAX_ATTACHMENTS_PER_EMAIL}.`,
        "warning"
      );
    }
    return false;
  }

  let totalSize = 0;
  for (let i = 0; i < files.length; i++) {
    totalSize += files[i].size;
  }

  if (totalSize > MAX_TOTAL_ATTACHMENT_SIZE_BYTES) {
    if (showErrorMessages) {
      errorDiv.textContent = `Total attachment size exceeds limit (${
        appLimits.MAX_TOTAL_ATTACHMENT_SIZE_MB
      } MB). Current size: ${(totalSize / (1024 * 1024)).toFixed(1)} MB.`;
      displayStatus(
        `Attachment Error: Total size exceeds ${appLimits.MAX_TOTAL_ATTACHMENT_SIZE_MB} MB.`,
        "warning"
      );
    }
    return false;
  }

  return true;
}

function updateAttachmentList() {
  const attachmentInput = document.getElementById("attachments");
  const listDiv = document.getElementById("attachment-list");
  listDiv.innerHTML = ""; // Clear existing list

  if (!attachmentInput.files || attachmentInput.files.length === 0) {
    return;
  }

  const files = Array.from(attachmentInput.files);
  const list = document.createElement("ul");
  list.className = "list-unstyled mb-0 small";
  let totalSize = 0;

  files.forEach((file) => {
    const li = document.createElement("li");
    li.className =
      "text-muted d-flex justify-content-between align-items-center";
    const fileSizeKB = (file.size / 1024).toFixed(1);
    totalSize += file.size;
    li.innerHTML = `
            <span><i class="bi bi-file-earmark-arrow-up me-1"></i> ${escapeHtml(
              file.name
            )}</span>
            <span class="ms-2 text-nowrap">${fileSizeKB} KB</span>
        `;
    list.appendChild(li);
  });

  const summary = document.createElement("li");
  summary.className = "mt-1 pt-1 border-top fw-medium";
  const totalSizeMB = (totalSize / (1024 * 1024)).toFixed(1);
  summary.textContent = `Total: ${files.length} file(s), ${totalSizeMB} MB / ${appLimits.MAX_TOTAL_ATTACHMENT_SIZE_MB} MB`;
  list.appendChild(summary);

  listDiv.appendChild(list);
}

function handleAttachmentChange(event) {
  updateAttachmentList();
  if (!validateAttachments(true)) {
    // Optionally clear the input if invalid to force re-selection
    // event.target.value = null;
    // updateAttachmentList(); // Update list again if cleared
  }
  checkFormValidityAndButtonStates();
}

function parseManualRecipients(rawValue) {
  return rawValue
    .split(/[\s,;\n]+/) // Split by spaces, commas, semicolons, newlines
    .map((email) => email.trim())
    .filter(
      (email) => email !== "" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ); // Basic email format check
}

function countManualRecipients(rawValue) {
  // Simpler count just based on separators, less accurate but faster for UI feedback
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
  initializeQuill();

  const csvFileInput = document.getElementById("csv-file");
  const previewButton = document.getElementById("preview-button");
  const emailForm = document.getElementById("email-form");
  const modeTabs = document.querySelectorAll(
    '#modeTabs button[data-bs-toggle="tab"]'
  );
  const attachmentInput = document.getElementById("attachments");
  const manualRecipientsTextarea = document.getElementById("manual-recipients");

  if (emailForm) emailForm.addEventListener("submit", handleFormSubmit);

  modeTabs.forEach((tab) => {
    tab.addEventListener("shown.bs.tab", handleModeChange);
  });

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
    ); // Also check main buttons
  }

  document.querySelectorAll(".placeholder-inserter-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("data-target");
      if (targetId) {
        insertPlaceholderIntoInput(targetId);
      }
    });
  });

  // Add input listeners to relevant fields to check form validity
  ["recipient-template", "subject-template"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", checkFormValidityAndButtonStates);
  });
  if (quill) {
    quill.on("text-change", () => {
      // Update hidden input for form submission
      document.getElementById("body-template").value = quill.root.innerHTML;
      checkFormValidityAndButtonStates();
    });
  }

  // Initial setup
  resetCsvState(); // Resets CSV specific state and buttons
  currentMode =
    document
      .querySelector("#modeTabs .nav-link.active")
      ?.getAttribute("data-mode") || "csv";
  document.getElementById("current-mode").value = currentMode;
  updatePlaceholderInsertersState(); // Set initial state based on mode
  updateManualRecipientCounter(); // Set initial count for manual mode
  checkFormValidityAndButtonStates(); // Set initial button states
});
