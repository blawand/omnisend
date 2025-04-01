let quill;
let csvHeaders = [];
let csvFirstRow = null;
let csvFileHandle = null;
let currentMode = "csv";
let infoStatusTimeout = null;

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
    const csvSection = document.getElementById("csv-mode-pane");
    const manualSection = document.getElementById("manual-mode-pane");
    updatePlaceholderInsertersState();
    resetPreview();
    checkPreviewButtonState();
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
  if (file && file.size > 16777216) {
    displayStatus("File size exceeds 16 MB limit.", "danger");
    event.target.value = "";
    return;
  }
  const headersSection = document.getElementById("csv-headers-section");
  const headersContainer = document.getElementById("headers-container");
  resetCsvState();
  if (!file) {
    headersContainer.innerHTML =
      '<span class="text-muted small">No file selected.</span>';
    headersSection.classList.add("d-none");
    return;
  }
  if (currentMode !== "csv") {
    displayStatus("Switched to CSV mode as a file was uploaded.", "info");
    const csvTab = document.getElementById("csv-mode-tab");
    if (csvTab) {
      const tab = new bootstrap.Tab(csvTab);
      tab.show();
      currentMode = "csv";
      document.getElementById("current-mode").value = currentMode;
    }
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
        resetCsvState();
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
      checkPreviewButtonState();
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
  const headersSection = document.getElementById("csv-headers-section");
  const headersContainer = document.getElementById("headers-container");
  if (headersSection) headersSection.classList.add("d-none");
  if (headersContainer)
    headersContainer.innerHTML =
      '<span class="text-muted small">Upload a CSV to see headers.</span>';
  updatePlaceholderInsertersState();
  checkPreviewButtonState();
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

function checkPreviewButtonState() {
  const previewButton = document.getElementById("preview-button");
  if (!previewButton) return;
  const subjectFilled =
    document.getElementById("subject-template").value.trim() !== "";
  const bodyFilled = quill && quill.getLength() > 1;
  if (currentMode === "csv") {
    previewButton.disabled = !(
      csvFirstRow &&
      subjectFilled &&
      bodyFilled &&
      document.getElementById("recipient-template").value.trim() !== ""
    );
  } else {
    const recipientsFilled =
      document.getElementById("manual-recipients").value.trim() !== "";
    previewButton.disabled = !(recipientsFilled && subjectFilled && bodyFilled);
  }
}

function generatePreview() {
  const previewArea = document.getElementById("preview-area");
  const previewContext = document.getElementById("preview-context");
  resetPreview();
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
    const manualRecipientsRaw =
      document.getElementById("manual-recipients").value;
    const firstRecipient = manualRecipientsRaw.split(/[, \n]+/)[0].trim();
    if (!firstRecipient) {
      displayStatus(
        "Please enter at least one recipient email for Manual mode preview.",
        "warning"
      );
      return;
    }
    previewTo =
      firstRecipient +
      (manualRecipientsRaw.includes(",") ||
      manualRecipientsRaw.includes(" ") ||
      manualRecipientsRaw.includes("\n")
        ? " (and others)"
        : "");
    contextText = "(Manual mode preview - Placeholders NOT replaced)";
    [subjectTemplate, bodyTemplateHtml].forEach((template) => {
      let match;
      while ((match = placeholderRegex.exec(template)) !== null) {
        unresolvedPlaceholders.add(match[0]);
      }
    });
  }
  document.getElementById("preview-to").textContent = previewTo || "(empty)";
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
      ].join(", ")}. Check spelling/case.`,
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
    if (!document.getElementById("manual-recipients").value.trim()) {
      displayStatus(
        "Please enter at least one recipient email for Manual mode.",
        "warning"
      );
      return;
    }
  }
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
    formData.delete("csv_file");
  }
  sendButton.disabled = true;
  spinner.style.display = "inline-block";
  if (sendButtonIcon) sendButtonIcon.style.display = "none";
  displayStatus(
    "Sending emails... Please wait. You might be prompted to authenticate with Google (check for pop-ups or new tabs). This can take time.",
    "info",
    true
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
            return {
              error: `Server responded with status: ${response.status} ${response.statusText}`,
              statusCode: response.status,
            };
          })
          .then((errData) => {
            if (!errData.statusCode) errData.statusCode = response.status;
            throw errData;
          });
      }
      return response.json();
    })
    .then((body) => {
      if (body.success) {
        let message = `<h5><i class="bi bi-check-circle-fill text-success me-2"></i>Process Complete</h5><p class="lead">${escapeHtml(
          body.message
        )}</p>`;
        if (body.results && body.results.length > 0) {
          message += renderResultsTable(body.results);
        }
        displayStatus(message, "success");
      } else {
        console.error("Send Error Response:", body);
        let errorMessage =
          body.error || "An unknown error occurred during sending.";
        if (body.statusCode === 401) {
          errorMessage = `Authentication Error (${
            body.statusCode
          }): ${escapeHtml(
            body.error || ""
          )}. Please ensure you granted permission. Try reloading the page and authenticating again. Check if 'credentials.json' exists on the server.`;
        } else if (body.statusCode) {
          errorMessage = `Error ${body.statusCode}: ${escapeHtml(
            errorMessage
          )}`;
        } else {
          errorMessage = escapeHtml(errorMessage);
        }
        let detailedMessage = `<h5><i class="bi bi-exclamation-triangle-fill text-danger me-2"></i>Send Failed</h5><p class="lead">${errorMessage}</p>`;
        if (body.results && body.results.length > 0) {
          detailedMessage +=
            '<p class="mt-2 mb-1">Partial results (processing may have stopped):</p>';
          detailedMessage += renderResultsTable(body.results);
        }
        displayStatus(detailedMessage, "danger");
      }
    })
    .catch((error) => {
      console.error("Fetch/Processing Error:", error);
      let message = "An unexpected error occurred.";
      if (error instanceof TypeError) {
        message = `Network error: ${error.message}. Could not reach the server.`;
      } else if (error.error) {
        message = error.error;
        if (error.statusCode === 401) {
          message = `Authentication Error (${error.statusCode}): ${escapeHtml(
            message
          )}. Please reload and re-authenticate. Check server logs and 'credentials.json'.`;
        } else if (error.statusCode) {
          message = `Error ${error.statusCode}: ${escapeHtml(message)}`;
        } else {
          message = escapeHtml(message);
        }
      } else if (error.message) {
        message = error.message;
      }
      displayStatus(
        `<h5><i class="bi bi-wifi-off text-danger me-2"></i>Error Occurred</h5> <p>${message}</p>`,
        "danger"
      );
    })
    .finally(() => {
      sendButton.disabled = false;
      spinner.style.display = "none";
      if (sendButtonIcon) sendButtonIcon.style.display = "inline-block";
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
  results.forEach((r) => {
    let statusClass = "";
    let iconClass = "";
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
      default:
        statusClass = "text-muted";
        iconClass = "bi-question-circle";
    }
    const reasonHtml = r.reason
      ? `<span title="${escapeHtml(r.reason)}">${escapeHtml(
          r.reason.substring(0, 150)
        )}${r.reason.length > 150 ? "..." : ""}</span>`
      : '<span class="text-muted">N/A</span>';
    const recipientHtml = escapeHtml(r.recipient || "N/A");
    const rowNum = r.row || results.indexOf(r) + 1;
    tableHtml += `
            <tr>
              <td>${rowNum}</td>
              <td>${recipientHtml}</td>
              <td class="${statusClass}"><i class="bi ${iconClass} me-1"></i>${escapeHtml(
      r.status
    )}</td>
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
  let iconHtml = "";
  if (isLoading) {
    alertClass = "alert-info";
    iconHtml =
      '<div class="spinner-border spinner-border-sm flex-shrink-0 me-3" role="status" style="margin-top: 0.15rem;"><span class="visually-hidden">Loading...</span></div>';
    shouldScroll = true;
  } else if (type === "info") {
    alertClass = "alert-secondary";
    autoDismiss = true;
    iconHtml = '<i class="bi bi-info-circle flex-shrink-0 me-2"></i>';
  } else if (type === "success") {
    iconHtml = '<i class="bi bi-check-circle-fill flex-shrink-0 me-2"></i>';
    shouldScroll = true;
  } else if (type === "warning") {
    iconHtml =
      '<i class="bi bi-exclamation-triangle-fill flex-shrink-0 me-2"></i>';
  } else if (type === "danger") {
    iconHtml = '<i class="bi bi-x-octagon-fill flex-shrink-0 me-2"></i>';
    shouldScroll = true;
  }
  const alertDiv = document.createElement("div");
  alertDiv.className = `alert ${alertClass} d-flex align-items-start fade show`;
  alertDiv.setAttribute("role", "alert");
  alertDiv.innerHTML = `
        ${iconHtml}
        <div class="flex-grow-1">${message}</div>
        <button type="button" class="btn-close ms-2" data-bs-dismiss="alert" aria-label="Close" style="margin-top: -0.2rem;"></button>
    `;
  statusMessageDiv.innerHTML = "";
  statusMessageDiv.appendChild(alertDiv);
  if (shouldScroll) {
    statusMessageDiv.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  if (autoDismiss) {
    infoStatusTimeout = setTimeout(() => {
      const currentAlert = statusMessageDiv.querySelector(".alert");
      if (currentAlert && currentAlert.classList.contains("alert-secondary")) {
        const bsAlert = bootstrap.Alert.getOrCreateInstance(currentAlert);
        if (bsAlert) {
          bsAlert.close();
        } else {
          currentAlert.remove();
        }
      }
      infoStatusTimeout = null;
    }, 4000);
  }
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== "string") {
    try {
      return String(unsafe)
        .replace(/&/g, "&")
        .replace(/</g, "<")
        .replace(/>/g, ">")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "'");
    } catch (e) {
      return "Invalid Value";
    }
  }
  return unsafe
    .replace(/&/g, "&")
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
    checkPreviewButtonState();
  } else if (header) {
    displayStatus(
      `Header "${header.trim()}" not found or target input missing.`,
      "warning"
    );
  }
}

document.addEventListener("DOMContentLoaded", function () {
  initializeQuill();
  const csvFileInput = document.getElementById("csv-file");
  const previewButton = document.getElementById("preview-button");
  const emailForm = document.getElementById("email-form");
  const modeTabs = document.querySelectorAll(
    '#modeTabs button[data-bs-toggle="tab"]'
  );
  const attachmentInput = document.getElementById("attachments");
  if (emailForm) emailForm.addEventListener("submit", handleFormSubmit);
  modeTabs.forEach((tab) => {
    tab.addEventListener("shown.bs.tab", handleModeChange);
  });
  if (csvFileInput)
    csvFileInput.addEventListener("change", handleCsvFileSelect);
  if (previewButton) previewButton.addEventListener("click", generatePreview);
  document.querySelectorAll(".placeholder-inserter-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("data-target");
      if (targetId) {
        insertPlaceholderIntoInput(targetId);
      }
    });
  });
  if (attachmentInput) {
    attachmentInput.addEventListener("change", (event) => {
      const listDiv = document.getElementById("attachment-list");
      listDiv.innerHTML = "";
      if (event.target.files.length > 0) {
        const files = Array.from(event.target.files);
        const list = document.createElement("ul");
        list.className = "list-unstyled mb-0 small";
        files.forEach((file) => {
          const li = document.createElement("li");
          li.className = "text-muted";
          li.innerHTML = `<i class="bi bi-file-earmark-arrow-up me-1"></i> ${escapeHtml(
            file.name
          )} (${(file.size / 1024).toFixed(1)} KB)`;
          list.appendChild(li);
        });
        listDiv.appendChild(list);
      }
      checkPreviewButtonState();
    });
  }
  ["recipient-template", "subject-template", "manual-recipients"].forEach(
    (id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", checkPreviewButtonState);
    }
  );
  if (quill) {
    quill.on("text-change", checkPreviewButtonState);
  }
  resetCsvState();
  checkPreviewButtonState();
  currentMode =
    document
      .querySelector("#modeTabs .nav-link.active")
      .getAttribute("data-mode") || "csv";
  document.getElementById("current-mode").value = currentMode;
  updatePlaceholderInsertersState();
});
