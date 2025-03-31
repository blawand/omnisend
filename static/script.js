let quill;
let csvHeaders = [];
let csvFirstRow = null;
let csvFileHandle = null;
let currentMode = "csv"; // 'csv' or 'manual'

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

  // Customize the placeholder button icon
  const placeholderButton = document.querySelector(".ql-insertPlaceholder");
  if (placeholderButton) {
    placeholderButton.innerHTML = '<i class="bi bi-paperclip"></i>';
    placeholderButton.title = "Insert CSV Placeholder";
  }
  updatePlaceholderInsertersState(); // Initial state
}

function insertPlaceholderHandler() {
  if (currentMode !== "csv" || csvHeaders.length === 0) {
    alert(
      "Placeholders are only available in CSV mode after uploading a valid CSV file with headers."
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
    alert(
      `Header "${header.trim()}" not found in the detected CSV headers. Please check spelling and case.`
    );
  }
}

function handleModeChange(event) {
  const newMode = event.target.getAttribute("data-mode");
  if (newMode && newMode !== currentMode) {
    currentMode = newMode;
    document.getElementById("current-mode").value = currentMode;
    console.log("Switched to mode:", currentMode);

    // Toggle visibility based on mode (though Bootstrap tabs handle pane visibility)
    const csvSection = document.getElementById("csv-mode-pane");
    const manualSection = document.getElementById("manual-mode-pane");

    // Update UI elements like placeholder buttons, preview button state etc.
    updatePlaceholderInsertersState();
    resetPreview();
    checkPreviewButtonState();

    // Optionally clear fields when switching modes if desired
    // if (newMode === 'manual') {
    //     document.getElementById('csv-file').value = '';
    //     resetCsvState();
    // } else {
    //     document.getElementById('manual-recipients').value = '';
    // }
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

  // Update tooltip or other visual cues if needed
}

function handleCsvFileSelect(event) {
  const file = event.target.files[0];
  const headersSection = document.getElementById("csv-headers-section");
  const headersContainer = document.getElementById("headers-container");

  resetCsvState(); // Clear previous CSV info

  if (!file) {
    displayStatus("Please select a CSV file.", "warning");
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
      // Manually trigger mode change logic if bootstrap event doesn't fire fast enough
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
    preview: 2, // Only need header and first row for preview/headers
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
        csvFileHandle = null; // Invalidate handle on error
        headersSection.classList.add("d-none");
        resetCsvState(); // Fully reset
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

      csvHeaders = results.meta.fields.filter((h) => h && h.trim() !== ""); // Filter out empty headers
      csvFirstRow = results.data.length > 0 ? results.data[0] : null;

      headersContainer.innerHTML = ""; // Clear parsing message
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
                // Optional: brief feedback e.g., change color or show tooltip
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
          csvFirstRow
            ? "First data row available for preview."
            : "No data rows found for preview."
        }`,
        "success"
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
  // Do not reset csvFileHandle here, keep it until a new file is selected or mode changes significantly
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
  const bodyFilled = quill && quill.getLength() > 1; // More than just the initial newline

  if (currentMode === "csv") {
    previewButton.disabled = !(
      csvFirstRow &&
      subjectFilled &&
      bodyFilled &&
      document.getElementById("recipient-template").value.trim() !== ""
    );
  } else {
    // Manual mode
    const recipientsFilled =
      document.getElementById("manual-recipients").value.trim() !== "";
    previewButton.disabled = !(recipientsFilled && subjectFilled && bodyFilled);
  }
}

function generatePreview() {
  const previewArea = document.getElementById("preview-area");
  const previewContext = document.getElementById("preview-context");
  resetPreview(); // Clear previous preview first

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

    // Find all unique placeholders in templates
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

    // Replace placeholders with data from the first row
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
    // Manual Mode
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

    // Check for literal placeholders in manual mode templates
    [subjectTemplate, bodyTemplateHtml].forEach((template) => {
      let match;
      while ((match = placeholderRegex.exec(template)) !== null) {
        unresolvedPlaceholders.add(match[0]);
      }
    });
  }

  // Display Preview
  document.getElementById("preview-to").textContent = previewTo || "(empty)";
  document.getElementById("preview-subject").textContent =
    previewSubject || "(empty)";
  document.getElementById("preview-body").innerHTML =
    previewBody || "<p>(empty)</p>";
  previewContext.textContent = contextText;

  // Display attached file names in preview
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

  // Display warnings/info
  if (currentMode === "csv" && unresolvedPlaceholders.size > 0) {
    displayStatus(
      `<strong>Preview Generated.</strong> <strong class="text-danger">Warning:</strong> Unresolved placeholders found: ${[
        ...unresolvedPlaceholders,
      ].join(
        ", "
      )}. Check spelling/case against CSV headers. Emails for rows with unresolved placeholders may be skipped.`,
      "warning"
    );
  } else if (currentMode === "manual" && unresolvedPlaceholders.size > 0) {
    displayStatus(
      `<strong>Preview Generated.</strong> <strong class="text-warning">Note:</strong> Placeholders detected (${[
        ...unresolvedPlaceholders,
      ].join(
        ", "
      )}) in Subject or Body. In Manual mode, these will be sent literally and NOT replaced with data.`,
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

  // Basic Validations common to both modes
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

  // Mode-specific validations
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
    // Manual mode
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
  formData.set("mode", currentMode); // Ensure mode is explicitly set

  // Ensure the correct file handle is included if in CSV mode
  if (
    currentMode === "csv" &&
    csvFileHandle &&
    (!formData.has("csv_file") || !formData.get("csv_file").size)
  ) {
    formData.set("csv_file", csvFileHandle, csvFileHandle.name);
  } else if (currentMode === "manual" && formData.has("csv_file")) {
    // Remove potentially stale CSV file if switching from CSV to manual before submit
    formData.delete("csv_file");
  }

  sendButton.disabled = true;
  spinner.style.display = "inline-block";
  if (sendButtonIcon) sendButtonIcon.style.display = "none";
  displayStatus(
    "Sending emails... Please wait. You might be prompted to authenticate with Google (check for pop-ups or new tabs). This can take time.",
    "info",
    true // isLoading = true
  );

  fetch("/send-emails", {
    method: "POST",
    body: formData,
  })
    .then((response) => {
      if (!response.ok) {
        // Try to parse JSON error body, otherwise use status text
        return response
          .json()
          .catch(() => {
            // If JSON parsing fails, create a simpler error object
            return {
              error: `Server responded with status: ${response.status} ${response.statusText}`,
              statusCode: response.status,
            };
          })
          .then((errData) => {
            // Ensure statusCode is set if not already present
            if (!errData.statusCode) errData.statusCode = response.status;
            throw errData; // Throw the structured error object
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
        // Handle structured error from backend (or the one created in .catch above)
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
      // Catch fetch errors (network, CORS) or thrown errors from .then blocks
      console.error("Fetch/Processing Error:", error);
      let message = "An unexpected error occurred.";
      if (error instanceof TypeError) {
        // Network error
        message = `Network error: ${error.message}. Could not reach the server.`;
      } else if (error.error) {
        // Structured error from .then block
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
        // Other JS errors
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
    const rowNum = r.row || results.indexOf(r) + 1; // Use index+1 if row number missing

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
  const statusMessage = document.getElementById("status-message");
  // Ensure spinner only shows when explicitly loading, not for standard info/success/warning/danger messages
  const showSpinner = isLoading && type === "info";
  statusMessage.innerHTML = `
        <div class="alert alert-${type} d-flex align-items-start fade show" role="alert">
             ${
               showSpinner
                 ? '<div class="spinner-border spinner-border-sm flex-shrink-0 me-3" role="status" style="margin-top: 0.15rem;"><span class="visually-hidden">Loading...</span></div>'
                 : "" // No spinner for non-loading messages
             }
            <div class="flex-grow-1">${message}</div>
             <button type="button" class="btn-close ms-2" data-bs-dismiss="alert" aria-label="Close" style="margin-top: -0.2rem;"></button>
        </div>
    `;
  // Scroll into view if it's an important message (error/success)
  if (type === "danger" || type === "success" || isLoading) {
    statusMessage.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== "string") {
    // Attempt to convert non-strings safely
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
    alert(
      "Placeholders are only available in CSV mode after uploading a valid CSV file with headers."
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
    checkPreviewButtonState(); // Re-check if preview is possible now
  } else if (header) {
    alert(
      `Header "${header.trim()}" not found in the detected CSV headers or target input not found. Please check spelling and case.`
    );
  }
}

// Event Listeners
document.addEventListener("DOMContentLoaded", function () {
  initializeQuill();

  const csvFileInput = document.getElementById("csv-file");
  const previewButton = document.getElementById("preview-button");
  const emailForm = document.getElementById("email-form");
  const modeTabs = document.querySelectorAll(
    '#modeTabs button[data-bs-toggle="tab"]'
  );
  const attachmentInput = document.getElementById("attachments");

  // Form Submission
  if (emailForm) emailForm.addEventListener("submit", handleFormSubmit);

  // Mode Switching
  modeTabs.forEach((tab) => {
    tab.addEventListener("shown.bs.tab", handleModeChange); // Use Bootstrap event
  });

  // CSV File Input
  if (csvFileInput)
    csvFileInput.addEventListener("change", handleCsvFileSelect);

  // Preview Button
  if (previewButton) previewButton.addEventListener("click", generatePreview);

  // Placeholder Inserter Buttons (for input fields)
  document.querySelectorAll(".placeholder-inserter-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.getAttribute("data-target");
      if (targetId) {
        insertPlaceholderIntoInput(targetId);
      }
    });
  });

  // Attachment List Update
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
      checkPreviewButtonState(); // Check if adding/removing attachments affects preview readiness (it doesn't directly, but good practice)
    });
  }

  // Add event listeners to inputs affecting preview readiness
  ["recipient-template", "subject-template", "manual-recipients"].forEach(
    (id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", checkPreviewButtonState);
    }
  );
  if (quill) {
    quill.on("text-change", checkPreviewButtonState);
  }

  // Initial State Setup
  resetCsvState(); // Includes resetting preview and button states
  checkPreviewButtonState(); // Check initial state
  currentMode =
    document
      .querySelector("#modeTabs .nav-link.active")
      .getAttribute("data-mode") || "csv"; // Set initial mode from active tab
  document.getElementById("current-mode").value = currentMode;
  updatePlaceholderInsertersState(); // Ensure correct initial state for placeholder buttons
});
