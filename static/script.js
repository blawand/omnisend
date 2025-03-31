let quill;
let csvHeaders = [];
let csvFirstRow = null;
let csvFileHandle = null;

function initializeQuill() {
  quill = new Quill("#editor-container", {
    theme: "snow",
    modules: {
      toolbar: [
        [{ header: [1, 2, 3, false] }, { font: [] }],
        [
          "bold",
          "italic",
          "underline",
          "strike",
          { color: [] },
          { background: [] },
        ],
        [
          { list: "ordered" },
          { list: "bullet" },
          { indent: "-1" },
          { indent: "+1" },
        ],
        [{ script: "sub" }, { script: "super" }, { align: [] }],
        ["link", "image", "blockquote", "code-block"],
        ["clean"],
      ],
    },
    placeholder:
      "Compose your email template here... Use {Placeholders} for dynamic content.",
  });
}

function handleCsvFileSelect(event) {
  const file = event.target.files[0];
  const previewButton = document.getElementById("preview-button");
  const headersListDiv = document.getElementById("csv-headers-list");
  const headersContainer = document.getElementById("headers-container");

  resetCsvState();

  if (!file) {
    displayStatus("Please select a CSV file.", "warning");
    headersContainer.innerHTML =
      '<span class="text-muted small">No file selected.</span>';
    return;
  }

  csvFileHandle = file;
  previewButton.disabled = true;
  headersContainer.innerHTML =
    '<span class="text-muted small">Parsing CSV...</span>';
  headersListDiv.classList.remove("visually-hidden");

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
          `Error parsing CSV:<br>${errorMsg}.<br>Please check the file format, encoding (UTF-8 recommended), and ensure headers are present.`,
          "danger"
        );
        previewButton.disabled = true;
        headersContainer.innerHTML =
          '<span class="text-danger small">Error parsing CSV.</span>';
        csvFileHandle = null;
        return;
      }

      if (!results.meta.fields || results.meta.fields.length === 0) {
        displayStatus(
          "CSV file seems to be empty or does not contain valid headers in the first row.",
          "warning"
        );
        previewButton.disabled = true;
        headersContainer.innerHTML =
          '<span class="text-warning small">No headers found.</span>';
        csvFileHandle = null;
        return;
      }

      if (!results.data || results.data.length === 0) {
        displayStatus("CSV file contains headers but no data rows.", "warning");
      }

      csvHeaders = results.meta.fields.filter((h) => h);
      csvFirstRow = results.data.length > 0 ? results.data[0] : null;

      headersContainer.innerHTML = "";
      if (csvHeaders.length > 0) {
        csvHeaders.forEach((header) => {
          const badge = document.createElement("span");
          badge.className = "badge bg-secondary me-1 mb-1 fw-normal";
          badge.textContent = header;
          badge.title = `Use {${header}} in templates`;
          headersContainer.appendChild(badge);
        });
      } else {
        headersContainer.innerHTML =
          '<span class="text-warning small">No valid headers detected.</span>';
      }

      previewButton.disabled = !csvFirstRow;
      displayStatus(
        `CSV loaded: ${csvHeaders.length} headers detected. ${
          csvFirstRow ? "Preview enabled." : "No data rows found for preview."
        }`,
        "success"
      );
    },
    error: function (error, file) {
      console.error("CSV Parsing Failed:", error);
      displayStatus(
        `Failed to parse CSV file: ${error}. Check file encoding and format.`,
        "danger"
      );
      previewButton.disabled = true;
      headersContainer.innerHTML =
        '<span class="text-danger small">Failed to parse CSV.</span>';
      csvFileHandle = null;
    },
  });
}

function resetCsvState() {
  csvHeaders = [];
  csvFirstRow = null;
  csvFileHandle = null;
  const previewButton = document.getElementById("preview-button");
  const headersListDiv = document.getElementById("csv-headers-list");
  const headersContainer = document.getElementById("headers-container");
  const previewArea = document.getElementById("preview-area");

  if (previewButton) previewButton.disabled = true;
  if (headersListDiv) headersListDiv.classList.add("visually-hidden");
  if (headersContainer)
    headersContainer.innerHTML =
      '<span class="text-muted small">No headers detected yet.</span>';
  if (previewArea) previewArea.classList.add("visually-hidden");

  const csvInput = document.getElementById("csv-file");
  if (csvInput) {
  }
}

function generatePreview() {
  const previewArea = document.getElementById("preview-area");
  if (!csvFirstRow || csvHeaders.length === 0) {
    displayStatus(
      "Cannot generate preview. Load a valid CSV file with at least one data row.",
      "warning"
    );
    previewArea.classList.add("visually-hidden");
    return;
  }

  const recipientTemplate = document.getElementById("recipient-template").value;
  const subjectTemplate = document.getElementById("subject-template").value;
  const bodyTemplateHtml = quill.root.innerHTML;

  if (!recipientTemplate || !subjectTemplate || quill.getLength() <= 1) {
    displayStatus(
      "Please fill in recipient, subject, and body templates before previewing.",
      "warning"
    );
    previewArea.classList.add("visually-hidden");
    return;
  }

  let previewTo = recipientTemplate;
  let previewSubject = subjectTemplate;
  let previewBody = bodyTemplateHtml;
  let unresolvedPlaceholders = new Set();

  const placeholderRegex = /\{(.+?)\}/g;

  [recipientTemplate, subjectTemplate, bodyTemplateHtml].forEach((template) => {
    let match;
    while ((match = placeholderRegex.exec(template)) !== null) {
      if (!csvHeaders.includes(match[1])) {
        unresolvedPlaceholders.add(match[0]);
      }
    }
  });

  csvHeaders.forEach((header) => {
    const placeholder = new RegExp(`\\{${escapeRegExp(header)}\\}`, "g");
    const value = csvFirstRow[header] || "";
    previewTo = previewTo.replace(placeholder, value);
    previewSubject = previewSubject.replace(placeholder, value);
    previewBody = previewBody.replace(placeholder, value);
  });

  document.getElementById("preview-to").textContent = previewTo || "(empty)";
  document.getElementById("preview-subject").textContent =
    previewSubject || "(empty)";
  document.getElementById("preview-body").innerHTML = previewBody || "(empty)";
  previewArea.classList.remove("visually-hidden");

  if (unresolvedPlaceholders.size > 0) {
    displayStatus(
      `Preview generated. <strong class="text-danger">Warning:</strong> Unresolved placeholders found: ${[
        ...unresolvedPlaceholders,
      ].join(
        ", "
      )}. Check spelling/case against CSV headers. Emails for rows with unresolved placeholders might be skipped.`,
      "warning"
    );
  } else {
    displayStatus(
      "Preview generated successfully using the first data row.",
      "info"
    );
  }
}

function handleFormSubmit(event) {
  event.preventDefault();
  const sendButton = document.getElementById("send-button");
  const spinner = sendButton.querySelector(".spinner-border");
  const sendButtonIcon = sendButton.querySelector("i");

  if (!csvFileHandle) {
    displayStatus("Please upload a CSV file first.", "warning");
    return;
  }

  if (csvHeaders.length === 0) {
    displayStatus(
      "CSV headers not detected or invalid. Please upload a valid CSV with headers.",
      "warning"
    );
    return;
  }

  if (quill.getLength() <= 1 && !quill.getText().trim()) {
    if (
      !confirm(
        "The email body appears empty. Are you sure you want to proceed?"
      )
    ) {
      return;
    }
  }

  document.getElementById("body-template").value = quill.root.innerHTML;
  const formData = new FormData(event.target);

  if (!formData.has("csv_file") || !formData.get("csv_file").size) {
    formData.set("csv_file", csvFileHandle);
  }

  sendButton.disabled = true;
  spinner.style.display = "inline-block";
  if (sendButtonIcon) sendButtonIcon.style.display = "none";
  displayStatus(
    "Sending emails... Please wait. You might be prompted to authenticate with Google (check for pop-ups or new tabs). This can take time depending on the number of emails.",
    "info",
    true
  );

  fetch("/send-emails", {
    method: "POST",
    body: formData,
  })
    .then((response) => {
      if (!response.ok) {
        return response.json().then((errData) => {
          errData.statusCode = response.status;
          throw errData;
        });
      }
      return response.json();
    })
    .then((body) => {
      if (body.success) {
        let message = `<h5><i class="bi bi-check-circle-fill text-success me-2"></i>Process Complete</h5><strong>${body.message}</strong>`;
        if (body.results && body.results.length > 0) {
          message +=
            '<div class="mt-3" style="max-height: 300px; overflow-y: auto;"><ul class="list-group list-group-flush">';
          body.results.forEach((r) => {
            let badgeClass = "bg-success";
            let iconClass = "bi-check-circle-fill";
            let statusText = r.status;
            if (r.status === "skipped") {
              badgeClass = "bg-warning text-dark";
              iconClass = "bi-skip-end-circle-fill";
            }
            if (r.status === "failed") {
              badgeClass = "bg-danger";
              iconClass = "bi-x-octagon-fill";
            }

            let reasonHtml = r.reason
              ? `<br><small class="text-muted" title="${escapeHtml(
                  r.reason
                )}">Reason: ${escapeHtml(r.reason.substring(0, 100))}${
                  r.reason.length > 100 ? "..." : ""
                }</small>`
              : "";

            message += `<li class="list-group-item d-flex justify-content-between align-items-center small">
                                     <div><i class="bi ${iconClass} me-2"></i>Row ${
              r.row
            }: ${escapeHtml(r.recipient || "N/A")} ${reasonHtml}</div>
                                     <span class="badge ${badgeClass} rounded-pill ms-2">${statusText}</span>
                                 </li>`;
          });
          message += "</ul></div>";
        }
        displayStatus(message, "success");
      } else {
        console.error("Send Error Response:", body);
        let errorMessage =
          body.error || "An unknown error occurred during sending.";
        if (body.statusCode === 401) {
          errorMessage = `Authentication Error (${body.statusCode}): ${body.error}. Please ensure you granted permission. Try reloading the page and authenticating again.`;
        } else if (body.statusCode) {
          errorMessage = `Error ${body.statusCode}: ${errorMessage}`;
        }

        let detailedMessage = `<h5><i class="bi bi-exclamation-triangle-fill text-danger me-2"></i>Send Failed</h5><strong>${errorMessage}</strong>`;

        if (body.results && body.results.length > 0) {
          detailedMessage +=
            '<p class="mt-2 mb-1">Partial results (processing may have stopped):</p>';
          detailedMessage +=
            '<div style="max-height: 200px; overflow-y: auto;"><ul class="list-group list-group-flush">';
          body.results.forEach((r) => {
            let badgeClass = "bg-success";
            let iconClass = "bi-check-circle-fill";
            let statusText = r.status;
            if (r.status === "skipped") {
              badgeClass = "bg-warning text-dark";
              iconClass = "bi-skip-end-circle-fill";
            }
            if (r.status === "failed") {
              badgeClass = "bg-danger";
              iconClass = "bi-x-octagon-fill";
            }

            let reasonHtml = r.reason
              ? `<br><small class="text-muted" title="${escapeHtml(
                  r.reason
                )}">Reason: ${escapeHtml(r.reason.substring(0, 100))}${
                  r.reason.length > 100 ? "..." : ""
                }</small>`
              : "";

            detailedMessage += `<li class="list-group-item d-flex justify-content-between align-items-center small">
                                             <div><i class="bi ${iconClass} me-2"></i>Row ${
              r.row
            }: ${escapeHtml(r.recipient || "N/A")} ${reasonHtml}</div>
                                             <span class="badge ${badgeClass} rounded-pill ms-2">${statusText}</span>
                                         </li>`;
          });
          detailedMessage += "</ul></div>";
        }
        displayStatus(detailedMessage, "danger");
      }
    })
    .catch((error) => {
      console.error("Network/Fetch Error or Server Error:", error);
      let message = "An unexpected error occurred.";
      if (error instanceof TypeError) {
        message = `Network error: ${error.message}. Could not reach the server. Please check your connection and the server status.`;
      } else if (error.message) {
        message = `Error: ${error.message}`;
      } else if (error.error) {
        message = `Error: ${error.error}`;
      } else if (error.statusCode) {
        message = `Server returned status ${error.statusCode}. ${
          error.error || "Check server logs for details."
        }`;
      }

      displayStatus(
        `<h5><i class="bi bi-wifi-off text-danger me-2"></i>Connection Error</h5> ${message}`,
        "danger"
      );
    })
    .finally(() => {
      sendButton.disabled = false;
      spinner.style.display = "none";
      if (sendButtonIcon) sendButtonIcon.style.display = "inline-block";
    });
}

function displayStatus(message, type = "info", isLoading = false) {
  const statusMessage = document.getElementById("status-message");
  statusMessage.innerHTML = `
        <div class="alert alert-${type} d-flex ${
    isLoading ? "align-items-center" : "align-items-start"
  }" role="alert">
             ${
               isLoading
                 ? '<div class="spinner-border spinner-border-sm flex-shrink-0 me-2" role="status" style="margin-top: 0.2rem;"><span class="visually-hidden">Loading...</span></div>'
                 : ""
             }
            <div class="flex-grow-1">${message}</div>
        </div>
    `;
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(unsafe) {
  if (typeof unsafe !== "string") return unsafe;
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

document.addEventListener("DOMContentLoaded", function () {
  initializeQuill();

  const csvFileInput = document.getElementById("csv-file");
  const previewButton = document.getElementById("preview-button");
  const emailForm = document.getElementById("email-form");

  if (csvFileInput)
    csvFileInput.addEventListener("change", handleCsvFileSelect);
  if (previewButton) previewButton.addEventListener("click", generatePreview);
  if (emailForm) emailForm.addEventListener("submit", handleFormSubmit);

  resetCsvState();
});
