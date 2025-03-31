let quill;
let csvHeaders = [];
let placeholderCount = 0; // Counter to track unique placeholders

// Initialize Quill editor
document.addEventListener("DOMContentLoaded", function () {
    quill = new Quill('#editor-container', {
        theme: 'snow',
        modules: {
            toolbar: [
                [{ header: [1, 2, false] }],
                ['bold', 'italic', 'underline'],
                ['link'],
                [{ list: 'ordered' }, { list: 'bullet' }],
                ['clean']
            ]
        }
    });

    // Load CSV headers from localStorage if available
    if (localStorage.getItem('csvHeaders')) {
        csvHeaders = JSON.parse(localStorage.getItem('csvHeaders'));
    }

    // Auto-complete braces and insert unique placeholder in Quill editor
    quill.on('text-change', function (delta, oldDelta, source) {
        if (source === 'user') {
            const cursorPosition = quill.getSelection().index;
            const textBeforeCursor = quill.getText(cursorPosition - 1, 1);

            // Detect when the user types '{'
            if (textBeforeCursor === '{') {
                placeholderCount++;
                const placeholderText = `placeholder_${placeholderCount}}`;
                quill.insertText(cursorPosition, placeholderText);
                quill.formatText(cursorPosition - 1, placeholderText.length + 1, { color: 'blue', textDecoration: 'underline' });
                quill.setSelection(cursorPosition + placeholderText.length); // Move cursor after the placeholder
            }
        }
    });

    // Apply the same logic to the subject and recipient email fields
    ['recipient-email', 'subject'].forEach(fieldId => {
        const field = document.getElementById(fieldId);

        field.addEventListener('input', function () {
            const cursorPosition = field.selectionStart;
            const textBeforeCursor = field.value[cursorPosition - 1];

            // Detect when the user types '{'
            if (textBeforeCursor === '{') {
                placeholderCount++;
                const placeholderText = `placeholder_${placeholderCount}}`;
                const textBefore = field.value.slice(0, cursorPosition);
                const textAfter = field.value.slice(cursorPosition);
                field.value = textBefore + placeholderText + textAfter;

                // Move the cursor after the placeholder
                field.setSelectionRange(cursorPosition + placeholderText.length, cursorPosition + placeholderText.length);

                // Style the braces with blue underline
                styleBraces(field);
            }
        });
    });
});

// Function to style braces with blue underline
function styleBraces(field) {
    const regex = /\{.*?\}/g;
    field.innerHTML = field.value.replace(regex, match => `<span class="clickable-placeholder">${match}</span>`);
}

// Function to load CSV headers and store them in localStorage
function loadHeaders() {
    const fileInput = document.getElementById('csv-file');
    const file = fileInput.files[0];

    if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const csvContent = e.target.result;
            const rows = csvContent.split("\n");
            csvHeaders = rows[0].split(",").map(header => header.trim());

            // Store headers in localStorage
            localStorage.setItem('csvHeaders', JSON.stringify(csvHeaders));
        };
        reader.readAsText(file);
    } else {
        csvHeaders = []; // Clear headers if no file is provided
        localStorage.removeItem('csvHeaders');
    }
}

// Function to render the preview
function renderPreview() {
    // Ensure all inputs are filled
    const recipientEmail = document.getElementById("recipient-email").value;
    const emailSubject = document.getElementById("subject").value;
    const emailBody = quill.root.innerHTML.trim();  // Trim to remove extra white space

    if (!recipientEmail || !emailSubject || !emailBody || csvHeaders.length === 0) {
        alert("Please fill out all fields and upload a CSV file with headers.");
        return;
    }

    const previewContainer = document.getElementById("preview-container");
    previewContainer.innerHTML = ''; // Clear previous preview content

    // Create and style the preview sections
    const recipientPreview = createPreviewElement(recipientEmail, 'recipient-preview');
    const subjectPreview = createPreviewElement(emailSubject, 'subject-preview');
    const bodyPreview = createPreviewElement(emailBody, 'body-preview');

    const previewWrapper = document.createElement('div');
    previewWrapper.classList.add('email-preview-wrapper');
    previewWrapper.appendChild(recipientPreview);
    previewWrapper.appendChild(subjectPreview);
    previewWrapper.appendChild(bodyPreview);

    previewContainer.appendChild(previewWrapper);

    // Display headers in a list format for easy selection
    displayHeaderList();
}

// Helper function to create preview elements with clickable placeholders
function createPreviewElement(content, id) {
    const previewElement = document.createElement('div');
    previewElement.id = id;
    previewElement.classList.add('email-preview-line');
    previewElement.innerHTML = content.replace(/{(.*?)}/g, '<span class="clickable-placeholder" onclick="highlightPlaceholder(this)">$&</span>')
                                      .replace(/\n/g, '<br>');  // Replace new lines with HTML breaks
    return previewElement;
}

// Function to highlight a clicked placeholder
function highlightPlaceholder(element) {
    document.querySelectorAll('.clickable-placeholder').forEach(el => el.classList.remove('active'));
    element.classList.add('active');
}

// Function to show a list of headers for selection
function displayHeaderList() {
    const headerSelection = document.getElementById('header-selection');
    headerSelection.innerHTML = ''; // Clear previous content

    if (csvHeaders.length === 0) {
        headerSelection.innerHTML = '<p>No headers provided</p>';
        return;
    }

    csvHeaders.forEach(header => {
        const headerElement = document.createElement('div');
        headerElement.classList.add('clickable-header');
        headerElement.innerText = header;
        headerElement.onclick = function () {
            replacePlaceholderWithHeader(header);
        };
        headerSelection.appendChild(headerElement);
    });
}

// Function to replace {placeholder} with the selected header
function replacePlaceholderWithHeader(selectedHeader) {
    const activePlaceholder = document.querySelector('.clickable-placeholder.active');
    if (activePlaceholder) {
        activePlaceholder.innerHTML = `{${selectedHeader}}`;

        // Update corresponding field content (recipient, subject, or body)
        const fieldId = activePlaceholder.parentElement.id;
        let updatedContent = activePlaceholder.parentElement.innerHTML.replace(/<span.*?>|<\/span>/g, ''); // Remove span tags
        updatedContent = updatedContent.replace(`{${selectedHeader}}`, `{${selectedHeader}}`);

        if (fieldId === 'recipient-preview') {
            document.getElementById("recipient-email").value = updatedContent;
        } else if (fieldId === 'subject-preview') {
            document.getElementById("subject").value = updatedContent;
        } else if (fieldId === 'body-preview') {
            quill.root.innerHTML = updatedContent;
        }

        // Remove highlight after selection
        activePlaceholder.classList.remove('active');
    }
}

// Form submission handler to include Quill content
document.getElementById("email-form").onsubmit = function () {
    document.getElementById("email-template").value = quill.root.innerHTML.trim();  // Trim to remove extra white space
};