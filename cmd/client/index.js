// Store the last request data
let lastRequestData = null;

// Function to prepare and show the API request without actually sending it
function prepareRequest(protocol) {
  console.log("prepareRequest called with protocol:", protocol);
  
  // Check if getSelectedAttributes exists
  if (typeof getSelectedAttributes !== 'function') {
    console.error("getSelectedAttributes function not found. Check if temprate.js is loaded properly.");
    alert("Error: Could not get selected attributes. See console for details.");
    return;
  }
  
  // Get selected attributes
  const selectedAttributes = getSelectedAttributes();
  console.log("Selected attributes:", selectedAttributes);
  
  if (selectedAttributes.length === 0) {
    alert("Please select at least one attribute to request.");
    return;
  }
  
  // Prepare the request data based on the protocol
  let requestData;
  
  // Determine if it's Digital Credentials API or OpenID4VP flow
  const isDigitalCredentialsAPI = protocol === 'preview';
  const isOpenID4VP = protocol === 'openid4vp' || protocol === 'eudiw';
  
  switch(protocol) {
    case 'preview':
      requestData = {
        type: "digital_credentials_api",
        protocol: "preview",
        attributes: selectedAttributes
      };
      break;
    case 'openid4vp':
      requestData = {
        type: "openid4vp",
        protocol: "openid4vp",
        attributes: selectedAttributes
      };
      break;
    case 'eudiw':
      requestData = {
        type: "openid4vp",
        variant: "eudiw",
        attributes: selectedAttributes
      };
      break;
    default:
      requestData = {
        attributes: selectedAttributes
      };
  }
  
  console.log("Request data prepared:", requestData);
  
  // Update the request display
  updateRequestDisplay(requestData);
  
  // Show the request section with the API request information
  const requestSection = document.getElementById('requestSection');
  
  if (requestSection) {
    requestSection.style.display = 'block';
    
    // Hide the verification result section
    const resultSection = document.getElementById('resultSection');
    if (resultSection) {
      resultSection.style.display = 'none';
    }
    
    // Scroll to the request section
    requestSection.scrollIntoView({ behavior: 'smooth' });
  } else {
    console.error("Request section element not found");
  }
}

// Function to update the API request display
function updateRequestDisplay(requestData) {
  lastRequestData = requestData;
  const apiRequestData = document.getElementById('apiRequestData');
  
  if (apiRequestData) {
    apiRequestData.textContent = JSON.stringify(requestData, null, 2);
  } else {
    console.error("API request data element not found");
  }
}

// Function to show both request and result
function showFullResult(data, success = true) {
  // Make sure the API request section is up to date
  if (lastRequestData) {
    updateRequestDisplay(lastRequestData);
  }
  
  // Show the result section
  const resultSection = document.getElementById('resultSection');
  const verificationStatus = document.getElementById('verificationStatus');
  const resultContainer = document.getElementById('verificationResult').parentElement;
  
  resultSection.style.display = 'block';
  resultContainer.style.display = 'block';
  
  if (success) {
    verificationStatus.className = 'alert alert-success mb-3';
    verificationStatus.innerHTML = '<i class="fas fa-check-circle me-2"></i>Verification successful';
  } else {
    verificationStatus.className = 'alert alert-danger mb-3';
    verificationStatus.innerHTML = '<i class="fas fa-exclamation-circle me-2"></i>Verification failed';
  }
  
  // Display the result data
  const verificationResult = document.getElementById('verificationResult');
  
  if (typeof data === 'object') {
    try {
      // Clear previous content
      while (verificationResult.firstChild) {
        verificationResult.removeChild(verificationResult.firstChild);
      }
      
      // Add toggle button
      var toggleButton = document.createElement('button');
      toggleButton.className = 'btn btn-sm btn-outline-secondary mb-3';
      toggleButton.textContent = 'Toggle JSON View';
      toggleButton.onclick = function() {
        document.getElementById('tableView').style.display = 
          document.getElementById('tableView').style.display === 'none' ? 'block' : 'none';
        document.getElementById('jsonView').style.display = 
          document.getElementById('jsonView').style.display === 'none' ? 'block' : 'none';
      };
      verificationResult.appendChild(toggleButton);
      
      // Create table view
      var tableView = document.createElement('div');
      tableView.id = 'tableView';
      tableView.appendChild(createResultTable(data));
      verificationResult.appendChild(tableView);
      
      // Create JSON view (hidden by default)
      var jsonView = document.createElement('div');
      jsonView.id = 'jsonView';
      jsonView.style.display = 'none';
      
      var pre = document.createElement('pre');
      pre.textContent = JSON.stringify(data, null, 2);
      jsonView.appendChild(pre);
      
      verificationResult.appendChild(jsonView);
    } catch (error) {
      console.error('Error creating table:', error);
      // Fallback to JSON
      verificationResult.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
    }
  } else {
    verificationResult.textContent = data;
  }
  
  // Scroll to result section
  resultSection.scrollIntoView({ behavior: 'smooth' });
}

// Handle errors with our own error display
function handleApiError(error) {
  console.error(error);
  let errorMessage = '';
  
  if (error.responseJSON && error.responseJSON.Error) {
    errorMessage = error.responseJSON.Error;
  } else if (error.responseText) {
    try {
      const errorObj = JSON.parse(error.responseText);
      errorMessage = errorObj.Error || error.responseText;
    } catch {
      errorMessage = error.responseText;
    }
  } else if (error.message) {
    errorMessage = error.message;
  } else {
    errorMessage = JSON.stringify(error);
  }
  
  hideLoading();
  showFullResult({ error: errorMessage }, false);
}

async function getIdentity() {
  // Get selected attributes
  const selectedAttributes = getSelectedAttributes();
  
  if (selectedAttributes.length === 0) {
    alert("Please select at least one attribute to request.");
    return;
  }
  
  showLoading('Requesting identity via Preview protocol...');
  
  try {
    const requestPayload = {
      type: "digital_credentials_api",
      protocol: "preview",
      attributes: selectedAttributes
    };
    
    // Store the request data for display
    updateRequestDisplay(requestPayload);
    
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify(requestPayload),
        function (data, status) {
          return data;
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleApiError(err);
    });
    
    console.log(req);
    console.log(req.data);
    
    showLoading('Waiting for credential from your wallet...');
    
    const controller = new AbortController();
    const signal = controller.signal;

    // https://wicg.github.io/digital-credentials/
    const response = await navigator.credentials.get({
        digital: {
          providers: [
            {
              protocol: "preview",
              request: req.data,
            }
          ]
        },
    });
    
    console.log(response);
    
    showLoading('Verifying credentials...');
    
    const verifyRequest = {
      session_id: req.session_id,
      protocol: response.protocol,
      data: response.data,
      origin: location.origin,
    };
    
    // Update with verification request
    updateRequestDisplay({
      initialRequest: requestPayload,
      verificationRequest: verifyRequest
    });
    
    const verifyResult = await $.post(
        "https://{{.ServerDomain}}/verifyIdentityResponse",
        JSON.stringify(verifyRequest),
        function (data, status) {
          hideLoading();
          showFullResult(data, true);
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleApiError(err);
    });
    
    console.log(verifyResult);

  } catch (error) {
    console.error(error);
    handleApiError(error);
  }
}

async function getIdentityWithOpenid4VP() {
  // Get selected attributes
  const selectedAttributes = getSelectedAttributes();
  
  if (selectedAttributes.length === 0) {
    alert("Please select at least one attribute to request.");
    return;
  }
  
  showLoading('Requesting identity via OpenID4VP protocol...');
  
  try {
    const requestPayload = {
      type: "openid4vp",
      protocol: "openid4vp",
      attributes: selectedAttributes
    };
    
    // Store the request data for display
    updateRequestDisplay(requestPayload);
    
    const req = await $.post(
        "https://{{.ServerDomain}}/getIdentityRequest",
        JSON.stringify(requestPayload),
        function (data, status) {
          return data;
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleApiError(err);
    });
    
    console.log(req);
    console.log(req.data);
    
    showLoading('Waiting for credential from your wallet...');
    
    const controller = new AbortController();
    const signal = controller.signal;

    // https://wicg.github.io/digital-credentials/
    const response = await navigator.credentials.get({
        digital: {
          providers: [
            {
              protocol: "openid4vp",
              request: req.data,
            }
          ]
        },
    });
    
    console.log(response);
    
    showLoading('Verifying credentials...');
    
    const verifyRequest = {
      session_id: req.session_id,
      protocol: response.protocol,
      data: response.data,
      origin: location.origin,
    };
    
    // Update with verification request
    updateRequestDisplay({
      initialRequest: requestPayload,
      verificationRequest: verifyRequest
    });
    
    const verifyResult = await $.post(
        "https://{{.ServerDomain}}/verifyIdentityResponse",
        JSON.stringify(verifyRequest),
        function (data, status) {
          hideLoading();
          showFullResult(data, true);
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleApiError(err);
    });
    
    console.log(verifyResult);

  } catch (error) {
    console.error(error);
    handleApiError(error);
  }
}

async function getIdentifyFromEUDIW() {
  // Get selected attributes
  const selectedAttributes = getSelectedAttributes();
  
  if (selectedAttributes.length === 0) {
    alert("Please select at least one attribute to request.");
    return;
  }
  
  showLoading('Connecting to EU Digital Identity Wallet...');
  
  try {
    const requestPayload = {
      type: "openid4vp",
      variant: "eudiw",
      attributes: selectedAttributes
    };
    
    // Store the request data for display
    updateRequestDisplay(requestPayload);
    
    const req = await $.post(
        "https://{{.ServerDomain}}/wallet/startIdentityRequest",
        JSON.stringify(requestPayload),
        function (data, status) {
          return data;
        },
        'json'
    ).fail(function(err) {
        console.error(err);
        handleApiError(err);
    });
    
    console.log(req);
    console.log(req.data);
    
    // Redirect to the authentication URL
    window.location.href = req.url;
  } catch (error) {
    console.error(error);
    handleApiError(error);
  }
}

// Function to check if we're coming back from EUDIW flow
function processEUDIWResponse() {
  const sessionId = getQueryParam('session_id');

  // If session_id exists in URL, process the response
  if (sessionId) {
    showLoading('Completing verification process...');
    
    try {
      const requestPayload = {
        session_id: sessionId
      };
      
      // Store the request data
      updateRequestDisplay(requestPayload);
      
      const req = $.post(
          "https://{{.ServerDomain}}/wallet/finishIdentityRequest",
          JSON.stringify(requestPayload),
          function (data, status) {
            return data;
          },
          'json'
      ).fail(function(err) {
          console.error(err);
          handleApiError(err);
      }).then(res => {
        hideLoading();
        showFullResult(res, true);
        console.log(res);
        
        // Remove the session_id from the URL without reloading the page
        const newUrl = window.location.pathname;
        window.history.pushState({ path: newUrl }, '', newUrl);
      });
    } catch (error) {
      console.error(error);
      handleApiError(error);
    }
    
    return true;
  }
  
  return false;
}

// Initialize the page
function initPage() {
  // Process EUDIW response if present
  if (processEUDIWResponse()) {
    return;
  }
  
  // Initially hide the request section
  if (document.getElementById('requestSection')) {
    document.getElementById('requestSection').style.display = 'none';
  }
}

// When the page loads
window.addEventListener('load', function() {
  initPage();
});

// If createResultTable is not defined in this file, make sure it's imported from temprate.js
if (typeof createResultTable !== 'function' && typeof window.createResultTable === 'function') {
  window.createResultTable = window.createResultTable;
}