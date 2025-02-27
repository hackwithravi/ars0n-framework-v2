const validateInput = (type, inputText) => {
  if (type === 'Company') {
    if (!/^[a-zA-Z0-9]+$/.test(inputText)) {
      return {
        valid: false,
        message: 'Invalid Company name. Example: Google'
      };
    }
  } else if (type === 'Wildcard') {
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!inputText.startsWith('*.')) {
      inputText = `*.${inputText}`;
    }
    if (!domainRegex.test(inputText.slice(2))) {
      return {
        valid: false,
        message: 'Invalid Wildcard format. Example: *.google.com'
      };
    }
  } else if (type === 'URL') {
    const urlRegex = /^(https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!urlRegex.test(inputText)) {
      return {
        valid: false,
        message: 'Invalid URL. Example: https://google.com'
      };
    }
  } else if (type === 'Cloud') {
    const cloudRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!cloudRegex.test(inputText)) {
      return {
        valid: false,
        message: 'Invalid Cloud domain. Example: aws.amazon.com'
      };
    }
  } else if (type === 'API') {
    const apiRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!apiRegex.test(inputText)) {
      return {
        valid: false,
        message: 'Invalid API endpoint. Example: api.service.com'
      };
    }
  } else if (type === 'CIDR') {
    const cidrRegex = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
    if (!cidrRegex.test(inputText)) {
      return {
        valid: false,
        message: 'Invalid CIDR notation. Example: 192.168.1.0/24'
      };
    }
  } else {
    return {
      valid: false,
      message: 'Invalid selection. Please choose a type.'
    };
  }

  return {
    valid: true,
    message: ''
  };
};

export default validateInput;
  