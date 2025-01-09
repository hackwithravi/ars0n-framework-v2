const validateInput = (selections, setErrorMessage) => {
    const { type, inputText } = selections;
  
    if (type === 'Company') {
      if (!/^[a-zA-Z0-9]+$/.test(inputText)) {
        setErrorMessage('Invalid Company name. Example: Google');
        return false;
      }
    } else if (type === 'Wildcard') {
      const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (inputText.startsWith('*.') && domainRegex.test(inputText.slice(2))) {
        return true;
      }
      setErrorMessage('Invalid Wildcard format. Example: *.google.com');
      return false;
    } else if (type === 'URL') {
      const urlRegex = /^(https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!urlRegex.test(inputText)) {
        setErrorMessage('Invalid URL. Example: https://google.com');
        return false;
      }
    } else {
      setErrorMessage('Invalid selection. Please choose a type.');
      return false;
    }
  
    return true;
  };
  
  export default validateInput;
  