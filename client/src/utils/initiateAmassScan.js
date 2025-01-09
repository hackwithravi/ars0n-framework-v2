export const initiateAmassScan = async (activeTarget, monitorScanStatus, setIsScanning, setAmassScans, setLastScanTriggerTime, setMostRecentAmassScanStatus) => {
    if (!activeTarget) return;
    let fqdn = activeTarget.scope_target;
    if (activeTarget.type === 'Wildcard') {
      fqdn = fqdn.replace(/^\*\./, '');
    }
  
    try {
      const response = await fetch(`${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/amass/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fqdn }),
      });
  
      if (!response.ok) {
        throw new Error('Failed to initiate Amass scan');
      }
  
      setIsScanning(true);
      monitorScanStatus(activeTarget, setAmassScans, setIsScanning, setLastScanTriggerTime, setMostRecentAmassScanStatus);
    } catch (error) {
      console.error('Error initiating Amass scan:', error);
    }
  };

  export default initiateAmassScan