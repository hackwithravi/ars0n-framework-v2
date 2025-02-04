const initiateCeWLScan = async (
  activeTarget,
  monitorCeWLScanStatus,
  setIsCeWLScanning,
  setCeWLScans,
  setMostRecentCeWLScanStatus,
  setMostRecentCeWLScan
) => {
  if (!activeTarget) return;

  try {
    setIsCeWLScanning(true);

    // Extract the domain from the scope target (remove the wildcard if present)
    const domain = activeTarget.scope_target.replace(/^\*\./, '');

    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/cewl/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fqdn: domain
        }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate CeWL scan');
    }

    const data = await response.json();
    const scanId = data.scan_id;

    // Start monitoring the scan status
    monitorCeWLScanStatus(
      activeTarget,
      setCeWLScans,
      setMostRecentCeWLScan,
      setIsCeWLScanning,
      setMostRecentCeWLScanStatus
    );

  } catch (error) {
    console.error('Error initiating CeWL scan:', error);
    setIsCeWLScanning(false);
  }
};

export default initiateCeWLScan; 