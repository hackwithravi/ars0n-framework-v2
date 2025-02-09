const initiateNucleiSSLScan = async (
  activeTarget,
  monitorNucleiSSLScanStatus,
  setIsNucleiSSLScanning,
  setNucleiSSLScans,
  setMostRecentNucleiSSLScanStatus,
  setMostRecentNucleiSSLScan
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/nuclei-ssl/run`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fqdn: activeTarget.scope_target.replace('*.', ''),
        }),
      }
    );

    if (!response.ok) {
      throw new Error('Failed to initiate Nuclei SSL scan');
    }

    setIsNucleiSSLScanning(true);
    monitorNucleiSSLScanStatus(
      activeTarget,
      setNucleiSSLScans,
      setMostRecentNucleiSSLScan,
      setIsNucleiSSLScanning,
      setMostRecentNucleiSSLScanStatus
    );
  } catch (error) {
    console.error('Error initiating Nuclei SSL scan:', error);
    setIsNucleiSSLScanning(false);
  }
};

export default initiateNucleiSSLScan; 