const monitorNucleiSSLScanStatus = async (
  activeTarget,
  setNucleiSSLScans,
  setMostRecentNucleiSSLScan,
  setIsNucleiSSLScanning,
  setMostRecentNucleiSSLScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/nuclei-ssl`
    );

    if (!response.ok) {
      throw new Error('Failed to get Nuclei SSL scans');
    }

    const scans = await response.json();
    setNucleiSSLScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentNucleiSSLScan(mostRecentScan);
      setMostRecentNucleiSSLScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setTimeout(() => {
          monitorNucleiSSLScanStatus(
            activeTarget,
            setNucleiSSLScans,
            setMostRecentNucleiSSLScan,
            setIsNucleiSSLScanning,
            setMostRecentNucleiSSLScanStatus
          );
        }, 5000);
      } else {
        setIsNucleiSSLScanning(false);
      }
    }
  } catch (error) {
    console.error('Error monitoring Nuclei SSL scan status:', error);
    setIsNucleiSSLScanning(false);
  }
};

export default monitorNucleiSSLScanStatus; 