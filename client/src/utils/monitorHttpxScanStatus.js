const monitorHttpxScanStatus = async (
  activeTarget,
  setHttpxScans,
  setMostRecentHttpxScan,
  setIsHttpxScanning,
  setMostRecentHttpxScanStatus
) => {
  if (!activeTarget) {
    setHttpxScans([]);
    setMostRecentHttpxScan(null);
    setIsHttpxScanning(false);
    setMostRecentHttpxScanStatus(null);
    return;
  }

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/httpx`
    );

    if (!response.ok) {
      throw new Error('Failed to fetch httpx scans');
    }

    const scans = await response.json();
    setHttpxScans(scans || []);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans.reduce((latest, scan) => {
        const scanDate = new Date(scan.created_at);
        return scanDate > new Date(latest.created_at) ? scan : latest;
      }, scans[0]);

      setMostRecentHttpxScan(mostRecentScan);
      setMostRecentHttpxScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending') {
        setIsHttpxScanning(true);
        setTimeout(() => {
          monitorHttpxScanStatus(
            activeTarget,
            setHttpxScans,
            setMostRecentHttpxScan,
            setIsHttpxScanning,
            setMostRecentHttpxScanStatus
          );
        }, 5000);
      } else {
        setIsHttpxScanning(false);
      }
    } else {
      setMostRecentHttpxScan(null);
      setMostRecentHttpxScanStatus(null);
      setIsHttpxScanning(false);
    }
  } catch (error) {
    console.error('Error monitoring httpx scan status:', error);
    setHttpxScans([]);
    setMostRecentHttpxScan(null);
    setIsHttpxScanning(false);
    setMostRecentHttpxScanStatus(null);
  }
};

export default monitorHttpxScanStatus; 