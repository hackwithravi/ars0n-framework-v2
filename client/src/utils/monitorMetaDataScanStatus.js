const monitorMetaDataScanStatus = async (
  activeTarget,
  setMetaDataScans,
  setMostRecentMetaDataScan,
  setIsMetaDataScanning,
  setMostRecentMetaDataScanStatus
) => {
  if (!activeTarget) return;

  try {
    const response = await fetch(
      `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/scopetarget/${activeTarget.id}/scans/metadata`
    );

    if (!response.ok) {
      throw new Error('Failed to get Nuclei SSL scans');
    }

    const scans = await response.json();
    setMetaDataScans(scans);

    if (scans && scans.length > 0) {
      const mostRecentScan = scans[0];
      setMostRecentMetaDataScan(mostRecentScan);
      setMostRecentMetaDataScanStatus(mostRecentScan.status);

      if (mostRecentScan.status === 'pending' || mostRecentScan.status === 'running') {
        setTimeout(() => {
          monitorMetaDataScanStatus(
            activeTarget,
            setMetaDataScans,
            setMostRecentMetaDataScan,
            setIsMetaDataScanning,
            setMostRecentMetaDataScanStatus
          );
        }, 5000);
      } else {
        setIsMetaDataScanning(false);
        // Fetch updated target URLs when scan completes
        try {
          const urlsResponse = await fetch(
            `${process.env.REACT_APP_SERVER_PROTOCOL}://${process.env.REACT_APP_SERVER_IP}:${process.env.REACT_APP_SERVER_PORT}/api/scope-targets/${activeTarget.id}/target-urls`
          );
          if (!urlsResponse.ok) {
            throw new Error('Failed to fetch target URLs');
          }
          const data = await urlsResponse.json();
          window.dispatchEvent(new CustomEvent('metadataScanComplete', { detail: data }));
        } catch (error) {
          console.error('Error fetching target URLs:', error);
        }
      }
    }
  } catch (error) {
    console.error('Error monitoring Nuclei SSL scan status:', error);
    setIsMetaDataScanning(false);
  }
};

export default monitorMetaDataScanStatus; 