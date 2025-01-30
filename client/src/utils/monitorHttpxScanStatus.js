import fetchHttpxScans from './fetchHttpxScans';

const monitorHttpxScanStatus = async (activeTarget, setHttpxScans, setMostRecentHttpxScan, setIsScanning, setMostRecentHttpxScanStatus) => {
  if (!activeTarget) return;

  let status = await fetchHttpxScans(activeTarget, setHttpxScans, setMostRecentHttpxScan, setMostRecentHttpxScanStatus);

  while (status === 'pending' && activeTarget) {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    const scanDetails = await fetchHttpxScans(activeTarget, setHttpxScans, setMostRecentHttpxScan, setMostRecentHttpxScanStatus);
    status = scanDetails.status;
  }

  setIsScanning(false);
};

export default monitorHttpxScanStatus; 